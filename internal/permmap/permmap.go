// Package permmap is SopsHQ's read-only filesystem permission auditor.
//
// It MECHANICALLY collects who-can-access-what across selected directory roots
// on a Linux machine: per path it records the owner, owning group, octal mode
// (including the setuid/setgid/sticky special bits), the POSIX access ACL and
// default ACL (named user/group grants), and any file capabilities. From those
// raw facts it derives a small set of security flags so a viewer can filter
// quickly: world-writable, has-acl, acl-override, suid/sgid, and an overall
// "dangerous" verdict.
//
// The collector executes the standard Linux tools (find, getfacl, getcap) and
// is therefore Linux-only; see Collect. The block parser, octal-mode
// reconstruction, and flag rules in this file are PURE functions with no I/O,
// so they build and unit-test on any platform (including the Windows dev box).
//
// SECURITY: the produced map reveals the full filesystem layout and who can
// access what. It is sensitive: callers keep it machine-local and admin-only.
// This package only produces records; it never changes any permission, and it
// never logs the map.
package permmap

import (
	"fmt"
	"sort"
	"strings"
)

// Entry is one collected path with its ownership, mode, ACLs, and derived
// security flags. It mirrors the record the reference perm-map engine produced.
type Entry struct {
	Path string `json:"path"`
	// Type is the find(1) "%y" letter: f=file, d=directory, l=symlink, and so
	// on. Empty when a path was seen only by getfacl and not by find.
	Type          string   `json:"type"`
	Owner         string   `json:"owner"`
	Group         string   `json:"group"`
	Mode          string   `json:"mode"`     // octal string incl. special bits, e.g. "4755"
	ModeNum       int      `json:"mode_num"` // numeric value of Mode read as octal
	Setuid        bool     `json:"setuid"`
	Setgid        bool     `json:"setgid"`
	Sticky        bool     `json:"sticky"`
	ACL           []string `json:"acl"`         // named access ACL entries, e.g. "u:alice:r--"
	DefaultACL    []string `json:"default_acl"` // named default ACL entries (directories)
	Caps          string   `json:"caps"`        // file capabilities from getcap, if any
	WorldWritable bool     `json:"world_writable"`
	HasACL        bool     `json:"has_acl"`
	ACLOverride   bool     `json:"acl_override"`
	SuidSgid      bool     `json:"suid_sgid"`
	Dangerous     bool     `json:"dangerous"`
}

// faclAttrs holds the parsed contents of a single getfacl block, before the
// derived flags and final octal mode are computed.
type faclAttrs struct {
	Path       string
	Owner      string
	Group      string
	Setuid     bool
	Setgid     bool
	Sticky     bool
	UPerm      int // owning-user rwx as an octal digit 0..7
	GPerm      int // owning-group rwx as an octal digit 0..7
	OPerm      int // other rwx as an octal digit 0..7
	Mask       int // ACL mask as an octal digit, or -1 when no mask line is present
	ACL        []string
	DefaultACL []string
}

// permToOctal converts a 3-character "rwx" field (as getfacl prints it) into an
// octal digit 0..7. The execute slot also counts the setuid/setgid/sticky
// glyphs (s/S/t/T) that getfacl overlays on it.
func permToOctal(p string) int {
	v := 0
	if len(p) >= 1 && p[0] == 'r' {
		v += 4
	}
	if len(p) >= 2 && p[1] == 'w' {
		v += 2
	}
	if len(p) >= 3 {
		switch p[2] {
		case 'x', 's', 't', 'S', 'T':
			v += 1
		}
	}
	return v
}

// octalMode reconstructs the 4-digit octal mode from the base owner/group/other
// rwx digits and the special bits. It returns both the string form (e.g.
// "4755") and its numeric value read as octal (e.g. 0o4755).
func octalMode(uperm, gperm, operm int, setuid, setgid, sticky bool) (string, int) {
	special := 0
	if setuid {
		special += 4
	}
	if setgid {
		special += 2
	}
	if sticky {
		special += 1
	}
	str := fmt.Sprintf("%d%d%d%d", special, uperm, gperm, operm)
	num := special*512 + uperm*64 + gperm*8 + operm
	return str, num
}

// worldWritable reports whether the "other" class carries the write bit.
func worldWritable(operm int) bool { return operm&2 != 0 }

// hasACL reports whether the entry carries any named user/group ACL entry: a
// principal beyond the owning user, owning group, other, and mask.
func hasACL(named []string) bool { return len(named) > 0 }

// aclOverride reports whether a named ACL entry grants access to a principal
// beyond the owning user and owning group. Any named access-ACL entry is such a
// principal, so its presence is the test.
func aclOverride(named []string) bool { return len(named) > 0 }

// suidSgid reports whether the setuid or setgid bit is set.
func suidSgid(setuid, setgid bool) bool { return setuid || setgid }

// dangerous gives the overall verdict: a path is dangerous when it is
// setuid/setgid, or when it is world-writable -- with one exemption: a
// world-writable DIRECTORY that carries the sticky bit (the /tmp pattern, where
// the sticky bit blocks cross-user deletion) is not flagged.
func dangerous(ftype string, ww, suidsgid, sticky bool) bool {
	if suidsgid {
		return true
	}
	if ww {
		if ftype == "d" && sticky {
			return false
		}
		return true
	}
	return false
}

// parseBlock parses the lines of a single getfacl block -- the "# file:" /
// "# owner:" / "# group:" / "# flags:" header lines followed by the
// "user::"/"user:NAME:"/"group::"/"group:NAME:"/"mask::"/"other::" access-ACL
// lines and any "default:" lines -- into its attributes. It returns nil when
// the block has no "# file:" path line.
func parseBlock(block string) *faclAttrs {
	cur := &faclAttrs{Mask: -1}
	for _, raw := range strings.Split(block, "\n") {
		line := strings.TrimRight(raw, "\r")
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "# file:"):
			cur.Path = strings.TrimSpace(line[len("# file:"):])
		case strings.HasPrefix(line, "# owner:"):
			cur.Owner = strings.TrimSpace(line[len("# owner:"):])
		case strings.HasPrefix(line, "# group:"):
			cur.Group = strings.TrimSpace(line[len("# group:"):])
		case strings.HasPrefix(line, "# flags:"):
			f := strings.TrimSpace(line[len("# flags:"):])
			if len(f) >= 3 {
				cur.Setuid = f[0] == 's'
				cur.Setgid = f[1] == 's'
				cur.Sticky = f[2] == 't'
			}
		case strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "default:"):
			body := line[len("default:"):]
			switch {
			case strings.HasPrefix(body, "user:") && !strings.HasPrefix(body, "user::"):
				cur.DefaultACL = append(cur.DefaultACL, "u:"+body[len("user:"):])
			case strings.HasPrefix(body, "group:") && !strings.HasPrefix(body, "group::"):
				cur.DefaultACL = append(cur.DefaultACL, "g:"+body[len("group:"):])
			}
		default:
			// Access ACL line: type:qualifier:perms (exactly three fields).
			parts := strings.Split(line, ":")
			if len(parts) != 3 {
				continue
			}
			kind, who, perm := parts[0], parts[1], parts[2]
			switch {
			case kind == "user" && who == "":
				cur.UPerm = permToOctal(perm)
			case kind == "user":
				cur.ACL = append(cur.ACL, "u:"+who+":"+perm)
			case kind == "group" && who == "":
				cur.GPerm = permToOctal(perm)
			case kind == "group":
				cur.ACL = append(cur.ACL, "g:"+who+":"+perm)
			case kind == "mask":
				cur.Mask = permToOctal(perm)
			case kind == "other" && who == "":
				cur.OPerm = permToOctal(perm)
			}
		}
	}
	if cur.Path == "" {
		return nil
	}
	return cur
}

// parseGetfacl parses the full output of `getfacl -R -p <root>` into a map from
// path to its parsed attributes. Blocks are separated by a blank line; each
// block begins with a "# file:" header.
func parseGetfacl(text string) map[string]*faclAttrs {
	out := make(map[string]*faclAttrs)
	var block []string
	flush := func() {
		if len(block) == 0 {
			return
		}
		if a := parseBlock(strings.Join(block, "\n")); a != nil {
			out[a.Path] = a
		}
		block = block[:0]
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			flush()
			continue
		}
		block = append(block, line)
	}
	flush()
	return out
}

// assemble merges the per-path facts collected by find (types), getfacl (facl),
// and getcap (caps) into the final []Entry, computing the octal mode and the
// derived flags for each path. It walks the union of paths seen by find or
// getfacl (a symlink shows up only in find) and returns the entries sorted by
// path for deterministic output.
func assemble(types map[string]string, facl map[string]*faclAttrs, caps map[string]string) []Entry {
	seen := make(map[string]struct{}, len(types)+len(facl))
	for p := range types {
		seen[p] = struct{}{}
	}
	for p := range facl {
		seen[p] = struct{}{}
	}
	entries := make([]Entry, 0, len(seen))
	for path := range seen {
		a := facl[path]
		if a == nil {
			a = &faclAttrs{Mask: -1}
		}
		ftype := types[path]
		modeStr, modeNum := octalMode(a.UPerm, a.GPerm, a.OPerm, a.Setuid, a.Setgid, a.Sticky)
		ww := worldWritable(a.OPerm)
		ss := suidSgid(a.Setuid, a.Setgid)
		entries = append(entries, Entry{
			Path:          path,
			Type:          ftype,
			Owner:         a.Owner,
			Group:         a.Group,
			Mode:          modeStr,
			ModeNum:       modeNum,
			Setuid:        a.Setuid,
			Setgid:        a.Setgid,
			Sticky:        a.Sticky,
			ACL:           a.ACL,
			DefaultACL:    a.DefaultACL,
			Caps:          caps[path],
			WorldWritable: ww,
			HasACL:        hasACL(a.ACL),
			ACLOverride:   aclOverride(a.ACL),
			SuidSgid:      ss,
			Dangerous:     dangerous(ftype, ww, ss, a.Sticky),
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries
}
