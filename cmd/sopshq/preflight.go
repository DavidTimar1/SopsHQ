package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// requiredDir is one directory serve must be able to write before it touches the vault
// key. label names it for the operator; path is the directory.
type requiredDir struct {
	label string
	path  string
}

// classifyDirProbe turns a probe of one required directory into a preflight error, or
// nil when the directory is present and writable. It exists to tell the TRUTH about the
// two failure modes that systemd's ProtectSystem=strict otherwise blurs together:
//
//   - A MISSING directory under a read-only sandbox surfaces to a naive caller as
//     "mkdir ...: read-only file system", which sends the operator hunting a mount that
//     is fine. classifyDirProbe reports "directory does not exist: <path>" instead.
//   - A directory that EXISTS but cannot be written (a genuinely read-only mount, or the
//     wrong owner) reports "directory is not writable".
//
// exists and writable come from the OS probe; account is the service account name for
// the message; mountHint is an optional extra line (from unmountedMountHint) appended
// when a missing directory looks like it sits on an unmounted volume. It is pure so both
// classifications are unit-tested without a real filesystem.
func classifyDirProbe(label, path, account string, exists, writable bool, mountHint string) error {
	if !exists {
		msg := fmt.Sprintf("%s directory does not exist: %s", label, path)
		if mountHint != "" {
			msg += " (" + mountHint + ")"
		}
		return fmt.Errorf("%s", msg)
	}
	if !writable {
		return fmt.Errorf("%s directory is not writable by the %s account: %s "+
			"(check ownership, or that the volume is not mounted read-only)", label, account, path)
	}
	return nil
}

// probeDir reports whether path exists and whether this process can write into it. The
// writability test creates and removes a temp file, so it reflects the REAL effective
// permissions (owner, group, ACL, and a read-only mount) rather than guessing from the
// mode bits. A non-existent directory reports exists=false and writable=false. It is
// shared by the Linux and Windows preflights.
func probeDir(path string) (exists, writable bool) {
	fi, err := os.Stat(path)
	if err != nil || !fi.IsDir() {
		return false, false
	}
	tmp, err := os.CreateTemp(path, ".sopshq-preflight-*")
	if err != nil {
		return true, false
	}
	name := tmp.Name()
	_ = tmp.Close()
	_ = os.Remove(name)
	return true, true
}

// unmountedMountHint returns a short hint when a missing directory looks like it lives on
// a volume that is not mounted: some ancestor directly under a conventional mount parent
// (/mnt/<x> or /media/<x>) is not currently a mount point. isMounted reports whether a
// directory is a mount point (in production, read from /proc/mounts); injecting it keeps
// this pure and unit-testable. It returns "" when nothing looks unmounted.
func unmountedMountHint(path string, isMounted func(dir string) bool) string {
	for _, anc := range pathJunctions(path) {
		parent := filepath.Dir(anc)
		if (parent == "/mnt" || parent == "/media") && !isMounted(anc) {
			return "the volume at " + anc + " does not appear to be mounted"
		}
	}
	return ""
}

// pathJunctions returns every path component of an absolute path, ordered from the root
// "/" down to the path itself: pathJunctions("/mnt/vol/sopshq") is
// ["/", "/mnt", "/mnt/vol", "/mnt/vol/sopshq"]. It is the shared walk used by the
// preflight mount hint and the path-permission review, so both reason over the same
// ordered list. It is pure. A non-absolute or empty path yields nil.
func pathJunctions(path string) []string {
	path = filepath.Clean(path)
	if path == "" || !filepath.IsAbs(path) {
		return nil
	}
	out := []string{"/"}
	if path == "/" {
		return out
	}
	var b strings.Builder
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		b.WriteString("/")
		b.WriteString(part)
		out = append(out, b.String())
	}
	return out
}
