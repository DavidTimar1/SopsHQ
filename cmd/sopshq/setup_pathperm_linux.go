//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// reviewPathAccess is the per-junction path-permission review. For the data directory
// and the keybase root it walks every path component from "/" down to the leaf and tests
// whether the service account can TRAVERSE each one. At every blocking junction it shows
// the current state and, for a junction it is allowed to change, offers the operator two
// remedies - change the directory's group, or add a persistent POSIX ACL - and applies
// the chosen one, then verifies the grant actually took. Protected junctions ("/", any
// first-level directory, and mount points such as the encrypted mount root) are reported
// but NEVER modified.
func reviewPathAccess(plan setupPlan, svcUID, svcGID int) error {
	mounts := readMountpoints()
	isMount := func(dir string) bool { return mounts[dir] }
	svcGIDs := []int{svcGID}

	targets := []struct{ label, path string }{{"data directory", plan.Data}}
	if plan.Keybase != "" {
		targets = append(targets, struct{ label, path string }{"keybase root", plan.Keybase})
	}

	fmt.Println("-> path access review (can the service account reach its directories?)")
	for _, t := range targets {
		leaf := filepath.Clean(t.path)
		for _, j := range pathJunctions(t.path) {
			if j == "/" {
				continue // the root is world-traversable; never touched
			}
			if err := reviewJunction(j, j == leaf, plan.User, svcUID, svcGIDs, isMount); err != nil {
				return err
			}
		}
	}
	return nil
}

// reviewJunction tests one directory for service-account traversal and, when it blocks,
// either reports it (a protected junction) or offers and applies a remedy (any other
// junction). isLeaf marks the target directory itself, the only place a DEFAULT ACL may
// be set. It returns an error only on an unrecoverable problem (a failed stat, a declined
// mandatory step, or an unsupported filesystem); a skipped or protected junction is a
// warning, not a failure.
func reviewJunction(path string, isLeaf bool, username string, svcUID int, svcGIDs []int, isMount func(string) bool) error {
	can, state, err := junctionTraversable(path, username, svcUID, svcGIDs)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if can {
		return nil
	}
	if junctionOffLimits(path, isMount) {
		fmt.Printf("   [!] %s blocks the service account, but it is PROTECTED (root, a first-level\n", path)
		fmt.Printf("       directory, or a mount point) and is never weakened automatically.\n")
		fmt.Printf("       current: %s. Adjust it yourself if the service must traverse it\n", state)
		fmt.Printf("       (for example: sudo chmod o+x %s, or grant a group), then re-run setup.\n", path)
		return nil
	}

	fmt.Printf("   [!] %s blocks the service account (%s).\n", path, state)
	switch chooseJunctionRemedy() {
	case remedyACL:
		if err := applyTraverseACL(path, username, isLeaf); err != nil {
			return err
		}
	case remedyGroup:
		if err := applyChgrpTraverse(path, svcGIDs[0]); err != nil {
			return err
		}
	default:
		fmt.Printf("       skipped; the service account may not be able to reach past %s.\n", path)
		return nil
	}

	// Verify the remedy actually granted traversal, and re-read to confirm it persists.
	can, _, err = junctionTraversable(path, username, svcUID, svcGIDs)
	if err != nil {
		return fmt.Errorf("re-inspect %s after applying the remedy: %w", path, err)
	}
	if !can {
		fmt.Printf("       [x] traversal STILL blocked on %s after the change; adjust it by hand.\n", path)
		return nil
	}
	fmt.Printf("       [ok] %s is now traversable by the service account.\n", path)
	return nil
}

// junctionRemedy names which of the two operator-chosen remedies to apply at a blocking
// junction.
type junctionRemedy int

const (
	remedySkip  junctionRemedy = iota // leave the junction unchanged
	remedyGroup                       // change the directory's group to the service group
	remedyACL                         // add a persistent POSIX ACL granting traversal
)

// chooseJunctionRemedy asks the operator which remedy to apply at a blocking junction.
// The operator picks every time. When there is no terminal (unattended / piped setup) it
// applies the ACL remedy automatically - it is non-destructive (it adds a grant without
// changing ownership) - so an unattended install still ends up reachable.
func chooseJunctionRemedy() junctionRemedy {
	if !stdinIsTTY() {
		fmt.Println("       (no terminal: applying a POSIX ACL automatically)")
		return remedyACL
	}
	for {
		ans, err := promptLine("       Remedy - [a] add POSIX ACL, [g] change group, [s] skip: ")
		if err != nil {
			return remedySkip
		}
		switch strings.ToLower(strings.TrimSpace(ans)) {
		case "a", "acl":
			return remedyACL
		case "g", "group", "chgrp":
			return remedyGroup
		case "s", "skip", "":
			return remedySkip
		}
	}
}

// junctionTraversable reports whether the service account can traverse path, and a short
// human description of the directory's current owner and mode for the operator. It reads
// the mode and owner via stat and folds in any existing POSIX ACL that already grants the
// account execute (so a re-run over an already-fixed junction reports it as fine, making
// the whole review idempotent).
func junctionTraversable(path, username string, svcUID int, svcGIDs []int) (can bool, state string, err error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, "", err
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, "", fmt.Errorf("cannot read ownership of %s", path)
	}
	perm := fi.Mode().Perm()
	aclExec := aclGrantsExec(path, username)
	can = serviceCanTraverse(perm, int(stat.Uid), int(stat.Gid), svcUID, svcGIDs, aclExec)
	state = fmt.Sprintf("owner uid=%d gid=%d mode=%04o", stat.Uid, stat.Gid, perm)
	return can, state, nil
}

// aclGrantsExec reports whether an ACCESS ACL on path already grants username execute
// (search) permission, taking the effective mask into account. It reads getfacl output
// and never errors: a missing tool or unreadable ACL simply means "no ACL grant", and the
// mode-bit check in serviceCanTraverse still applies.
func aclGrantsExec(path, username string) bool {
	if _, err := exec.LookPath("getfacl"); err != nil {
		return false
	}
	out, err := exec.Command("getfacl", "-c", path).Output()
	if err != nil {
		return false
	}
	prefix := "user:" + username + ":"
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "default:") {
			continue
		}
		rest, ok := strings.CutPrefix(line, prefix)
		if !ok {
			continue
		}
		// rest is "<perms>" possibly with a "\t#effective:<masked>" suffix; the masked
		// value is the one that actually applies, so prefer it when present.
		perms := rest
		if i := strings.Index(rest, "#effective:"); i >= 0 {
			perms = strings.TrimSpace(rest[i+len("#effective:"):])
		} else if i := strings.IndexByte(rest, '\t'); i >= 0 {
			perms = rest[:i]
		}
		if strings.Contains(perms, "x") {
			return true
		}
	}
	return false
}

// applyTraverseACL adds a persistent POSIX ACL that lets the service account traverse
// path. On an intermediate junction it grants only "--x" (search, no read/list, no
// default entry). On the leaf directory (isLeaf) it grants "r-x" plus a matching DEFAULT
// entry, so files created there later inherit the grant - and the leaf is the ONLY place
// a default entry is ever set. setfacl -m replaces an existing entry rather than stacking,
// so re-running is idempotent. A filesystem without ACL support is reported clearly.
func applyTraverseACL(path, username string, isLeaf bool) error {
	if _, err := exec.LookPath("setfacl"); err != nil {
		return fmt.Errorf("setfacl is not installed, so the ACL cannot be applied to %s; "+
			"install the acl package and re-run setup", path)
	}
	type aclCmd struct{ args []string }
	cmds := []aclCmd{}
	if isLeaf {
		cmds = append(cmds,
			aclCmd{[]string{"-m", "u:" + username + ":r-x", path}},
			aclCmd{[]string{"-d", "-m", "u:" + username + ":r-x", path}},
		)
	} else {
		cmds = append(cmds, aclCmd{[]string{"-m", "u:" + username + ":--x", path}})
	}
	for _, c := range cmds {
		out, err := exec.Command("setfacl", c.args...).CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if strings.Contains(strings.ToLower(msg), "not supported") {
				return fmt.Errorf("the filesystem holding %s does not support POSIX ACLs (%s); "+
					"use the group remedy instead, or place the data on an ACL-capable filesystem", path, msg)
			}
			return fmt.Errorf("setfacl on %s failed: %v: %s", path, err, msg)
		}
	}
	fmt.Printf("       added a POSIX ACL granting %s traversal on %s\n", username, path)
	return nil
}

// applyChgrpTraverse changes path's group to the service account's group and, if the
// group-execute bit is not set, adds it - so the service account (a member of that group)
// can traverse the directory. It changes only this one directory, never recursively, and
// is only ever called for a non-protected junction. Re-running converges (idempotent).
func applyChgrpTraverse(path string, gid int) error {
	if err := os.Chown(path, -1, gid); err != nil {
		return fmt.Errorf("chgrp %s to gid %d: %w", path, gid, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s after chgrp: %w", path, err)
	}
	perm := fi.Mode().Perm()
	if perm&0o010 == 0 {
		if err := os.Chmod(path, perm|0o010); err != nil {
			return fmt.Errorf("add group-execute on %s: %w", path, err)
		}
	}
	fmt.Printf("       set group of %s to gid %d (with group-execute) for traversal\n", path, gid)
	return nil
}
