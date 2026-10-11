// Package access answers "can this OS user reach and read this folder?" - the
// pre-flight check SopsHQ runs before it places a key or an encrypted file that the
// user's apps must later read. The evaluation is platform-specific: on Unix it is a
// rigorous uid/gid/mode + parent-traversal check (stdlib); on Windows it is a
// best-effort DACL read via the built-in `icacls` tool (no third-party dependency).
// A Result always carries a human reason and whether the platform could fully
// decide, so callers can show honest, non-secret alerts.
package access

import (
	"os"
	"os/user"
	"path/filepath"
)

// Result describes whether an OS user can traverse to and read a path.
type Result struct {
	OK        bool   // the user can traverse to and read the path
	Reason    string // human explanation (always set)
	Evaluated bool   // false when the platform could not fully decide (treat OK as "unknown")
}

// CanReadDir reports whether OS user `username` can traverse to and read directory
// `dir` (every parent included), based on the live filesystem. It is implemented
// per-OS (access_unix.go / access_windows.go).

// UserHasHome reports whether `username` resolves to a local account with an
// existing home directory - a quick way to flag system/app accounts that have no
// real home. Cross-platform (os/user + stat).
func UserHasHome(username string) (home string, ok bool, reason string) {
	u, err := user.Lookup(username)
	if err != nil {
		return "", false, "OS user not found on this machine: " + err.Error()
	}
	if u.HomeDir == "" {
		return "", false, "the account has no home directory (looks like a system/app user)"
	}
	fi, err := os.Stat(u.HomeDir)
	if err != nil || !fi.IsDir() {
		return u.HomeDir, false, "home directory does not exist: " + u.HomeDir
	}
	return u.HomeDir, true, ""
}

// permits is the pure Unix permission test: given a file's owner uid/gid and its
// permission bits, and the candidate user's uid + group set, does the user have
// ALL the bits in `need` (0o1 = execute/traverse, 0o5 = read+execute)? Unix checks
// owner bits OR group bits OR other bits, in that precedence (owner perms apply to
// the owner even if group/other are more permissive). Pure and cross-platform so it
// is unit-tested on any OS.
func permits(fileUID, fileGID uint32, mode uint32, uid int, gids map[int]bool, need uint32) bool {
	switch {
	case int(fileUID) == uid:
		return mode&(need<<6) == need<<6
	case gids[int(fileGID)]:
		return mode&(need<<3) == need<<3
	default:
		return mode&need == need
	}
}

// ancestorPaths returns every path component from the filesystem root down to abs
// (root first), e.g. /a/b/c -> [/, /a, /a/b, /a/b/c]. Used to check traverse
// permission on every parent. Cross-platform.
func ancestorPaths(abs string) []string {
	abs = filepath.Clean(abs)
	var rev []string
	for {
		rev = append(rev, abs)
		parent := filepath.Dir(abs)
		if parent == abs {
			break
		}
		abs = parent
	}
	out := make([]string, len(rev))
	for i, p := range rev {
		out[len(rev)-1-i] = p
	}
	return out
}
