//go:build !windows

package access

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// CanReadDir (Unix) rigorously evaluates traverse+read access: the user needs
// execute (traverse) on every parent directory and read+execute on the target
// directory, judged from each component's owner uid/gid and mode bits against the
// user's uid and full group set (primary + supplementary).
func CanReadDir(username, dir string) Result {
	u, err := user.Lookup(username)
	if err != nil {
		return Result{Reason: "OS user not found on this machine: " + err.Error(), Evaluated: true}
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return Result{Reason: "could not read the user's uid", Evaluated: true}
	}
	if uid == 0 {
		return Result{OK: true, Reason: "root can access any path", Evaluated: true}
	}
	gids := map[int]bool{}
	if pg, e := strconv.Atoi(u.Gid); e == nil {
		gids[pg] = true
	}
	if list, e := u.GroupIds(); e == nil {
		for _, g := range list {
			if n, e := strconv.Atoi(g); e == nil {
				gids[n] = true
			}
		}
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return Result{Reason: "bad path: " + err.Error(), Evaluated: true}
	}
	comps := ancestorPaths(abs)
	for i, p := range comps {
		fi, err := os.Stat(p)
		if err != nil {
			// This component does not exist yet; SopsHQ would create it, so we cannot
			// (and need not) judge access to it from here.
			return Result{OK: true, Evaluated: false,
				Reason: fmt.Sprintf("%s does not exist yet (will be created)", p)}
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return Result{OK: true, Evaluated: false, Reason: "could not read file ownership"}
		}
		need := uint32(0o1) // traverse parents
		what := "traverse"
		if i == len(comps)-1 {
			need = 0o5 // read+traverse the target directory
			what = "read"
		}
		if !permits(uint32(st.Uid), uint32(st.Gid), uint32(fi.Mode().Perm()), uid, gids, need) {
			return Result{Evaluated: true,
				Reason: fmt.Sprintf("user %q cannot %s %s (owner uid %d, gid %d, mode %04o)",
					username, what, p, st.Uid, st.Gid, fi.Mode().Perm())}
		}
	}
	return Result{OK: true, Evaluated: true, Reason: "accessible"}
}
