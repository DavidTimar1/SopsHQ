//go:build unix

package main

import (
	"os"
	"syscall"
)

// dirOwnerUID returns the uid that owns path. ok is false when the path cannot be
// stat'd or its owner cannot be read, so the caller skips the ownership check rather
// than blocking on missing information.
func dirOwnerUID(path string) (uid int, ok bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
