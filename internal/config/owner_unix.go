//go:build unix

package config

import (
	"os"
	"syscall"
)

// matchOwner gives f the owner and group of like. It is best effort: when the caller
// may not chown (not root, different owner) the file simply keeps its creator, which is
// what a plain write would have done.
func matchOwner(f *os.File, like os.FileInfo) {
	if st, ok := like.Sys().(*syscall.Stat_t); ok {
		_ = f.Chown(int(st.Uid), int(st.Gid))
	}
}
