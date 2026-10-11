//go:build !unix

package config

import "os"

// matchOwner does nothing where file ownership does not map to Unix uid and gid.
func matchOwner(f *os.File, like os.FileInfo) {}
