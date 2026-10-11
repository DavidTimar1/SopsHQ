//go:build !unix && !windows

package main

import (
	"os"
	"path/filepath"
)

// defaultRuntimeDir is a plain temp-directory fallback on platforms SopsHQ does not
// target, which have neither systemd's /run convention nor Windows' per-user local
// app-data directory (see runtimedir_unix.go / runtimedir_windows.go).
func defaultRuntimeDir() string {
	return filepath.Join(os.TempDir(), "sopshq")
}
