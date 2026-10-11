//go:build windows

package main

import (
	"os"
	"path/filepath"
)

// defaultRuntimeDir is where the unlock socket lives on Windows: a "run" folder under
// the per-user LOCAL app-data directory (os.UserCacheDir(), resolved from
// %LOCALAPPDATA%). Local app data is machine- and profile-local and never roams,
// matching what /run means on Linux (a volatile, host-local location) - unlike the
// ROAMING %AppData% that defaultDir uses for the config and location pointer, which is
// deliberately meant to follow the user's profile across machines. A profile with no
// resolvable %LOCALAPPDATA% (a broken or minimal environment) falls back to a relative
// folder, mirroring defaultDir's own fallback.
func defaultRuntimeDir() string {
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "sopshq", "run")
	}
	return "sopshq-run"
}
