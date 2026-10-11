//go:build unix

package main

import (
	"os"
	"strings"
)

// defaultRuntimeDir is where the unlock socket lives on Linux and other Unix hosts.
// Under systemd the unit's RuntimeDirectory=sopshq creates /run/sopshq (0700, owned by
// the service account) and hands the path back in RUNTIME_DIRECTORY; off systemd it
// defaults to /run/sopshq. systemd may list several colon-separated paths; the first is
// used.
func defaultRuntimeDir() string {
	if d := os.Getenv("RUNTIME_DIRECTORY"); d != "" {
		if i := strings.IndexByte(d, ':'); i >= 0 {
			d = d[:i]
		}
		return d
	}
	return "/run/sopshq"
}
