//go:build !unix && !windows

package main

import "sopshq/internal/config"

// runPreflight is a no-op on platforms SopsHQ does not target. Linux and Windows both run
// a real path preflight (see preflight_unix.go / preflight_windows.go); everywhere else
// serve's ordinary startup surfaces any real path problem.
func runPreflight(cfg *config.Config) error { return nil }
