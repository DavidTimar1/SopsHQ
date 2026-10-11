//go:build linux

package main

import "sopshq/internal/update"

// Programs run as root are found at fixed absolute system paths, never through PATH:
// under sudo, PATH can still hold a folder another user can write to.
var (
	systemctlPaths = []string{"/usr/bin/systemctl", "/bin/systemctl"}
	ghPaths        = update.GHPaths
)

// firstExecutable returns the first of paths that is a regular file, or "" when none is.
func firstExecutable(paths []string) string { return update.FirstExecutable(paths) }

// systemctlBin returns the absolute path of systemctl, or "" when systemd is absent.
func systemctlBin() string { return firstExecutable(systemctlPaths) }
