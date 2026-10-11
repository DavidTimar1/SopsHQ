//go:build !windows

package main

import "errors"

// addUserPath persists a PATH entry only on Windows (HKCU\Environment). On other
// systems the menu never offers it - Linux installs get the /usr/local/bin symlink
// from `sopshq setup` and the printed shell-rc advice instead.
func addUserPath(dir string) error {
	return errors.New("adding to PATH automatically is a Windows-only step")
}
