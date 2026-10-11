//go:build !windows

package main

import "errors"

// errLauncherUnsupported is returned by the Startup-launcher helpers on non-Windows:
// cmdInstallLauncher/cmdUninstallLauncher already return early there, so these are
// unreachable in practice - the stub only keeps the cross-platform build compiling.
var errLauncherUnsupported = errors.New("the Windows Startup launcher is not supported on this platform")

// installLauncherScript is unreachable on non-Windows.
func installLauncherScript(bin, configPath string) (string, error) {
	return "", errLauncherUnsupported
}

// uninstallLauncherScript is unreachable on non-Windows.
func uninstallLauncherScript() (scriptPath string, removed bool, err error) {
	return "", false, errLauncherUnsupported
}
