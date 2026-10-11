//go:build !unix && !windows

package main

import (
	"errors"
	"syscall"
)

// errUnsupportedPlatform is returned by the process-lifecycle helpers on platforms
// SopsHQ does not target (only Linux and Windows are supported).
var errUnsupportedPlatform = errors.New("background start/stop is not supported on this platform")

// detachSysProcAttr has no detach flags to set on this platform.
func detachSysProcAttr() *syscall.SysProcAttr { return nil }

// processAlive cannot probe liveness here; it conservatively reports "not running".
func processAlive(pid int) bool { return false }

// terminateProcess is unsupported on this platform.
func terminateProcess(pid int) error { return errUnsupportedPlatform }

// forceKillProcess is unsupported on this platform.
func forceKillProcess(pid int) error { return errUnsupportedPlatform }
