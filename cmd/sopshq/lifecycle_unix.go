//go:build unix

package main

import (
	"errors"
	"syscall"
)

// detachSysProcAttr starts the child in its own session (setsid), with no controlling
// terminal, so it keeps running after this command exits. No terminal is also what
// makes `serve` choose LOCKED mode and wait for `sopshq unlock`.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

// processAlive reports whether a process with the given pid exists, using signal 0
// (error-checking only, no signal delivered). EPERM means the process exists but is
// owned by another user, which still counts as alive.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// terminateProcess asks the process to stop gracefully with SIGTERM.
func terminateProcess(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}

// forceKillProcess stops the process immediately with SIGKILL.
func forceKillProcess(pid int) error {
	return syscall.Kill(pid, syscall.SIGKILL)
}
