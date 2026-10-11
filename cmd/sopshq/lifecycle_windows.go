//go:build windows

package main

import (
	"os"
	"syscall"
)

// Windows CreationFlags: DETACHED_PROCESS gives the child no console, and
// CREATE_NEW_PROCESS_GROUP puts it in its own group, so it keeps running after this
// command exits. With no console and stdin routed away, `serve` starts LOCKED and
// waits for `sopshq unlock`.
const (
	detachedProcess       = 0x00000008
	createNewProcessGroup = 0x00000200
	stillActive           = 259    // STILL_ACTIVE: the exit code of a still-running process
	processQueryLimited   = 0x1000 // PROCESS_QUERY_LIMITED_INFORMATION
)

// detachSysProcAttr detaches the child from this console and process group.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: detachedProcess | createNewProcessGroup}
}

// processAlive reports whether a process with the given pid exists. os.FindProcess
// always succeeds on Windows, so liveness is probed by opening the process and reading
// its exit code: a running process reports STILL_ACTIVE. A process that cannot be
// opened is treated as gone.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := syscall.OpenProcess(processQueryLimited, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}

// terminateProcess stops the process. Windows has no SIGTERM, so this terminates it
// directly (the same as forceKillProcess).
func terminateProcess(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

// forceKillProcess stops the process immediately.
func forceKillProcess(pid int) error {
	return terminateProcess(pid)
}
