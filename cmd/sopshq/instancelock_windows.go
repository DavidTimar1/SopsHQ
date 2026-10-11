//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// errSharingViolation is Windows ERROR_SHARING_VIOLATION (32): CreateFile failed because
// the file is already open with a share mode that denies this open. For the lock file that
// means another live serve holds it. The stdlib syscall package does not export this
// value, so it is named here.
const errSharingViolation = syscall.Errno(32)

// acquireInstanceLock takes a process-lifetime exclusive lock on a lock file inside the
// data directory, so only one serve can own that data directory at a time. It opens the
// lock file with an exclusive share mode (FILE_SHARE_NONE, the zero share value): while
// this process holds the handle, no other process can open the same file, so a second
// serve is refused up front. It returns a release func that closes the handle (call it on
// shutdown via defer), or a refusal built by instanceLockDecision when another live serve
// already holds it. Windows drops the handle when this process dies, so a crash never
// leaves a stuck lock.
func acquireInstanceLock(dataDir string) (release func(), err error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir %s: %w", dataDir, err)
	}
	lockPath := filepath.Join(dataDir, instanceLockName)
	namep, err := syscall.UTF16PtrFromString(lockPath)
	if err != nil {
		return nil, fmt.Errorf("instance lock path %s: %w", lockPath, err)
	}
	h, err := syscall.CreateFile(
		namep,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0, // FILE_SHARE_NONE: no other process may open this file while we hold it
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		if errors.Is(err, errSharingViolation) {
			// The lock is held by another live serve. Name it from the pid file when we can.
			holder, _ := pidFileRunning(filepath.Join(dataDir, pidFileName), processAlive)
			return nil, instanceLockDecision(false, holder, dataDir)
		}
		return nil, fmt.Errorf("open instance lock %s: %w", lockPath, err)
	}
	return func() {
		_ = syscall.CloseHandle(h)
	}, nil
}
