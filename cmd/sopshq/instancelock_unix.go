//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// acquireInstanceLock takes an exclusive, non-blocking advisory lock on a lock file
// inside the data directory, so only one serve can own that data directory at a time.
// It returns a release func that drops the lock and closes the file (call it on shutdown
// via defer), or a refusal built by instanceLockDecision when another live serve already
// holds it. The lock is released automatically if this process dies, so a crash never
// leaves a stuck lock.
func acquireInstanceLock(dataDir string) (release func(), err error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir %s: %w", dataDir, err)
	}
	lockPath := filepath.Join(dataDir, instanceLockName)
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open instance lock %s: %w", lockPath, err)
	}
	if lerr := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); lerr != nil {
		f.Close()
		// The lock is held by another live serve. Name it from the pid file when we can.
		holder, _ := pidFileRunning(filepath.Join(dataDir, pidFileName), processAlive)
		return nil, instanceLockDecision(false, holder, dataDir)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
