//go:build !unix && !windows

package main

// acquireInstanceLock is a no-op on platforms SopsHQ does not target, which have neither
// Unix advisory file locking nor the Windows exclusive-share lock: the single-instance
// guarantee there rests on the pid file and the unlock socket alone. Linux and Windows
// both take a real process-lifetime lock (see instancelock_unix.go / instancelock_windows.go).
func acquireInstanceLock(dataDir string) (release func(), err error) {
	return func() {}, nil
}
