//go:build windows

package main

import "testing"

// TestAcquireInstanceLockWindows exercises the real Windows exclusive-share lock: the
// first acquire on a data dir succeeds, a second is refused while the first is held, and a
// fresh acquire succeeds again after the first is released. It runs only on Windows.
func TestAcquireInstanceLockWindows(t *testing.T) {
	dir := t.TempDir()

	release, err := acquireInstanceLock(dir)
	if err != nil {
		t.Fatalf("first acquire should succeed: %v", err)
	}
	if _, err := acquireInstanceLock(dir); err == nil {
		t.Fatal("second acquire on the same data dir should be refused while the first is held")
	}
	release()

	release2, err := acquireInstanceLock(dir)
	if err != nil {
		t.Fatalf("acquire after release should succeed: %v", err)
	}
	release2()
}
