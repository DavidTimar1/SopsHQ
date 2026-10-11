package web

import (
	"testing"
	"time"
)

// newTestLimiter returns a limiter whose clock the test controls.
func newTestLimiter(clock *time.Time) *loginLimiter {
	l := newLoginLimiter()
	l.now = func() time.Time { return *clock }
	return l
}

func TestLimiterLocksAfterThreshold(t *testing.T) {
	now := time.Now()
	l := newTestLimiter(&now)

	// The first maxLoginFailures-1 failures do not lock.
	for i := 0; i < maxLoginFailures-1; i++ {
		if justLocked := l.fail("admin"); justLocked {
			t.Fatalf("locked early after %d failures", i+1)
		}
		if locked, _ := l.locked("admin"); locked {
			t.Fatalf("reported locked after %d failures", i+1)
		}
	}

	// The threshold failure transitions into the locked state exactly once.
	if justLocked := l.fail("admin"); !justLocked {
		t.Fatalf("expected lock on failure %d", maxLoginFailures)
	}
	locked, remaining := l.locked("admin")
	if !locked {
		t.Fatal("expected username to be locked")
	}
	if remaining <= 0 || remaining > lockoutWindow {
		t.Fatalf("remaining = %v, want (0, %v]", remaining, lockoutWindow)
	}

	// A further failure while locked must NOT re-fire the transition.
	if justLocked := l.fail("admin"); justLocked {
		t.Fatal("a failure while already locked should not re-fire the lockout")
	}
}

func TestLimiterUnlocksAfterWindow(t *testing.T) {
	now := time.Now()
	l := newTestLimiter(&now)

	for i := 0; i < maxLoginFailures; i++ {
		l.fail("admin")
	}
	if locked, _ := l.locked("admin"); !locked {
		t.Fatal("expected locked right after the threshold")
	}

	// Advance past the window: the lock clears and attempts are allowed again.
	now = now.Add(lockoutWindow + time.Second)
	if locked, _ := l.locked("admin"); locked {
		t.Fatal("expected unlock after the window elapsed")
	}
	// A fresh failure starts a new count from one, not still-locked.
	if justLocked := l.fail("admin"); justLocked {
		t.Fatal("a single post-window failure should not immediately lock")
	}
}

func TestLimiterSuccessResets(t *testing.T) {
	now := time.Now()
	l := newTestLimiter(&now)

	for i := 0; i < maxLoginFailures-1; i++ {
		l.fail("admin")
	}
	l.succeed("admin") // a good login clears the slate

	// After a reset it takes the full threshold again to lock.
	for i := 0; i < maxLoginFailures-1; i++ {
		if justLocked := l.fail("admin"); justLocked {
			t.Fatalf("locked too early after reset, at failure %d", i+1)
		}
	}
	if justLocked := l.fail("admin"); !justLocked {
		t.Fatal("expected lock after a full fresh run of failures")
	}
}

func TestLimiterIsPerUsername(t *testing.T) {
	now := time.Now()
	l := newTestLimiter(&now)

	for i := 0; i < maxLoginFailures; i++ {
		l.fail("alice")
	}
	if locked, _ := l.locked("alice"); !locked {
		t.Fatal("alice should be locked")
	}
	if locked, _ := l.locked("bob"); locked {
		t.Fatal("bob must not be affected by alice's failures")
	}
}

func TestLimiterEvictsIdleEntries(t *testing.T) {
	now := time.Now()
	l := newTestLimiter(&now)

	l.fail("idle") // one stray failure, never reaches the threshold
	if len(l.entries) != 1 {
		t.Fatalf("expected 1 tracked entry, got %d", len(l.entries))
	}
	// Idle past the window: the next operation evicts it so the map stays bounded.
	now = now.Add(lockoutWindow + time.Second)
	l.locked("other") // triggers evictStale
	if _, present := l.entries["idle"]; present {
		t.Fatal("idle entry should have been evicted")
	}
}
