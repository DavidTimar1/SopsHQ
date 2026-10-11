package web

import (
	"sync"
	"time"
)

// Login lockout policy. After maxLoginFailures consecutive failed login attempts
// for one username, that username is locked for lockoutWindow; a successful login
// clears its counter. The thresholds are deliberately lenient so a normal operator
// fat-fingering a password is not locked out. They are constants so they are easy
// to find and tune.
const (
	maxLoginFailures = 5
	lockoutWindow    = 60 * time.Second
)

// loginLimiter tracks consecutive failed login attempts per username and locks a
// username out after too many. Counters live only in process memory (no
// persistence); stale entries are evicted so the map cannot grow unbounded. It is
// safe for concurrent use by the panel's request handlers.
type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginAttempt
	now     func() time.Time // injectable clock; defaults to time.Now
}

// loginAttempt is one username's running failure state.
type loginAttempt struct {
	failures    int
	lockedUntil time.Time // zero when not locked
	lastSeen    time.Time // last activity, used to evict idle entries
}

// newLoginLimiter returns an empty limiter using the real clock.
func newLoginLimiter() *loginLimiter {
	return &loginLimiter{entries: make(map[string]*loginAttempt), now: time.Now}
}

// locked reports whether username is currently locked out and, if so, how long
// remains. An expired lock is cleared as a side effect.
func (l *loginLimiter) locked(username string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evictStale()
	e := l.entries[username]
	if e == nil || e.lockedUntil.IsZero() {
		return false, 0
	}
	remaining := e.lockedUntil.Sub(l.now())
	if remaining <= 0 {
		delete(l.entries, username)
		return false, 0
	}
	return true, remaining
}

// fail records one failed attempt for username and reports whether THIS failure
// transitioned the username into the locked state, so the caller can fire the
// lockout event exactly once. A username already locked stays locked without
// re-firing.
func (l *loginLimiter) fail(username string) (justLocked bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evictStale()
	now := l.now()
	e := l.entries[username]
	if e == nil {
		e = &loginAttempt{}
		l.entries[username] = e
	}
	e.lastSeen = now
	if !e.lockedUntil.IsZero() && e.lockedUntil.After(now) {
		return false // already locked; nothing changes
	}
	e.failures++
	if e.failures >= maxLoginFailures {
		e.lockedUntil = now.Add(lockoutWindow)
		return true
	}
	return false
}

// succeed clears any failure counter for username: a good login resets the slate.
func (l *loginLimiter) succeed(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, username)
}

// evictStale drops entries that no longer need tracking, so the map stays bounded:
// an expired lock (the slate is clean again) and an unlocked entry idle for longer
// than the window (a few stray failures that never reached the threshold). The
// caller must hold l.mu.
func (l *loginLimiter) evictStale() {
	now := l.now()
	for k, e := range l.entries {
		if e.lockedUntil.IsZero() {
			if now.Sub(e.lastSeen) > lockoutWindow {
				delete(l.entries, k)
			}
			continue
		}
		if !e.lockedUntil.After(now) {
			delete(l.entries, k)
		}
	}
}
