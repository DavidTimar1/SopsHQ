package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"sopshq/internal/model"
)

// Session is a logged-in user's server-side state, keyed by an opaque random
// token stored in the browser's cookie.
type Session struct {
	Token    string
	UserID   string // the panel user's UUID; identifies the account even if two share a username
	Username string
	Role     model.Role
	Expires  time.Time
}

// Manager is a goroutine-safe in-memory session store. Sessions intentionally do
// not survive a restart: losing them just forces re-login, which is the safe
// default for a security tool.
type Manager struct {
	mu       sync.Mutex
	sessions map[string]Session
	ttl      time.Duration
	now      func() time.Time
}

// NewManager returns a Manager whose sessions live for ttl.
func NewManager(ttl time.Duration) *Manager {
	return &Manager{
		sessions: make(map[string]Session),
		ttl:      ttl,
		now:      time.Now,
	}
}

// Create starts a session for the user and returns it (including the token to
// set as a cookie).
func (m *Manager) Create(id, username string, role model.Role) (Session, error) {
	tok, err := newToken()
	if err != nil {
		return Session{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Session{
		Token:    tok,
		UserID:   id,
		Username: username,
		Role:     role,
		Expires:  m.now().Add(m.ttl),
	}
	m.sessions[tok] = s
	return s, nil
}

// Get returns the session for a token if it exists and has not expired. Expired
// sessions are evicted on access.
func (m *Manager) Get(token string) (Session, bool) {
	if token == "" {
		return Session{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[token]
	if !ok {
		return Session{}, false
	}
	if !m.now().Before(s.Expires) {
		delete(m.sessions, token)
		return Session{}, false
	}
	return s, true
}

// Delete ends a session (logout).
func (m *Manager) Delete(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, token)
}

// DeleteUser ends all sessions for a username (used when a user is disabled or
// their role changes).
func (m *Manager) DeleteUser(username string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for tok, s := range m.sessions {
		if s.Username == username {
			delete(m.sessions, tok)
		}
	}
}

// newToken returns a 256-bit URL-safe random session token.
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
