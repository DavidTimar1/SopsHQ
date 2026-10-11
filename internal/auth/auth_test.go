package auth

import (
	"strings"
	"testing"
	"time"

	"sopshq/internal/model"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	enc, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(enc, "pbkdf2_sha384$") {
		t.Fatalf("unexpected encoding: %s", enc)
	}
	if strings.Contains(enc, "correct horse") {
		t.Fatal("encoded hash leaks the password")
	}
	ok, err := VerifyPassword(enc, "correct horse battery staple")
	if err != nil || !ok {
		t.Fatalf("correct password should verify: ok=%v err=%v", ok, err)
	}
	ok, err = VerifyPassword(enc, "wrong password")
	if err != nil {
		t.Fatalf("verify wrong: unexpected err %v", err)
	}
	if ok {
		t.Fatal("wrong password must not verify")
	}
}

func TestHashIsSaltedUnique(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Fatal("two hashes of the same password should differ (random salt)")
	}
}

func TestVerifyMalformed(t *testing.T) {
	for _, bad := range []string{"", "nope", "pbkdf2_sha384$x$y", "other$1$a$b"} {
		if ok, err := VerifyPassword(bad, "pw"); ok || err == nil {
			t.Errorf("malformed %q: expected (false, error), got (%v, %v)", bad, ok, err)
		}
	}
}

func TestSessionLifecycle(t *testing.T) {
	m := NewManager(time.Hour)
	s, err := m.Create("user-1", "alice", model.RoleAdmin)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.Token == "" {
		t.Fatal("session token must not be empty")
	}
	got, ok := m.Get(s.Token)
	if !ok || got.UserID != "user-1" || got.Username != "alice" || got.Role != model.RoleAdmin {
		t.Fatalf("Get returned %+v ok=%v", got, ok)
	}
	m.Delete(s.Token)
	if _, ok := m.Get(s.Token); ok {
		t.Fatal("deleted session should be gone")
	}
}

func TestSessionExpiry(t *testing.T) {
	m := NewManager(time.Minute)
	now := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return now }
	s, _ := m.Create("user-bob", "bob", model.RoleDeveloper)
	if _, ok := m.Get(s.Token); !ok {
		t.Fatal("fresh session should be valid")
	}
	now = now.Add(2 * time.Minute) // advance past ttl
	if _, ok := m.Get(s.Token); ok {
		t.Fatal("expired session should be rejected and evicted")
	}
}

func TestDeleteUserEndsAllSessions(t *testing.T) {
	m := NewManager(time.Hour)
	s1, _ := m.Create("user-carol-1", "carol", model.RoleDeveloper)
	s2, _ := m.Create("user-carol-2", "carol", model.RoleDeveloper)
	other, _ := m.Create("user-dan", "dan", model.RoleAdmin)
	m.DeleteUser("carol")
	if _, ok := m.Get(s1.Token); ok {
		t.Fatal("carol session 1 should be gone")
	}
	if _, ok := m.Get(s2.Token); ok {
		t.Fatal("carol session 2 should be gone")
	}
	if _, ok := m.Get(other.Token); !ok {
		t.Fatal("dan session should remain")
	}
}
