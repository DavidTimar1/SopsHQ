package totp

import (
	"encoding/base32"
	"testing"
	"time"
)

// rfcSecret is the RFC 6238 Appendix B SHA-1 test seed ("12345678901234567890"),
// base32-encoded the way an authenticator app would store it.
func rfcSecret() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
}

// TestRFC6238Vectors checks our 6-digit codes against the published RFC 6238
// SHA-1 test vectors (the RFC lists 8-digit codes; the 6-digit code is the low
// six digits).
func TestRFC6238Vectors(t *testing.T) {
	secret := rfcSecret()
	cases := []struct {
		unix int64
		want string // low 6 digits of the RFC 8-digit value
	}{
		{59, "287082"},         // RFC: 94287082
		{1111111109, "081804"}, // RFC: 07081804
		{1111111111, "050471"}, // RFC: 14050471
		{1234567890, "005924"}, // RFC: 89005924
		{2000000000, "279037"}, // RFC: 69279037
	}
	for _, c := range cases {
		got, err := codeAt(secret, time.Unix(c.unix, 0).UTC())
		if err != nil {
			t.Fatalf("codeAt(%d): %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("codeAt(%d) = %s, want %s", c.unix, got, c.want)
		}
	}
}

func TestVerifyAcceptsCurrentAndSkew(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	code, err := codeAt(secret, now)
	if err != nil {
		t.Fatalf("codeAt: %v", err)
	}
	if !VerifyAt(secret, code, now) {
		t.Fatal("current code should verify")
	}
	// One step earlier still within the +/-1 skew window.
	if !VerifyAt(secret, code, now.Add(30*time.Second)) {
		t.Fatal("code should verify one step later (skew)")
	}
	// Two steps away must fail.
	if VerifyAt(secret, code, now.Add(90*time.Second)) {
		t.Fatal("code two steps away must not verify")
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	secret, _ := NewSecret()
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "000000"} {
		if VerifyAt(secret, bad, time.Unix(1_700_000_000, 0)) {
			// "000000" could in theory be valid, but is astronomically unlikely
			// for a fresh random secret at this fixed time; treat as reject.
			t.Errorf("garbage code %q unexpectedly verified", bad)
		}
	}
}

func TestNewSecretIsDecodableBase32(t *testing.T) {
	s, err := NewSecret()
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s); err != nil {
		t.Fatalf("secret not valid base32: %v", err)
	}
}
