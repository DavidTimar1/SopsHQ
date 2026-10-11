package keys

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestRecipientsForSingleExec proves the consolidated derivation: a key file holding
// SEVERAL identities yields all of their public keys from ONE age-keygen call, in input
// order, so callers need no exec per key.
func TestRecipientsForSingleExec(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	kp1, err := Generate()
	if err != nil {
		t.Fatalf("generate 1: %v", err)
	}
	kp2, err := Generate()
	if err != nil {
		t.Fatalf("generate 2: %v", err)
	}
	recs, err := RecipientsFor(kp1.Private + "\n" + kp2.Private + "\n")
	if err != nil {
		t.Fatalf("RecipientsFor: %v", err)
	}
	if len(recs) != 2 || recs[0] != kp1.Recipient || recs[1] != kp2.Recipient {
		t.Fatalf("expected [%s %s] in order, got %v", kp1.Recipient, kp2.Recipient, recs)
	}
}

// TestAgeKeygenDeadline proves every age-keygen call is bounded: with the timeout
// shortened to an already-expired deadline, the exec path returns a clear timeout
// error instead of blocking the caller.
func TestAgeKeygenDeadline(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	saved := ageKeygenTimeout
	ageKeygenTimeout = time.Nanosecond
	defer func() { ageKeygenTimeout = saved }()

	if _, err := RecipientFor("AGE-SECRET-KEY-1PLACEHOLDER"); err == nil ||
		!strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected a timeout error, got %v", err)
	}
}
