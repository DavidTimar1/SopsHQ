package vault

import "testing"

// TestSamePassphraseSameKey is the core of the simple-sync model: two independent
// vaults created from the SAME passphrase derive the SAME key (fixed salt), so one
// can open a blob the other sealed - with nothing exchanged between them.
func TestSamePassphraseSameKey(t *testing.T) {
	const pass = "cluster-passphrase-correct-horse"
	const secret = "AGE-SECRET-KEY-1EXAMPLEEXAMPLE"

	a, err := Init(t.TempDir(), pass)
	if err != nil {
		t.Fatalf("Init A: %v", err)
	}
	sealed, err := a.Seal([]byte(secret))
	if err != nil {
		t.Fatalf("A seal: %v", err)
	}

	b, err := Init(t.TempDir(), pass)
	if err != nil {
		t.Fatalf("Init B: %v", err)
	}
	pt, err := b.Open(sealed)
	if err != nil {
		t.Fatalf("B could not open A's blob (keys not shared): %v", err)
	}
	if string(pt) != secret {
		t.Fatalf("decrypted %q, want %q", pt, secret)
	}
}
