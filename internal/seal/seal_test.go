package seal

import (
	"bytes"
	"testing"
)

func testCrypter(t *testing.T) *Crypter {
	t.Helper()
	key := make([]byte, KeyLen)
	for i := range key {
		key[i] = byte(i + 1)
	}
	c, err := New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestRoundTrip(t *testing.T) {
	c := testCrypter(t)
	plain := []byte(`{"machine":"alpha","host":"alpha.ts.net"}`)
	blob, err := c.Seal(plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !IsSealed(blob) {
		t.Fatal("sealed blob lacks magic header")
	}
	if bytes.Contains(blob, []byte("alpha")) {
		t.Fatal("plaintext leaked into sealed blob")
	}
	got, err := c.Open(blob)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plain)
	}
}

func TestOpenRejectsPlaintext(t *testing.T) {
	c := testCrypter(t)
	if _, err := c.Open([]byte(`[{"name":"plain"}]`)); err != ErrNotSealed {
		t.Fatalf("Open on plaintext: got %v want ErrNotSealed", err)
	}
	if IsSealed([]byte("[]")) {
		t.Fatal("plaintext JSON reported as sealed")
	}
}

func TestOpenDetectsTampering(t *testing.T) {
	c := testCrypter(t)
	blob, err := c.Seal([]byte("secret-shape"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	blob[len(blob)-1] ^= 0xff // flip a ciphertext/tag bit
	if _, err := c.Open(blob); err == nil {
		t.Fatal("tampered blob opened without error")
	}
}

func TestWrongKeyFails(t *testing.T) {
	c := testCrypter(t)
	blob, err := c.Seal([]byte("data"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	other, err := New(make([]byte, KeyLen)) // different (all-zero) key
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := other.Open(blob); err == nil {
		t.Fatal("blob opened under the wrong key")
	}
}

func TestNewRejectsBadKeyLength(t *testing.T) {
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("New accepted a 16-byte key")
	}
}
