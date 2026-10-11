package vault

import (
	"bytes"
	"testing"
)

func TestInitSealOpenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	v, err := Init(dir, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if v.Locked() {
		t.Fatal("vault should be unlocked right after Init")
	}
	secret := []byte("AGE-SECRET-KEY-1EXAMPLEEXAMPLEEXAMPLEEXAMPLE")
	sealed, err := v.Seal(secret)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains([]byte(sealed), secret) {
		t.Fatal("sealed blob leaks the plaintext")
	}
	got, err := v.Open(sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("round trip mismatch: got %q", got)
	}
}

func TestLoadUnlockCorrectAndWrong(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir, "right-pass"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// Reload from disk and unlock with the wrong passphrase.
	v, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !v.Locked() {
		t.Fatal("loaded vault should start locked")
	}
	if err := v.Unlock("wrong-pass"); err != ErrWrongKey {
		t.Fatalf("expected ErrWrongKey, got %v", err)
	}
	if !v.Locked() {
		t.Fatal("vault must stay locked after a wrong passphrase")
	}
	// Now unlock correctly and use it.
	if err := v.Unlock("right-pass"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	sealed, err := v.Seal([]byte("hello"))
	if err != nil {
		t.Fatalf("Seal after unlock: %v", err)
	}
	pt, err := v.Open(sealed)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("Open after unlock: pt=%q err=%v", pt, err)
	}
}

func TestSealRequiresUnlock(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir, "p"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	v, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := v.Seal([]byte("x")); err != ErrLocked {
		t.Fatalf("Seal while locked: expected ErrLocked, got %v", err)
	}
	if _, err := v.Open("AAAA"); err != ErrLocked {
		t.Fatalf("Open while locked: expected ErrLocked, got %v", err)
	}
}

func TestDoubleInitFails(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir, "p"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := Init(dir, "p"); err != ErrAlreadyInit {
		t.Fatalf("second Init: expected ErrAlreadyInit, got %v", err)
	}
}

func TestDeriveStoreKey(t *testing.T) {
	dir := t.TempDir()
	v, err := Init(dir, "store-key-pass")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	k1, err := v.DeriveStoreKey()
	if err != nil {
		t.Fatalf("DeriveStoreKey: %v", err)
	}
	if len(k1) != dekLen {
		t.Fatalf("store key length = %d, want %d", len(k1), dekLen)
	}
	// Deterministic for the same unlocked vault.
	k2, err := v.DeriveStoreKey()
	if err != nil {
		t.Fatalf("DeriveStoreKey again: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("store key is not stable across calls")
	}
	// Distinct from the DEK itself (a store-key leak must not be the master key).
	if bytes.Equal(k1, v.dek) {
		t.Fatal("store key must differ from the vault DEK")
	}
	// A locked vault refuses to derive it.
	locked, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := locked.DeriveStoreKey(); err != ErrLocked {
		t.Fatalf("DeriveStoreKey while locked: expected ErrLocked, got %v", err)
	}
}

func TestTamperDetection(t *testing.T) {
	dir := t.TempDir()
	v, err := Init(dir, "p")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	sealed, err := v.Seal([]byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Flip a byte in the middle of the base64 blob.
	b := []byte(sealed)
	b[len(b)/2] ^= 0x01
	if _, err := v.Open(string(b)); err == nil {
		t.Fatal("expected Open to fail on tampered ciphertext")
	}
}
