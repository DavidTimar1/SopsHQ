// Package seal provides whole-file authenticated encryption for SopsHQ's
// machine-local persisted data: the record store JSON files, the replication
// oplog, and the audit log.
//
// The model is the same one the vault uses for private keys (standard library
// only): AES-256-GCM, which is quantum-resistant for symmetric encryption and
// gives confidentiality AND integrity. A Crypter is built from a 32-byte key
// that the caller derives from the already-unlocked vault, so a sealed file is
// only readable after the operator unlocks the vault at startup - it never
// auto-unlocks at boot.
//
// A sealed blob is self-identifying: it begins with a fixed ASCII magic header,
// so a loader can tell a sealed file from a legacy plaintext one and migrate it
// forward (read plaintext once, rewrite sealed). The on-disk layout is:
//
//	magic(8) || nonce(gcm.NonceSize()) || ciphertext+tag
//
// SECURITY: this package never logs the key or the plaintext. The key is the
// caller's to protect; a Crypter holds only the derived AES cipher state.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// magic identifies a sealed SopsHQ data file. It is fixed ASCII; the trailing
// digit is the format version (bump it if the layout ever changes).
const magic = "SHQSEAL1"

// KeyLen is the required key length in bytes (32 -> AES-256).
const KeyLen = 32

// ErrNotSealed is returned by Open when the blob lacks the magic header, i.e. it
// is not a sealed file (most likely legacy plaintext). Callers use IsSealed to
// branch before opening.
var ErrNotSealed = errors.New("seal: not a sealed blob")

// Crypter seals and opens file-sized byte blobs under one AES-256-GCM key.
type Crypter struct {
	gcm cipher.AEAD
}

// New builds a Crypter from a 32-byte key. The key must come from the unlocked
// vault (see vault.DeriveStoreKey); New does not derive or store it elsewhere.
func New(key []byte) (*Crypter, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("seal: key must be %d bytes, got %d", KeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("seal: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("seal: gcm: %w", err)
	}
	return &Crypter{gcm: gcm}, nil
}

// IsSealed reports whether blob begins with the sealed-file magic header. It is
// cheap and safe to call on any file contents (including an empty file).
func IsSealed(blob []byte) bool {
	return len(blob) >= len(magic) && string(blob[:len(magic)]) == magic
}

// Seal encrypts plaintext and returns magic || nonce || ciphertext+tag. The
// magic header is authenticated as additional data so a truncated or swapped
// header fails the GCM tag check.
func (c *Crypter) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("seal: nonce: %w", err)
	}
	out := make([]byte, 0, len(magic)+len(nonce)+len(plaintext)+c.gcm.Overhead())
	out = append(out, magic...)
	out = append(out, nonce...)
	// Seal appends the ciphertext+tag to out; the magic bytes are the AAD.
	return c.gcm.Seal(out, nonce, plaintext, []byte(magic)), nil
}

// Open reverses Seal: it checks the magic header, then authenticates and
// decrypts. A blob without the header yields ErrNotSealed (so the caller can
// fall back to treating it as plaintext); a tampered or wrong-key blob fails the
// GCM tag check and returns an error.
func (c *Crypter) Open(blob []byte) ([]byte, error) {
	if !IsSealed(blob) {
		return nil, ErrNotSealed
	}
	body := blob[len(magic):]
	ns := c.gcm.NonceSize()
	if len(body) < ns {
		return nil, errors.New("seal: blob too short")
	}
	nonce, ct := body[:ns], body[ns:]
	pt, err := c.gcm.Open(nil, nonce, ct, []byte(magic))
	if err != nil {
		return nil, fmt.Errorf("seal: open: %w", err)
	}
	return pt, nil
}
