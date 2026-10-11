// Package vault provides the at-rest encryption for SopsHQ's crown jewels: the
// age PRIVATE keys.
//
// The model is simple and dependency-free (standard library only):
//
//   - A "vault key" is entered by the operator at startup. It is NEVER
//     stored on disk and is held only in memory for the life of the process.
//   - From that key plus a fixed application salt (the same on every machine, so the
//     same vault key yields the same DEK everywhere) we derive a 32-byte data
//     encryption key (DEK) with PBKDF2-HMAC-SHA384 (FIPS KDF, stdlib). 32 bytes
//     selects AES-256, which is quantum-resistant for symmetric encryption.
//   - Every secret blob (a private key) is sealed with AES-256-GCM under the
//     DEK. GCM gives confidentiality AND integrity (authenticated encryption).
//
// The fixed salt and the iteration count are recorded in a small metadata file
// (vault.json); they are NOT secret. A "verifier" blob (a sealed known constant) lets Unlock detect
// a wrong key without ever revealing the DEK.
//
// SECURITY: this package never logs, prints, or returns the key or the
// DEK. Callers must treat the plaintext returned by Open the same way (it is an
// age private key) and never write it to a log, audit row, or .md file.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const (
	// dekLen is 32 bytes -> AES-256.
	dekLen = 32
	// verifierPlaintext is sealed at init and re-opened at Unlock to confirm the
	// key is correct. It is a fixed, non-secret marker.
	verifierPlaintext = "sopshq-vault-verifier-v1"
	// metaFile is the on-disk metadata file name inside the vault directory.
	metaFile = "vault.json"
	// storeKeyInfo is the fixed HKDF context label that binds the derived
	// store/audit key to its purpose. Changing it would orphan existing sealed
	// data, so it is a stable, versioned constant.
	storeKeyInfo = "sopshq-store-v1"
)

// defaultIter is the PBKDF2 iteration count for new vaults. PBKDF2-HMAC-SHA384 is a
// deliberate work factor; the count is stored in metadata so it can be raised over
// time. Under `go test` it is lowered to a tiny value so the security-grade KDF does
// not make the suite slow - testing.Testing() is false in a real binary, so a
// production vault always uses the full count.
var defaultIter = 600000

func init() {
	if testing.Testing() {
		defaultIter = 4096
	}
}

// fixedSalt is the single, app-wide PBKDF2 salt. SopsHQ derives the vault key from
// the key ALONE (this constant salt, not a random per-machine one), so the
// SAME key yields the SAME key on every machine - which is what lets one
// machine decrypt the keys it syncs from another with nothing to exchange. The
// trade-off (accepted deliberately for that simplicity) is that a fixed salt offers
// no protection against precomputed/rainbow-table attacks on a WEAK key; the
// defense is a strong key plus the high PBKDF2 iteration count. It is exactly
// 16 bytes.
var fixedSalt = []byte("SopsHQ-vault-v1!")

// ErrLocked is returned by Seal/Open before a successful Unlock.
var ErrLocked = errors.New("vault: locked (call Unlock first)")

// ErrWrongKey is returned by Unlock when the key does not match
// the verifier recorded at Init time.
var ErrWrongKey = errors.New("vault: wrong key")

// ErrAlreadyInit is returned by Init when a vault already exists at the path.
var ErrAlreadyInit = errors.New("vault: already initialized")

// ErrNotInit is returned by Open/Unlock when no vault metadata exists yet.
var ErrNotInit = errors.New("vault: not initialized (run Init first)")

// meta is the non-secret on-disk metadata. Salt and Iter are public KDF
// parameters; Verifier is a sealed known constant used to check the key.
type meta struct {
	Version   int    `json:"version"`
	KDF       string `json:"kdf"`  // "pbkdf2-hmac-sha384"
	Salt      string `json:"salt"` // base64
	Iter      int    `json:"iter"`
	Verifier  string `json:"verifier"` // sealed verifierPlaintext
	Algorithm string `json:"algorithm"`
}

// Vault holds the in-memory DEK after Unlock. The zero value is unusable; use
// Load then Unlock, or Init.
type Vault struct {
	dir  string
	meta meta
	dek  []byte // nil until Unlock succeeds; never persisted, never logged
}

// Init creates a new vault under dir from the given key. It writes the
// metadata file (salt, iter, verifier) and leaves the returned Vault UNLOCKED
// (the DEK is in memory). It fails if a vault already exists.
func Init(dir, key string) (*Vault, error) {
	if key == "" {
		return nil, errors.New("vault: empty key")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("vault: mkdir: %w", err)
	}
	mp := filepath.Join(dir, metaFile)
	if _, err := os.Stat(mp); err == nil {
		return nil, ErrAlreadyInit
	}
	dek, err := deriveKey(key, fixedSalt, defaultIter)
	if err != nil {
		return nil, err
	}
	v := &Vault{
		dir: dir,
		dek: dek,
		meta: meta{
			Version:   1,
			KDF:       "pbkdf2-hmac-sha384",
			Salt:      base64.StdEncoding.EncodeToString(fixedSalt),
			Iter:      defaultIter,
			Algorithm: "aes-256-gcm",
		},
	}
	verifier, err := v.Seal([]byte(verifierPlaintext))
	if err != nil {
		return nil, err
	}
	v.meta.Verifier = verifier
	if err := v.writeMeta(); err != nil {
		return nil, err
	}
	return v, nil
}

// Load reads the metadata for an existing vault under dir without unlocking it.
// Call Unlock afterwards to provide the key.
func Load(dir string) (*Vault, error) {
	mp := filepath.Join(dir, metaFile)
	b, err := os.ReadFile(mp)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotInit
		}
		return nil, fmt.Errorf("vault: read meta: %w", err)
	}
	var m meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("vault: parse meta: %w", err)
	}
	return &Vault{dir: dir, meta: m}, nil
}

// IsInitialized reports whether a vault metadata file exists under dir.
func IsInitialized(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, metaFile))
	return err == nil
}

// Unlock derives the DEK from the key and verifies it against the stored
// verifier. On success the vault can Seal/Open; on mismatch it returns
// ErrWrongKey and stays locked.
func (v *Vault) Unlock(key string) error {
	salt, err := base64.StdEncoding.DecodeString(v.meta.Salt)
	if err != nil {
		return fmt.Errorf("vault: bad salt: %w", err)
	}
	dek, err := deriveKey(key, salt, v.meta.Iter)
	if err != nil {
		return err
	}
	// Temporarily set the DEK to attempt opening the verifier.
	v.dek = dek
	pt, err := v.Open(v.meta.Verifier)
	if err != nil || subtle.ConstantTimeCompare(pt, []byte(verifierPlaintext)) != 1 {
		v.dek = nil
		return ErrWrongKey
	}
	return nil
}

// Locked reports whether the vault still needs Unlock.
func (v *Vault) Locked() bool { return v.dek == nil }

// Seal encrypts plaintext with AES-256-GCM under the DEK and returns a base64
// string of nonce||ciphertext. Returns ErrLocked if not unlocked.
func (v *Vault) Seal(plaintext []byte) (string, error) {
	if v.dek == nil {
		return "", ErrLocked
	}
	gcm, err := newGCM(v.dek)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("vault: rand nonce: %w", err)
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Open reverses Seal: it base64-decodes, splits the nonce, and authenticates +
// decrypts. A tampered or wrong-key blob fails the GCM tag check and errors.
func (v *Vault) Open(sealed string) ([]byte, error) {
	if v.dek == nil {
		return nil, ErrLocked
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("vault: bad base64: %w", err)
	}
	gcm, err := newGCM(v.dek)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("vault: ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: open: %w", err)
	}
	return pt, nil
}

// DeriveStoreKey returns a 32-byte key for sealing the machine-local persisted
// data (the record store, the oplog, and the audit log) at rest. It is derived
// from the unlocked vault DEK with HKDF-Expand(SHA-384) under a fixed context
// label, so it is stable across runs but distinct from the DEK itself: the
// store key never decrypts a private key and vice versa. It requires an unlocked
// vault (ErrLocked otherwise) and never logs the key.
func (v *Vault) DeriveStoreKey() ([]byte, error) {
	if v.dek == nil {
		return nil, ErrLocked
	}
	key, err := hkdf.Key(sha512.New384, v.dek, nil, storeKeyInfo, dekLen)
	if err != nil {
		return nil, fmt.Errorf("vault: derive store key: %w", err)
	}
	return key, nil
}

// writeMeta atomically writes the metadata file (0600).
func (v *Vault) writeMeta() error {
	b, err := json.MarshalIndent(v.meta, "", "  ")
	if err != nil {
		return fmt.Errorf("vault: marshal meta: %w", err)
	}
	mp := filepath.Join(v.dir, metaFile)
	tmp := mp + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("vault: write meta: %w", err)
	}
	if err := os.Rename(tmp, mp); err != nil {
		return fmt.Errorf("vault: rename meta: %w", err)
	}
	return nil
}

// deriveKey runs PBKDF2-HMAC-SHA384 to produce the 32-byte DEK.
func deriveKey(key string, salt []byte, iter int) ([]byte, error) {
	dek, err := pbkdf2.Key(sha512.New384, key, salt, iter, dekLen)
	if err != nil {
		return nil, fmt.Errorf("vault: kdf: %w", err)
	}
	return dek, nil
}

// newGCM builds an AES-256-GCM AEAD from the 32-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("vault: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: gcm: %w", err)
	}
	return gcm, nil
}
