// Package auth provides panel authentication: password hashing, login sessions,
// and role checks. It is storage-agnostic; the web layer ties it to PanelUser
// records in the store.
//
// SECURITY: passwords are never stored or logged in the clear. HashPassword
// produces a self-describing encoded string (algorithm, iterations, salt, hash)
// that is safe to persist; the original password cannot be recovered from it.
package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

const (
	// pwSaltLen is the per-password salt length in bytes.
	pwSaltLen = 16
	// pwHashLen is the derived hash length in bytes.
	pwHashLen = 32
	// pwScheme labels the encoding so a future algorithm change is detectable.
	pwScheme = "pbkdf2_sha384"
)

// pwIter is the PBKDF2 iteration count for passwords - a deliberate work factor,
// stored in the encoded hash so it can be raised over time without breaking existing
// hashes. Under `go test` it is lowered so the suite is not dominated by hashing;
// testing.Testing() is false in a real binary, so production always uses the full
// count.
var pwIter = 210000

func init() {
	if testing.Testing() {
		pwIter = 4096
	}
}

// ErrMalformedHash indicates a stored hash string is not in the expected form.
var ErrMalformedHash = errors.New("auth: malformed password hash")

// HashPassword derives a salted PBKDF2-HMAC-SHA384 hash and returns it encoded as
// "pbkdf2_sha384$<iter>$<saltb64>$<hashb64>".
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("auth: empty password")
	}
	salt := make([]byte, pwSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: rand salt: %w", err)
	}
	hash, err := pbkdf2.Key(sha512.New384, password, salt, pwIter, pwHashLen)
	if err != nil {
		return "", fmt.Errorf("auth: kdf: %w", err)
	}
	return fmt.Sprintf("%s$%d$%s$%s",
		pwScheme, pwIter,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword reports whether password matches the encoded hash, using a
// constant-time comparison. A malformed encoded string returns false (and an
// error for the caller to log without leaking which user it was).
func VerifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != pwScheme {
		return false, ErrMalformedHash
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter <= 0 {
		return false, ErrMalformedHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false, ErrMalformedHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, ErrMalformedHash
	}
	got, err := pbkdf2.Key(sha512.New384, password, salt, iter, len(want))
	if err != nil {
		return false, fmt.Errorf("auth: kdf: %w", err)
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
