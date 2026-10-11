package auth

// Recovery codes are the second-factor backup: one-time codes the operator saves
// at 2FA enrollment and can type at login instead of an authenticator code, so a
// lost authenticator never means a permanent lockout.
//
// SECURITY: a recovery code is a credential, exactly like a password. Only its
// PBKDF2-HMAC-SHA384 hash is ever stored (HashRecoveryCode); the plaintext is
// shown to the operator once at enrollment and never persisted, logged, echoed,
// or written to an audit row. Hashing reuses the same quantum-safe KDF as
// passwords.

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
)

const (
	// recoveryCount is how many one-time codes a fresh set contains.
	recoveryCount = 10
	// recoveryGroups is the number of hyphen-separated groups per code.
	recoveryGroups = 3
	// recoveryGroupLen is the number of characters in each group.
	recoveryGroupLen = 4
	// recoveryScheme labels the encoding so a future algorithm change is detectable.
	recoveryScheme = "pbkdf2_sha384_rc"
	// recoveryAlphabet excludes look-alike characters (0/O, 1/I/L) so a code can be
	// read off paper and typed back without ambiguity. 32 symbols => 5 bits each.
	recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"
)

// GenerateRecoveryCodes returns a fresh set of human-typeable one-time codes in
// plaintext (for one-time display) alongside their stored hashes. The two slices
// are index-aligned. The plaintext MUST be shown once and then discarded; only
// the hashes are persisted.
func GenerateRecoveryCodes() (plain []string, hashes []string, err error) {
	plain = make([]string, recoveryCount)
	hashes = make([]string, recoveryCount)
	for i := range plain {
		code, err := newRecoveryCode()
		if err != nil {
			return nil, nil, err
		}
		h, err := HashRecoveryCode(code)
		if err != nil {
			return nil, nil, err
		}
		plain[i] = code
		hashes[i] = h
	}
	return plain, hashes, nil
}

// newRecoveryCode builds one code like "abcd-2345-wxyz" from crypto/rand, drawing
// each character uniformly from recoveryAlphabet (rejection sampling avoids modulo
// bias).
func newRecoveryCode() (string, error) {
	total := recoveryGroups * recoveryGroupLen
	chars := make([]byte, 0, total+recoveryGroups-1)
	n := len(recoveryAlphabet)
	// 256 mod n bytes at the top of the range would bias the result; reject them.
	limit := byte(256 - (256 % n))
	for g := 0; g < recoveryGroups; g++ {
		if g > 0 {
			chars = append(chars, '-')
		}
		for c := 0; c < recoveryGroupLen; c++ {
			var b [1]byte
			for {
				if _, err := rand.Read(b[:]); err != nil {
					return "", fmt.Errorf("auth: rand recovery: %w", err)
				}
				if b[0] < limit {
					break
				}
			}
			chars = append(chars, recoveryAlphabet[int(b[0])%n])
		}
	}
	return string(chars), nil
}

// HashRecoveryCode derives a salted PBKDF2-HMAC-SHA384 hash of a recovery code,
// encoded as "pbkdf2_sha384_rc$<iter>$<saltb64>$<hashb64>". It uses the same KDF
// as passwords.
func HashRecoveryCode(code string) (string, error) {
	code = normalizeRecoveryCode(code)
	if code == "" {
		return "", errors.New("auth: empty recovery code")
	}
	salt := make([]byte, pwSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: rand salt: %w", err)
	}
	hash, err := pbkdf2.Key(sha512.New384, code, salt, pwIter, pwHashLen)
	if err != nil {
		return "", fmt.Errorf("auth: kdf: %w", err)
	}
	return fmt.Sprintf("%s$%d$%s$%s",
		recoveryScheme, pwIter,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// MatchRecoveryCode reports whether code matches the encoded hash, using a
// constant-time comparison. A malformed encoded string returns false with
// ErrMalformedHash.
func MatchRecoveryCode(encoded, code string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != recoveryScheme {
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
	got, err := pbkdf2.Key(sha512.New384, normalizeRecoveryCode(code), salt, iter, len(want))
	if err != nil {
		return false, fmt.Errorf("auth: kdf: %w", err)
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// ConsumeRecoveryCode checks code against every stored hash and, on the first
// match, returns the set with that one hash removed plus ok=true. On no match it
// returns the original set unchanged and ok=false. The match is one-time: the
// caller persists the returned (shorter) set so the code cannot be reused. Every
// stored hash is checked even after a match so timing does not leak the position.
func ConsumeRecoveryCode(hashes []string, code string) (remaining []string, ok bool) {
	if normalizeRecoveryCode(code) == "" {
		return hashes, false
	}
	matchIdx := -1
	for i, h := range hashes {
		m, err := MatchRecoveryCode(h, code)
		if err == nil && m && matchIdx < 0 {
			matchIdx = i
		}
	}
	if matchIdx < 0 {
		return hashes, false
	}
	remaining = make([]string, 0, len(hashes)-1)
	remaining = append(remaining, hashes[:matchIdx]...)
	remaining = append(remaining, hashes[matchIdx+1:]...)
	return remaining, true
}

// normalizeRecoveryCode canonicalizes operator input so display formatting does
// not affect matching: lowercase, hyphens and surrounding whitespace stripped.
// Hashing and verification both run input through this so "ABCD 2345 WXYZ" and
// "abcd-2345-wxyz" match the same stored hash.
func normalizeRecoveryCode(code string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(code) {
		if r == '-' || r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
