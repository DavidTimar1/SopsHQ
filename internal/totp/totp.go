// Package totp implements Time-based One-Time Passwords (RFC 6238), the 6-digit
// codes from an authenticator app (Google Authenticator, 1Password, etc.).
//
// It is the second factor for logging into the SopsHQ panel. Implementation uses
// only the standard library: HMAC (crypto/hmac) over a counter derived from the
// current time, per RFC 4226 (HOTP) / RFC 6238 (TOTP).
//
// SECURITY: a user's TOTP shared secret is itself sensitive (anyone with it can
// generate valid codes). SopsHQ stores it vault-sealed and never logs it. This
// package returns the secret only at enrollment time so it can be shown to the
// user once.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strings"
	"time"
)

const (
	// digits is the code length. 6 is the universal authenticator-app default.
	digits = 6
	// period is the time step in seconds. 30 is the RFC 6238 default.
	period = 30
	// secretBytes is the size of a freshly generated shared secret (160 bits,
	// the RFC 6238 recommendation for SHA-1).
	secretBytes = 20
	// skew is how many time steps before/after "now" are accepted, to tolerate
	// clock drift and the user typing as a step rolls over. 1 => +/-30s.
	skew = 1
)

// NewSecret generates a random base32-encoded shared secret suitable for an
// authenticator app. The returned string has no padding and is uppercase, the
// form authenticator apps expect.
func NewSecret() (string, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("totp: rand: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// Code returns the current 6-digit code for the secret. It is used in tests and
// could drive a "show current code" debug view; normal login uses Verify.
func Code(secret string) (string, error) {
	return codeAt(secret, time.Now())
}

// Verify reports whether code is valid for the secret at the current time,
// accepting a small skew window. Comparison is constant-time per candidate step.
func Verify(secret, code string) bool {
	return VerifyAt(secret, code, time.Now())
}

// VerifyAt is Verify with an explicit time, for testing and determinism.
func VerifyAt(secret, code string, t time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != digits {
		return false
	}
	for i := -skew; i <= skew; i++ {
		want, err := codeAt(secret, t.Add(time.Duration(i)*period*time.Second))
		if err != nil {
			return false
		}
		if hmac.Equal([]byte(want), []byte(code)) {
			return true
		}
	}
	return false
}

// ProvisioningURI builds an otpauth:// URI that authenticator apps import (often
// via a QR code). issuer and account label the entry in the user's app.
func ProvisioningURI(secret, account, issuer string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprintf("%d", digits))
	v.Set("period", fmt.Sprintf("%d", period))
	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://totp/" + label + "?" + v.Encode()
}

// codeAt computes the code for a given moment.
func codeAt(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("totp: bad secret: %w", err)
	}
	counter := uint64(t.Unix()) / period
	return hotp(key, counter, func() hash.Hash { return sha1.New() }), nil
}

// hotp is the RFC 4226 HMAC-based one-time password: HMAC the 8-byte counter,
// dynamically truncate to a 31-bit integer, then take the low `digits` decimals.
func hotp(key []byte, counter uint64, h func() hash.Hash) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(h, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%mod)
}
