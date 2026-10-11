package update

import (
	"crypto/mldsa"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// signingContext domain-separates release signatures from any other ML-DSA use of the
// same key. The signer and the verifier must use the same value.
const signingContext = "sopshq-release-v1"

// ErrNoKey means no release signing key is embedded in this build, so no release can
// be verified and every update is refused.
var ErrNoKey = errors.New("no release signing key is embedded in this build; updates are refused " +
	"(the operator embeds the public key in internal/update/release_pubkey.hex and rebuilds)")

// embeddedKey and embeddedNextKey are the public key files compiled into the binary:
// the primary key, and an optional next key that lets the signing key be rotated. See
// the files themselves for how they are filled in.
//
//go:embed release_pubkey.hex
var embeddedKey string

//go:embed release_pubkey_next.hex
var embeddedNextKey string

// params is the one ML-DSA parameter set releases are signed with.
func params() mldsa.Parameters { return mldsa.MLDSA65() }

// Keys is the set of public keys a release signature may verify against. Primary is
// required. Next is optional: it is the key a rotation moves to, so binaries built while
// both are set accept releases signed with either, and can then be updated across the
// change.
type Keys struct {
	Primary *mldsa.PublicKey
	Next    *mldsa.PublicKey // nil when no next key is set
}

// ParseKeys decodes the primary and next key texts. An empty primary is ErrNoKey even
// when next is filled, so the rotation slot can never be the only trust anchor. An empty
// next is fine; a damaged next is an error.
func ParseKeys(primaryText, nextText string) (Keys, error) {
	primary, err := ParsePublicKey(primaryText)
	if err != nil {
		return Keys{}, err
	}
	k := Keys{Primary: primary}
	next, err := ParsePublicKey(nextText)
	switch {
	case errors.Is(err, ErrNoKey):
	case err != nil:
		return Keys{}, fmt.Errorf("next key: %w", err)
	default:
		k.Next = next
	}
	return k, nil
}

// EmbeddedKeys returns the keys compiled into this binary.
func EmbeddedKeys() (Keys, error) { return ParseKeys(embeddedKey, embeddedNextKey) }

// Matches reports whether sk's public key is the primary or the next key.
func (k Keys) Matches(sk *mldsa.PrivateKey) bool {
	pub := sk.PublicKey()
	return (k.Primary != nil && k.Primary.Equal(pub)) || (k.Next != nil && k.Next.Equal(pub))
}

// ParsePublicKey decodes a public key from text: hex, with blank lines and lines
// starting with # ignored. Text with no key in it returns ErrNoKey; text that is not a
// valid ML-DSA-65 public key is a different error, so a damaged key is never mistaken
// for an unset one.
func ParsePublicKey(text string) (*mldsa.PublicKey, error) {
	var hexKey strings.Builder
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hexKey.WriteString(line)
	}
	if hexKey.Len() == 0 {
		return nil, ErrNoKey
	}
	raw, err := hex.DecodeString(hexKey.String())
	if err != nil {
		return nil, fmt.Errorf("release public key is not valid hex: %w", err)
	}
	pk, err := mldsa.NewPublicKey(params(), raw)
	if err != nil {
		return nil, fmt.Errorf("release public key is not a valid ML-DSA-65 key: %w", err)
	}
	return pk, nil
}

// EncodePublicKey renders a public key as the hex string release_pubkey.hex holds.
func EncodePublicKey(pk *mldsa.PublicKey) string { return hex.EncodeToString(pk.Bytes()) }
