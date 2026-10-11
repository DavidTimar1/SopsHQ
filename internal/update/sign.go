package update

import (
	"crypto/mldsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// GenerateKey creates a new ML-DSA-65 release signing key.
func GenerateKey() (*mldsa.PrivateKey, error) { return mldsa.GenerateKey(params()) }

// PrivateKeyFromSeedHex rebuilds the signing key from its hex-encoded 32-byte seed, the
// form the release pipeline holds in its secret. Surrounding whitespace is ignored.
// The errors never contain the seed.
func PrivateKeyFromSeedHex(seedHex string) (*mldsa.PrivateKey, error) {
	seed, err := hex.DecodeString(strings.TrimSpace(seedHex))
	if err != nil {
		// A fixed message: the decoder's own error names the offending byte of the seed.
		return nil, errors.New("signing seed is not valid hex")
	}
	if len(seed) != mldsa.PrivateKeySize {
		return nil, fmt.Errorf("signing seed must be %d bytes, got %d", mldsa.PrivateKeySize, len(seed))
	}
	return mldsa.NewPrivateKey(params(), seed)
}

// SeedHex renders a signing key's seed as hex. It is the secret itself: callers write
// it to a 0600 file and never print it.
func SeedHex(sk *mldsa.PrivateKey) string { return hex.EncodeToString(sk.Bytes()) }

// Sign signs message (the exact SHA256SUMS bytes) with sk.
func Sign(sk *mldsa.PrivateKey, message []byte) ([]byte, error) {
	return sk.Sign(rand.Reader, message, &mldsa.Options{Context: signingContext})
}
