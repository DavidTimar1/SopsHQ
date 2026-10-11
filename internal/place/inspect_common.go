package place

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"sopshq/internal/keys"
)

// maxKeystoreBytes caps how much SopsHQ reads from a key-store file (keys.txt /
// keys.pub) on a scan or read path. A real key file is a few hundred bytes; 1 MiB is
// generous. A file larger than this is REJECTED rather than loaded, so a KeyBase
// pointed at a huge file cannot exhaust memory - the read paths run on every panel
// render during the on-disk key scan.
const maxKeystoreBytes = 1 << 20

// ReadCappedFile reads a key-store file, refusing one larger than maxKeystoreBytes. It
// stats first for a clear early rejection and backstops with an io.LimitReader in case
// the file grows or cannot be stat'd. Callers on the scan/read path (ReadPrivateKeys,
// the public-key scan) use it so an oversized file is skipped, never fully loaded. The
// error names the path and sizes only - never file contents.
func ReadCappedFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, serr := f.Stat(); serr == nil && fi.Size() > maxKeystoreBytes {
		return nil, fmt.Errorf("place: key-store file %s is too large (%d bytes; cap %d)", path, fi.Size(), maxKeystoreBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeystoreBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxKeystoreBytes {
		return nil, fmt.Errorf("place: key-store file %s exceeds the %d-byte cap", path, maxKeystoreBytes)
	}
	return data, nil
}

// sopsYAMLPath returns the .sops.yaml path SopsHQ would write for a project dir.
// Kept beside the inspector so the inspect/write pair stay in agreement.
func sopsYAMLPath(projectDir string) string {
	return filepath.Join(projectDir, ".sops.yaml")
}

// samePath reports whether two file paths refer to the same location, after
// normalizing separators and cleaning. It is a textual comparison (no stat), so
// it is safe to call on paths that may not exist. On Windows it is
// case-insensitive to match the file system; elsewhere it is case-sensitive.
func samePath(a, b string) bool {
	na := filepath.Clean(a)
	nb := filepath.Clean(b)
	if caseInsensitiveFS {
		return strings.EqualFold(na, nb)
	}
	return na == nb
}

// recipientFromPrivateBytes derives the PUBLIC age recipient (age1...) for an
// on-disk private key. It delegates to keys.RecipientFor, which runs
// `age-keygen -y` with the key on STDIN (never an argument, never a file) and
// returns only the recipient. The private bytes are not logged.
func recipientFromPrivateBytes(priv []byte) (string, error) {
	return keys.RecipientFor(strings.TrimSpace(string(priv)))
}

// ReadPrivateKey reads the on-disk private key at <base>/keys.txt and returns the
// AGE-SECRET-KEY-1 line. It is the REUSE path's bridge: the caller (keysvc) seals
// the returned key into the vault, leaving the file on disk byte-identical.
//
// It tolerates BOTH on-disk shapes so import parses consistently with the detector
// (keys.RecipientFor, which feeds the file through `age-keygen -y`):
//
//   - a bare key file (SopsHQ's own WriteKeyStore output: just the secret line), and
//   - the standard `age-keygen -o` shape that real machines
//     produce: two leading "# ..." comment lines (created /
//     public key) then the AGE-SECRET-KEY-1 line.
//
// It scans for the first line beginning with AGE-SECRET-KEY-1, ignoring blank and
// "#" comment lines.
//
// SECURITY: the returned string is a SECRET (AGE-SECRET-KEY-1...). The caller must
// seal it and never log it. This helper does not log it either (the error names
// no key bytes).
func ReadPrivateKey(base string) (string, error) {
	keys, err := ReadPrivateKeys(base)
	if err != nil {
		return "", err
	}
	return keys[0], nil
}

// ReadPrivateKeys reads EVERY age private key at <base>/keys.txt, in file order.
// A real key store may hold SEVERAL identities (a user assigned several project keys
// keeps them all in one keys.txt, and age tries each), so adopting or inspecting such
// a file must not silently reduce it to the first key. It tolerates both on-disk
// shapes (bare secret lines, and the comment-headed `age-keygen -o` output), scanning
// every AGE-SECRET-KEY-1 line and ignoring blank and "#" comment lines.
//
// SECURITY: each returned string is a SECRET (AGE-SECRET-KEY-1...). The caller seals
// them and never logs them; this helper does not log them either.
func ReadPrivateKeys(base string) ([]string, error) {
	data, err := readKeyFile(KeyFile(base))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "AGE-SECRET-KEY-1") {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("place: file does not contain an age private key")
	}
	return out, nil
}
