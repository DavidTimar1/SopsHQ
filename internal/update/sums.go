package update

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// versionHeader starts the first line of SHA256SUMS. Putting the version inside the
// signed bytes is what lets the updater refuse a replayed older release: a signature
// alone proves who published a file, not when.
const versionHeader = "# version: "

// Names of the files a release publishes besides the binaries.
const (
	SumsFile = "SHA256SUMS"
	SigFile  = "SHA256SUMS.sig"
)

// AssetName is the release asset holding the binary for goos/goarch. The name carries
// OS and architecture, so one release serves every platform from one SHA256SUMS.
func AssetName(goos, goarch string) string {
	name := "sopshq-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

var sumLineRe = regexp.MustCompile(`^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$`)

// Sums is a parsed SHA256SUMS: the release version and each asset's SHA-256.
type Sums struct {
	Version string
	files   map[string]string
}

// FormatSums renders SHA256SUMS for version: the version header, then one
// "<hex sha256>  <name>" line per asset, sorted by name. files maps name to hex.
func FormatSums(version string, files map[string]string) []byte {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var b bytes.Buffer
	b.WriteString(versionHeader + version + "\n")
	for _, n := range names {
		fmt.Fprintf(&b, "%s  %s\n", files[n], n)
	}
	return b.Bytes()
}

// ParseSums parses SHA256SUMS strictly: the first line is the version header, every
// other line is a well-formed checksum line, names are unique, and the version is a
// valid release version. Anything else is refused, because this text decides what is
// installed as root.
func ParseSums(raw []byte) (Sums, error) {
	text := string(raw)
	if !strings.HasSuffix(text, "\n") {
		return Sums{}, errors.New("SHA256SUMS does not end with a newline")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if !strings.HasPrefix(lines[0], versionHeader) {
		return Sums{}, errors.New("SHA256SUMS has no version header on its first line")
	}
	version := strings.TrimPrefix(lines[0], versionHeader)
	if _, err := ParseVersion(version); err != nil {
		return Sums{}, fmt.Errorf("SHA256SUMS version header: %w", err)
	}
	s := Sums{Version: version, files: make(map[string]string, len(lines))}
	for _, line := range lines[1:] {
		m := sumLineRe.FindStringSubmatch(line)
		if m == nil {
			return Sums{}, fmt.Errorf("SHA256SUMS has a malformed line %q", line)
		}
		if _, dup := s.files[m[2]]; dup {
			return Sums{}, fmt.Errorf("SHA256SUMS lists %s twice", m[2])
		}
		s.files[m[2]] = m[1]
	}
	return s, nil
}

// VerifySums checks the ML-DSA-65 signature (from the primary or the next key) over the exact SHA256SUMS bytes and only
// then parses them, so nothing in unsigned text is ever interpreted.
func VerifySums(keys Keys, sums, sig []byte) (Sums, error) {
	if keys.Primary == nil {
		return Sums{}, ErrNoKey
	}
	opts := &mldsa.Options{Context: signingContext}
	err := mldsa.Verify(keys.Primary, sums, sig, opts)
	if err != nil && keys.Next != nil {
		err = mldsa.Verify(keys.Next, sums, sig, opts)
	}
	if err != nil {
		return Sums{}, errors.New("the SHA256SUMS signature does not verify against the embedded release keys")
	}
	return ParseSums(sums)
}

// CheckAsset hashes r and requires it to match name's line in the (already verified)
// SHA256SUMS. A name with no line is refused.
func (s Sums) CheckAsset(name string, r io.Reader) error {
	want, ok := s.files[name]
	if !ok {
		return fmt.Errorf("SHA256SUMS has no entry for %s", name)
	}
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return fmt.Errorf("hash %s: %w", name, err)
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return fmt.Errorf("%s does not match its checksum in the signed SHA256SUMS", name)
	}
	return nil
}
