package update

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

// ErrDevBuild means the running binary carries no release version (a plain `go build`
// reports "dev"), so there is nothing to compare an update against.
var ErrDevBuild = errors.New("this is a dev build with no release version; build a release with build.sh before using update")

// ErrNotNewer means the candidate release is not newer than the installed one. An
// update to an equal or older release is how a replayed old (but validly signed)
// release would downgrade an install, so it is refused.
var ErrNotNewer = errors.New("the release is not newer than the installed version")

// versionRe is plain MAJOR.MINOR.PATCH semver with no leading zeros, the only shape
// the VERSION file and the signed release header may take. Anything else is refused
// rather than guessed at.
var versionRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// Version is a parsed MAJOR.MINOR.PATCH release version.
type Version [3]int

// ParseVersion parses a plain semver release version such as "0.83.0".
func ParseVersion(s string) (Version, error) {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return Version{}, fmt.Errorf("%q is not a MAJOR.MINOR.PATCH release version", s)
	}
	var v Version
	for i := range v {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return Version{}, fmt.Errorf("%q is not a valid release version: %w", s, err)
		}
		v[i] = n
	}
	return v, nil
}

// Compare returns -1, 0 or 1 as v is older than, equal to or newer than o.
func (v Version) Compare(o Version) int {
	for i := range v {
		switch {
		case v[i] < o[i]:
			return -1
		case v[i] > o[i]:
			return 1
		}
	}
	return 0
}

// CheckNewer returns nil only when candidate is strictly newer than installed.
// installed "dev" returns ErrDevBuild; a malformed version on either side is an
// error, so an unparseable value can never pass as "newer".
func CheckNewer(installed, candidate string) error {
	if installed == "dev" {
		return ErrDevBuild
	}
	have, err := ParseVersion(installed)
	if err != nil {
		return fmt.Errorf("installed version: %w", err)
	}
	want, err := ParseVersion(candidate)
	if err != nil {
		return fmt.Errorf("release version: %w", err)
	}
	if want.Compare(have) <= 0 {
		return fmt.Errorf("%w (installed %s, release %s)", ErrNotNewer, installed, candidate)
	}
	return nil
}
