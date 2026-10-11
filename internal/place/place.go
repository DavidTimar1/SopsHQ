// Package place writes age private keys into a user's key store on the local
// machine in the layout sops expects (a keys.txt file read through SOPS_AGE_KEY_FILE or
// the default key path), so SopsHQ-placed keys are indistinguishable from hand-placed
// ones.
//
// The work splits in two:
//
//   - WriteKeyStore writes <base>/keys.txt (the PRIVATE key, owner-only) and
//     <base>/keys.pub (the PUBLIC recipient). This is cross-platform and is the
//     unit-tested core.
//   - EnsureDiscovery wires up how sops FINDS the key: on Linux a
//     SOPS_AGE_KEY_FILE export in ~/.bashrc plus a ~/.config/sops/age/keys.txt
//     symlink; on Windows a junction at %USERPROFILE%\.sops plus a persisted
//     SOPS_AGE_KEY_FILE. These touch the user's home/environment and are
//     OS-specific (see place_linux.go / place_windows.go). Because they write into a
//     user's home, Place runs them ONLY for a SELF placement (the account SopsHQ
//     itself runs as); a cross-user placement into the shared keybase root writes the
//     key store + POSIX ACL and never reads or writes another user's home.
//
// SECURITY: the private key is written only to keys.txt with owner-only
// permissions and is never logged. Callers pass it in memory (unsealed from the
// vault just before placement).
package place

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// Opts describes one placement.
type Opts struct {
	// Base is the key-store directory (e.g. ~/.sops or a path on an encrypted
	// volume). keys.txt and keys.pub are written here.
	Base string
	// Recipient is the public age recipient (age1...).
	Recipient string
	// Private is the secret age key (AGE-SECRET-KEY-1...). Never logged.
	Private string
	// Username is the OS account that should own the files (Linux). Empty means
	// "leave ownership as the writing process" (the common local case where the
	// server already runs as that user). Placement for another user goes through
	// KeybaseRoot and POSIX ACLs, below.
	Username string
	// KeybaseRoot, when non-empty, marks this placement as into a SHARED keybase
	// root: Base is "<KeybaseRoot>/<Username>", the root is owned by the SopsHQ
	// service account, and after keys.txt is written SopsHQ applies POSIX ACLs
	// (setfacl) so the target OS user - and only that user - can read their own key.
	// Empty means the ordinary per-home placement with no ACL step. Linux only.
	KeybaseRoot string
}

// KeyFile returns the path to the private key file for a base dir.
func KeyFile(base string) string { return filepath.Join(base, "keys.txt") }

// PubFile returns the path to the public recipient file for a base dir.
func PubFile(base string) string { return filepath.Join(base, "keys.pub") }

// WriteKeyStore creates the key store: it makes base (0700), writes keys.txt
// (owner-only) and keys.pub (0644). It is idempotent - re-running converges and
// re-asserts permissions. It does NOT wire discovery; call Place for that.
func WriteKeyStore(o Opts) error {
	if o.Base == "" {
		return errors.New("place: empty base directory")
	}
	if o.Private == "" || o.Recipient == "" {
		return errors.New("place: missing key material")
	}
	if err := os.MkdirAll(o.Base, 0o700); err != nil {
		return fmt.Errorf("place: mkdir base: %w", err)
	}
	keyPath := KeyFile(o.Base)
	if err := writeFileAtomic(keyPath, []byte(o.Private+"\n"), 0o600); err != nil {
		return fmt.Errorf("place: write keys.txt: %w", err)
	}
	// Re-assert owner-only permissions every run (the OS-specific restrict).
	if err := restrictKeyFile(keyPath); err != nil {
		return fmt.Errorf("place: restrict keys.txt: %w", err)
	}
	if err := writeFileAtomic(PubFile(o.Base), []byte(o.Recipient+"\n"), 0o644); err != nil {
		return fmt.Errorf("place: write keys.pub: %w", err)
	}
	return nil
}

// Place writes the key store and, for a SELF placement only, wires sops discovery.
//
// The discovery step (the ~/.bashrc export + ~/.config/sops/age symlink on Linux, the
// junction + persisted SOPS_AGE_KEY_FILE on Windows) writes into the target user's home,
// so it runs ONLY when the placement is for the account SopsHQ itself runs as (see
// isSelfPlacement). For any OTHER target user - a cross-user placement into the shared
// keybase root - Place writes the key store, applies the POSIX ACL grant, and STOPS: it
// never reads or writes another user's home. Those users reach their key through the ACL
// grant and call sops with explicit key/secret paths, so home discovery wiring would be
// pointless (and would require root or being that user).
//
// When Opts.KeybaseRoot is set (a shared keybase root), it applies the POSIX ACLs that
// let the target OS user read their own key. If the ACL step cannot be completed (setfacl
// missing, no ACL support, or a permission error) it FAILS LOUD - the placement returns an
// error carrying the exact remediation commands rather than leaving an unreadable key
// store behind.
func Place(o Opts) error {
	if o.KeybaseRoot != "" {
		// Never create the shared root ourselves and never write into one we do not
		// own: refuse loudly (with the one-time sudo commands) before touching disk.
		if err := checkSharedRoot(o.KeybaseRoot); err != nil {
			return err
		}
	}
	if err := WriteKeyStore(o); err != nil {
		return err
	}
	if o.KeybaseRoot != "" {
		if err := applyKeystoreACL(o); err != nil {
			return err
		}
	}
	self, err := isSelfPlacement(o)
	if err != nil {
		return err
	}
	if !self {
		// Cross-user placement: the key store + ACL are done; never touch the target
		// user's home for discovery wiring.
		return nil
	}
	return configureDiscovery(o)
}

// isSelfPlacement reports whether o targets the account SopsHQ itself runs as: an empty
// Username (the ordinary local placement for the account SopsHQ already runs as) OR a
// Username that resolves to the current process user. Only a self placement wires sops
// discovery in the user's home; a cross-user placement writes the key store + ACL and
// stops. It is cross-platform (os/user.Current).
func isSelfPlacement(o Opts) (bool, error) {
	if strings.TrimSpace(o.Username) == "" {
		return true, nil
	}
	cur, err := user.Current()
	if err != nil {
		return false, fmt.Errorf("place: resolve current user: %w", err)
	}
	return sameUsername(o.Username, cur.Username), nil
}

// sameUsername reports whether two OS account names refer to the same user. It ignores a
// DOMAIN\ or path prefix (so a stored bare name matches a prefixed process name) and uses
// the platform's case rule (Windows account names are case-insensitive, Linux
// case-sensitive), via caseInsensitiveFS.
func sameUsername(a, b string) bool {
	a, b = bareUsername(a), bareUsername(b)
	if caseInsensitiveFS {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// bareUsername strips a leading DOMAIN\ or path prefix from an account name and trims
// surrounding whitespace, yielding just the account name.
func bareUsername(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// CheckSharedRoot verifies a shared keybase root exists and is owned by the SopsHQ
// service account, WITHOUT creating or modifying it. It is used at serve start to warn
// the operator (with the one-time sudo commands) before any placement is attempted. It
// returns nil for an empty root (the feature is off).
func CheckSharedRoot(root string) error {
	if root == "" {
		return nil
	}
	return checkSharedRoot(root)
}

// VerifyKeystoreACL confirms a root-derived key store's POSIX ACLs still grant the
// target OS user read access to their own key (and that the shared root is present and
// owned by the SopsHQ account). It is the read-only check behind drift/verification for
// shared-root key stores. On an ordinary per-home placement (Opts.KeybaseRoot empty) it
// is a no-op returning nil, so callers can invoke it unconditionally.
func VerifyKeystoreACL(o Opts) error {
	if o.KeybaseRoot == "" {
		return nil
	}
	if err := checkSharedRoot(o.KeybaseRoot); err != nil {
		return err
	}
	return verifyKeystoreACL(o)
}

// writeFileAtomic writes data to path via a temp file + rename, with the given
// mode. On Windows the unix mode is advisory; restrictKeyFile applies the real
// ACL afterwards.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
