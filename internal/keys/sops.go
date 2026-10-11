package keys

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// ErrSopsMissing means the sops binary is not on PATH.
var ErrSopsMissing = errors.New("keys: sops not found on PATH (install sops)")

// ageDiscoveryEnvVars are the environment variables sops consults to FIND a
// decrypting age identity. SopsHQ passes the exact key it wants via SOPS_AGE_KEY,
// so any of these inherited from the operator's shell (or a parallel test) are
// unwanted and could point sops at an unintended identity. Names are matched
// case-sensitively, matching Linux environment semantics.
var ageDiscoveryEnvVars = []string{
	"SOPS_AGE_KEY",
	"SOPS_AGE_KEY_FILE",
	"SOPS_AGE_KEY_CMD",
	"SOPS_AGE_SSH_PRIVATE_KEY_FILE",
	"SOPS_AGE_SSH_PRIVATE_KEY_CMD",
}

// sopsChildEnv builds the environment for a sops child process: the current
// process environment with every age-identity-discovery variable removed, plus a
// single SOPS_AGE_KEY carrying keyValue. Scrubbing the discovery variables makes
// sops decrypt with ONLY the key SopsHQ passes, never an identity discovered from
// the ambient shell. PATH, HOME, and everything else are kept intact.
//
// SECURITY: keyValue is a private key. It is placed only in the returned child
// environment and is never logged or returned in an error.
func sopsChildEnv(keyValue string) []string {
	base := os.Environ()
	out := make([]string, 0, len(base)+1)
	for _, kv := range base {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		if slices.Contains(ageDiscoveryEnvVars, name) {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "SOPS_AGE_KEY="+keyValue)
}

// sopsPath is overridable in tests; empty means "resolve from PATH".
var sopsPath string

func resolveSops() (string, error) {
	if sopsPath != "" {
		return sopsPath, nil
	}
	p, err := exec.LookPath("sops")
	if err != nil {
		return "", ErrSopsMissing
	}
	return p, nil
}

// secretFileRe matches a project's encrypted secret files by base name
// (secrets.yaml, secrets.prod.yml, ...). It mirrors SopsCreationRuleRegex but is
// anchored to the file name for local discovery.
var secretFileRe = regexp.MustCompile(`^secrets.*\.ya?ml$`)

// FindSecretFiles lists the secret files in a project directory that the
// creation rule applies to. It skips .sops.yaml itself.
func FindSecretFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("keys: read project dir: %w", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == ".sops.yaml" {
			continue
		}
		if secretFileRe.MatchString(name) {
			out = append(out, filepath.Join(dir, name))
		}
	}
	return out, nil
}

// UpdateKeys re-encrypts a file's data key to the current recipient set in the
// directory's .sops.yaml, non-interactively. Run this after changing recipients
// (adding a teammate, rotating) so existing secrets stay decryptable by the new
// set and undecryptable by removed recipients.
//
// currentPriv MUST be the private key of a recipient that can ALREADY decrypt
// the file: sops decrypts the data key with it, then re-encrypts to the new set.
// It is supplied through the SOPS_AGE_KEY environment variable so it never
// touches disk and never appears in a log. The .sops.yaml beside the file is
// passed via --config so the rule is found regardless of working directory.
//
// SECURITY: currentPriv is a secret. It is passed only in the child process
// environment and is never written to stdout/stderr or any error returned here.
func UpdateKeys(file, currentPriv string) error {
	bin, err := resolveSops()
	if err != nil {
		return err
	}
	if currentPriv == "" {
		return errors.New("keys: updatekeys needs a current private key to decrypt with")
	}
	cfg := filepath.Join(filepath.Dir(file), ".sops.yaml")
	var errb bytes.Buffer
	cmd := exec.Command(bin, "--config", cfg, "updatekeys", "--yes", file)
	cmd.Env = sopsChildEnv(currentPriv)
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keys: sops updatekeys %s: %w: %s", filepath.Base(file), err, errb.String())
	}
	return nil
}

// UpdateKeysInDir runs UpdateKeys on every secret file in a project directory,
// decrypting with currentPriv. It returns the count updated. A directory with no
// secret files is not an error (nothing to re-key yet).
func UpdateKeysInDir(dir, currentPriv string) (int, error) {
	files, err := FindSecretFiles(dir)
	if err != nil {
		return 0, err
	}
	for _, f := range files {
		if err := UpdateKeys(f, currentPriv); err != nil {
			return 0, err
		}
	}
	return len(files), nil
}
