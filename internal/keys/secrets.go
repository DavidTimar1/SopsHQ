package keys

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// SecretFileName is the canonical encrypted file SopsHQ manages per project. It
// must match SopsCreationRuleRegex so a freshly created file is encrypted by the
// project's .sops.yaml.
const SecretFileName = "secrets.yaml"

// secretNameRe constrains a secret NAME to a safe, sops-index-safe character set:
// letters, digits, underscore, hyphen, dot. This keeps the JSON tree index
// (["NAME"]) unambiguous (no quotes or brackets to escape) and rejects control
// characters. It does NOT constrain the VALUE, which may be any UTF-8 string.
var secretNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// ErrBadSecretName is returned when a secret name is empty or uses characters
// outside the allowed set.
var ErrBadSecretName = errors.New("keys: secret name must be non-empty and use only letters, digits, '_', '-', '.'")

// ErrSecretNotFound is returned by GetSecretValue/UnsetSecret when the name is
// absent from the file.
var ErrSecretNotFound = errors.New("keys: secret not found")

// ValidSecretName reports whether name is a legal secret name.
func ValidSecretName(name string) bool { return secretNameRe.MatchString(name) }

// sopsCmd builds an exec.Cmd for sops with the project's .sops.yaml as --config
// and the decrypting private key in SOPS_AGE_KEY (child env only, never logged).
// The child environment is scrubbed of ambient age-identity-discovery variables
// (see sopsChildEnv) so sops decrypts with ONLY this key. stderr is captured into
// errb so the caller controls what is surfaced.
func sopsCmd(bin, dir, priv string, errb *bytes.Buffer, args ...string) *exec.Cmd {
	cfg := filepath.Join(dir, ".sops.yaml")
	full := append([]string{"--config", cfg}, args...)
	cmd := exec.Command(bin, full...)
	cmd.Dir = dir
	cmd.Env = sopsChildEnv(priv)
	cmd.Stderr = errb
	return cmd
}

// secretFilePath returns the absolute path of the project's secret file.
func secretFilePath(dir string) string { return filepath.Join(dir, SecretFileName) }

// SecretFileExists reports whether the project's encrypted secret file is present.
func SecretFileExists(dir string) bool {
	_, err := os.Stat(secretFilePath(dir))
	return err == nil
}

// ListSecretNames decrypts the project's secret file and returns its top-level
// key NAMES, sorted. priv must be a private key that can decrypt the file.
//
// If the file does not exist yet, it returns an empty list and no error (a
// project simply has no secrets yet). Values are never returned, logged, or
// placed in an error: the decrypted JSON is parsed in-memory and only its keys
// escape this function.
func ListSecretNames(dir, priv string) ([]string, error) {
	bin, err := resolveSops()
	if err != nil {
		return nil, err
	}
	if !SecretFileExists(dir) {
		return nil, nil
	}
	if priv == "" {
		return nil, errors.New("keys: a private key is required to read secret names")
	}
	var out, errb bytes.Buffer
	cmd := sopsCmd(bin, dir, priv, &errb, "-d", "--output-type", "json", SecretFileName)
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		// errb may describe a decrypt failure; it does not contain secret values
		// (decryption failed) but to be safe we surface only a generic message.
		return nil, fmt.Errorf("keys: decrypt secrets: %w: %s", err, sanitizeSopsErr(errb.String()))
	}
	// The decrypted plaintext is in out; we read ONLY its top-level keys and let
	// the rest go out of scope. Use json.Decoder against a generic map.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		// An empty document decrypts to "{}" or "null"; treat as no secrets.
		t := strings.TrimSpace(out.String())
		if t == "" || t == "null" || t == "{}" {
			return nil, nil
		}
		return nil, errors.New("keys: secrets file is not a flat key/value document")
	}
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names, nil
}

// ReadSecrets decrypts the project's secret file and returns ALL of its
// top-level name -> value pairs. priv must be a private key that can decrypt the
// file. If the file does not exist yet, it returns an empty map and no error.
//
// SECURITY: the returned VALUES are plaintext secrets. They are handed back to
// the caller (the admin-only cross-project catalog sweep, held in memory and
// sent in the HTTP response body to the already-authenticated admin) and are
// NEVER logged or placed in an error here. The panel is served over plain HTTP
// by default on loopback; front it with a TLS terminator before binding it
// off-loopback, or the value crosses the network in cleartext. Callers must not
// persist or log them; group/observe in memory and discard. Values stored by
// SetSecret are JSON strings; a hand-added non-string scalar is returned as its
// JSON text.
func ReadSecrets(dir, priv string) (map[string]string, error) {
	bin, err := resolveSops()
	if err != nil {
		return nil, err
	}
	if !SecretFileExists(dir) {
		return map[string]string{}, nil
	}
	if priv == "" {
		return nil, errors.New("keys: a private key is required to read secrets")
	}
	var out, errb bytes.Buffer
	cmd := sopsCmd(bin, dir, priv, &errb, "-d", "--output-type", "json", SecretFileName)
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("keys: decrypt secrets: %w: %s", err, sanitizeSopsErr(errb.String()))
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		t := strings.TrimSpace(out.String())
		if t == "" || t == "null" || t == "{}" {
			return map[string]string{}, nil
		}
		return nil, errors.New("keys: secrets file is not a flat key/value document")
	}
	m := make(map[string]string, len(raw))
	for k, rv := range raw {
		var sv string
		if err := json.Unmarshal(rv, &sv); err == nil {
			m[k] = sv
		} else {
			m[k] = strings.TrimSpace(string(rv))
		}
	}
	return m, nil
}

// GetSecretValue decrypts and returns ONE secret value by name. The value is
// returned to the caller (the panel sends it back in the HTTP response body to
// the already-authenticated admin to prefill the edit form); it is never logged
// or put in an error. The panel is served over plain HTTP by default on
// loopback; front it with a TLS terminator before binding it off-loopback.
// Returns ErrSecretNotFound if the name is absent.
func GetSecretValue(dir, name, priv string) (string, error) {
	bin, err := resolveSops()
	if err != nil {
		return "", err
	}
	if !ValidSecretName(name) {
		return "", ErrBadSecretName
	}
	if priv == "" {
		return "", errors.New("keys: a private key is required to read a secret")
	}
	if !SecretFileExists(dir) {
		return "", ErrSecretNotFound
	}
	var out, errb bytes.Buffer
	cmd := sopsCmd(bin, dir, priv, &errb, "-d", "--extract", `["`+name+`"]`, SecretFileName)
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		// sops returns a non-zero status when the key is absent.
		if strings.Contains(errb.String(), "not found") || strings.Contains(errb.String(), "Key not found") {
			return "", ErrSecretNotFound
		}
		return "", fmt.Errorf("keys: read secret: %w: %s", err, sanitizeSopsErr(errb.String()))
	}
	return out.String(), nil
}

// SetSecret sets (creates or overwrites) name=value in the project's secret
// file, re-encrypting in place. The VALUE is passed to sops on STDIN as a
// JSON-encoded string via --value-stdin, so it never appears in the process
// argument list, in stdout, in stderr, or in any error returned here.
//
// If the secret file does not exist yet, it is created: an empty encrypted
// document is written first (matching the project's .sops.yaml creation rule),
// then the value is set. The project's .sops.yaml must already exist (the
// onboarding glue ensures this before the first SetSecret).
func SetSecret(dir, name, value, priv string) error {
	bin, err := resolveSops()
	if err != nil {
		return err
	}
	if !ValidSecretName(name) {
		return ErrBadSecretName
	}
	if priv == "" {
		return errors.New("keys: a private key is required to set a secret")
	}
	if _, err := os.Stat(filepath.Join(dir, ".sops.yaml")); err != nil {
		return errors.New("keys: project has no .sops.yaml (wire the project first)")
	}
	if !SecretFileExists(dir) {
		if err := createEmptyEncrypted(bin, dir, priv); err != nil {
			return err
		}
	}
	// Encode the value as a JSON string. encoding/json escapes control characters
	// and quotes, producing the valid JSON scalar sops set expects on stdin.
	jv, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("keys: encode secret value: %w", err)
	}
	var errb bytes.Buffer
	cmd := sopsCmd(bin, dir, priv, &errb, "set", "--value-stdin", SecretFileName, `["`+name+`"]`)
	cmd.Stdin = bytes.NewReader(jv)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keys: set secret %q: %w: %s", name, err, sanitizeSopsErr(errb.String()))
	}
	return nil
}

// UnsetSecret removes name from the project's secret file, re-encrypting in
// place. Returns ErrSecretNotFound if the name is absent.
func UnsetSecret(dir, name, priv string) error {
	bin, err := resolveSops()
	if err != nil {
		return err
	}
	if !ValidSecretName(name) {
		return ErrBadSecretName
	}
	if priv == "" {
		return errors.New("keys: a private key is required to remove a secret")
	}
	if !SecretFileExists(dir) {
		return ErrSecretNotFound
	}
	var errb bytes.Buffer
	cmd := sopsCmd(bin, dir, priv, &errb, "unset", SecretFileName, `["`+name+`"]`)
	if err := cmd.Run(); err != nil {
		if strings.Contains(errb.String(), "not found") || strings.Contains(errb.String(), "Key not found") {
			return ErrSecretNotFound
		}
		return fmt.Errorf("keys: unset secret %q: %w: %s", name, err, sanitizeSopsErr(errb.String()))
	}
	return nil
}

// createEmptyEncrypted writes an empty YAML document and encrypts it in place so
// the project gains a secrets.yaml that subsequent `sops set` calls can edit.
// The file name matches SopsCreationRuleRegex so sops finds the creation rule.
func createEmptyEncrypted(bin, dir, priv string) error {
	path := secretFilePath(dir)
	// An empty mapping. sops -e -i encrypts it to the project's recipients.
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		return fmt.Errorf("keys: create secrets file: %w", err)
	}
	var errb bytes.Buffer
	cmd := sopsCmd(bin, dir, priv, &errb, "-e", "-i", SecretFileName)
	if err := cmd.Run(); err != nil {
		_ = os.Remove(path) // do not leave a plaintext file behind on failure
		return fmt.Errorf("keys: encrypt new secrets file: %w: %s", err, sanitizeSopsErr(errb.String()))
	}
	return nil
}

// sanitizeSopsErr trims sops stderr to a single line so a multi-line dump does
// not bloat a flash message. sops stderr describes errors (missing key, bad
// config), never plaintext secret values, but we keep it terse regardless.
func sanitizeSopsErr(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
