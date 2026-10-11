package keys

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidSecretName(t *testing.T) {
	ok := []string{"DB_PASSWORD", "api-key", "a.b.c", "X1", "_leading", "9start"}
	for _, n := range ok {
		if !ValidSecretName(n) {
			t.Errorf("expected %q to be valid", n)
		}
	}
	bad := []string{"", "has space", "quote\"inside", "bracket]", "new\nline", "slash/x", "tab\tx"}
	for _, n := range bad {
		if ValidSecretName(n) {
			t.Errorf("expected %q to be invalid", n)
		}
	}
}

// secretsEnv builds a project dir with a .sops.yaml for a generated key and
// returns (dir, private key). It skips when the binaries are missing.
func secretsEnv(t *testing.T) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	dir := t.TempDir()
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := WriteSopsYAML(dir, []Recipient{{Label: "tester", Age: kp.Recipient}}); err != nil {
		t.Fatalf("WriteSopsYAML: %v", err)
	}
	return dir, kp.Private
}

// TestSecretsLifecycle drives the real sops binary through the full editor flow:
// list (empty) -> set (creates file) -> list -> get -> overwrite -> set second
// -> unset -> list. It also confirms the on-disk file is encrypted (no plaintext
// value leaks to disk).
func TestSecretsLifecycle(t *testing.T) {
	dir, priv := secretsEnv(t)

	// No file yet: list is empty, get reports not found.
	if names, err := ListSecretNames(dir, priv); err != nil || len(names) != 0 {
		t.Fatalf("initial list: names=%v err=%v", names, err)
	}
	if _, err := GetSecretValue(dir, "MISSING", priv); err != ErrSecretNotFound {
		t.Fatalf("get on empty: expected ErrSecretNotFound, got %v", err)
	}

	// Set the first secret (creates the encrypted file).
	const v1 = "line1\nline2 \"quoted\" and tab\there"
	if err := SetSecret(dir, "DB_PASSWORD", v1, priv); err != nil {
		t.Fatalf("set DB_PASSWORD: %v", err)
	}
	if !SecretFileExists(dir) {
		t.Fatal("secrets file should exist after first set")
	}
	// The on-disk file must not contain the plaintext value.
	enc := readFile(t, dir)
	if strings.Contains(enc, "line2") || strings.Contains(enc, "quoted") {
		t.Fatal("plaintext value leaked into the encrypted file")
	}

	// List sees the name; get returns the exact value (round-trips specials).
	names, err := ListSecretNames(dir, priv)
	if err != nil || len(names) != 1 || names[0] != "DB_PASSWORD" {
		t.Fatalf("list after set: names=%v err=%v", names, err)
	}
	got, err := GetSecretValue(dir, "DB_PASSWORD", priv)
	if err != nil || got != v1 {
		t.Fatalf("get DB_PASSWORD: got=%q err=%v", got, err)
	}

	// Overwrite the value.
	if err := SetSecret(dir, "DB_PASSWORD", "newvalue", priv); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	if got, _ := GetSecretValue(dir, "DB_PASSWORD", priv); got != "newvalue" {
		t.Fatalf("overwrite value: got=%q", got)
	}

	// Add a second secret, then unset the first.
	if err := SetSecret(dir, "API_KEY", "abc123", priv); err != nil {
		t.Fatalf("set API_KEY: %v", err)
	}
	names, _ = ListSecretNames(dir, priv)
	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %v", names)
	}
	if err := UnsetSecret(dir, "DB_PASSWORD", priv); err != nil {
		t.Fatalf("unset DB_PASSWORD: %v", err)
	}
	names, _ = ListSecretNames(dir, priv)
	if len(names) != 1 || names[0] != "API_KEY" {
		t.Fatalf("after unset: names=%v", names)
	}

	// Unset an absent key reports not found.
	if err := UnsetSecret(dir, "DB_PASSWORD", priv); err != ErrSecretNotFound {
		t.Fatalf("unset absent: expected ErrSecretNotFound, got %v", err)
	}
}

func TestSetSecretRejectsBadName(t *testing.T) {
	dir, priv := secretsEnv(t)
	if err := SetSecret(dir, "bad name", "x", priv); err != ErrBadSecretName {
		t.Fatalf("expected ErrBadSecretName, got %v", err)
	}
}

func TestSetSecretRequiresSopsYAML(t *testing.T) {
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	dir := t.TempDir() // no .sops.yaml written
	if err := SetSecret(dir, "FOO", "bar", "AGE-SECRET-KEY-1FAKE"); err == nil {
		t.Fatal("expected an error when .sops.yaml is missing")
	}
}

// readFile returns the raw bytes of the project's secrets file as a string.
func readFile(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, SecretFileName))
	if err != nil {
		t.Fatalf("read secrets file: %v", err)
	}
	return string(b)
}
