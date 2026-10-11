package keys

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAgeKeygen(t *testing.T) {
	out := "# public key: age1sqjl2p33u296dr49y6mxhsrkfguqvs0s0uk4u04v2sw2fsx9f9dsls82rf\r\n" +
		"AGE-SECRET-KEY-1QJPUUMPFU0NSA8KEED7AYCY7Q5EAJEJ5NVY046TW4XGWYHXMRX3QM7EKAC\r\n"
	kp, err := parseAgeKeygen(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !strings.HasPrefix(kp.Recipient, "age1") {
		t.Fatalf("recipient wrong: %q", kp.Recipient)
	}
	if !strings.HasPrefix(kp.Private, "AGE-SECRET-KEY-1") {
		t.Fatalf("private wrong")
	}
}

func TestParseAgeKeygenRejectsGarbage(t *testing.T) {
	if _, err := parseAgeKeygen("not a key\n"); err == nil {
		t.Fatal("expected error on garbage input")
	}
}

func TestSopsYAMLDeterministicAndDocumented(t *testing.T) {
	a := SopsYAML([]Recipient{
		{Label: "bob", Age: "age1bbb"},
		{Label: "alice", Age: "age1aaa"},
	})
	b := SopsYAML([]Recipient{
		{Label: "alice", Age: "age1aaa"},
		{Label: "bob", Age: "age1bbb"},
	})
	if a != b {
		t.Fatal("SopsYAML should be order-independent (sorted)")
	}
	if !strings.Contains(a, "do not hand-edit") {
		t.Fatal("missing generated header")
	}
	if !strings.Contains(a, "age: age1aaa,age1bbb") {
		t.Fatalf("recipients not joined/sorted as expected:\n%s", a)
	}
	if !strings.Contains(a, "#   alice -> age1aaa") {
		t.Fatalf("missing who-is-who comment:\n%s", a)
	}
}

// runSops runs the sops binary in dir with extra env, returning stdout.
func runSops(t *testing.T, dir string, env []string, args ...string) (string, error) {
	t.Helper()
	bin, err := exec.LookPath("sops")
	if err != nil {
		t.Fatalf("sops missing")
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err = cmd.Run()
	if err != nil {
		return out.String(), &execErr{err: err, stderr: errb.String()}
	}
	return out.String(), nil
}

type execErr struct {
	err    error
	stderr string
}

func (e *execErr) Error() string { return e.err.Error() + ": " + e.stderr }

// TestEndToEndEncryptDecryptRotate exercises the real age/sops binaries: generate
// a key, write .sops.yaml, encrypt a secret, decrypt it, then add a second key
// via updatekeys and decrypt with the second key.
func TestEndToEndEncryptDecryptRotate(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}

	proj := t.TempDir()
	keyDir := t.TempDir()

	kp1, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := WriteSopsYAML(proj, []Recipient{{Label: "alice", Age: kp1.Recipient}}); err != nil {
		t.Fatalf("WriteSopsYAML: %v", err)
	}
	secret := filepath.Join(proj, "secrets.yaml")
	if err := os.WriteFile(secret, []byte("password: hunter2\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	// Encrypt in place (sops reads .sops.yaml from the project dir).
	if _, err := runSops(t, proj, nil, "-e", "-i", "secrets.yaml"); err != nil {
		t.Fatalf("sops encrypt: %v", err)
	}
	enc, _ := os.ReadFile(secret)
	if strings.Contains(string(enc), "hunter2") {
		t.Fatal("value not encrypted")
	}

	// Place key 1 and decrypt.
	key1 := filepath.Join(keyDir, "key1.txt")
	if err := os.WriteFile(key1, []byte(kp1.Private+"\n"), 0o600); err != nil {
		t.Fatalf("write key1: %v", err)
	}
	out, err := runSops(t, proj, []string{"SOPS_AGE_KEY_FILE=" + key1}, "-d", "secrets.yaml")
	if err != nil {
		t.Fatalf("decrypt with key1: %v", err)
	}
	if !strings.Contains(out, "hunter2") {
		t.Fatalf("decrypted output missing value: %q", out)
	}

	// Add a second recipient and updatekeys; decrypt with key2 only.
	kp2, err := Generate()
	if err != nil {
		t.Fatalf("Generate 2: %v", err)
	}
	if err := WriteSopsYAML(proj, []Recipient{
		{Label: "alice", Age: kp1.Recipient},
		{Label: "bob", Age: kp2.Recipient},
	}); err != nil {
		t.Fatalf("rewrite .sops.yaml: %v", err)
	}
	// updatekeys must decrypt with a current recipient (kp1) before adding kp2.
	if n, err := UpdateKeysInDir(proj, kp1.Private); err != nil || n != 1 {
		t.Fatalf("UpdateKeysInDir: n=%d err=%v", n, err)
	}
	key2 := filepath.Join(keyDir, "key2.txt")
	if err := os.WriteFile(key2, []byte(kp2.Private+"\n"), 0o600); err != nil {
		t.Fatalf("write key2: %v", err)
	}
	out, err = runSops(t, proj, []string{"SOPS_AGE_KEY_FILE=" + key2}, "-d", "secrets.yaml")
	if err != nil {
		t.Fatalf("decrypt with key2 (after updatekeys): %v", err)
	}
	if !strings.Contains(out, "hunter2") {
		t.Fatalf("key2 could not decrypt after updatekeys: %q", out)
	}
}
