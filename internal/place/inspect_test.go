package place

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"sopshq/internal/keys"
)

// TestInspectEmptyTarget: a clean base + project dir reports nothing existing.
func TestInspectEmptyTarget(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY_FILE", "") // hermetic: ignore any host env var
	base := t.TempDir()
	proj := t.TempDir()
	insp := Inspect(base, proj)
	if insp.AnyExisting() {
		t.Fatalf("clean target should report nothing existing: %+v", insp)
	}
	if insp.KeysTxtPath != KeyFile(base) {
		t.Fatalf("KeysTxtPath = %q, want %q", insp.KeysTxtPath, KeyFile(base))
	}
	if insp.SopsYAMLPath != filepath.Join(proj, ".sops.yaml") {
		t.Fatalf("SopsYAMLPath = %q", insp.SopsYAMLPath)
	}
}

// TestInspectDetectsKeysTxt: a non-empty keys.txt is detected; an empty one is not.
func TestInspectDetectsKeysTxt(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY_FILE", "")
	base := t.TempDir()

	// Empty file: not treated as pre-existing state.
	if err := os.WriteFile(KeyFile(base), []byte("   \n"), 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}
	if Inspect(base, "").KeysTxtExists {
		t.Fatal("an empty keys.txt should not count as existing")
	}

	// Non-empty file: detected.
	if err := os.WriteFile(KeyFile(base), []byte("AGE-SECRET-KEY-1EXAMPLE\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	insp := Inspect(base, "")
	if !insp.KeysTxtExists || !insp.AnyExisting() {
		t.Fatalf("non-empty keys.txt should be detected: %+v", insp)
	}
}

// TestInspectKeysTxtRecipient: with age-keygen available, the public recipient is
// derived from a real on-disk private key (the private half never surfaces).
func TestInspectKeysTxtRecipient(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	t.Setenv("SOPS_AGE_KEY_FILE", "")
	base := t.TempDir()
	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := os.WriteFile(KeyFile(base), []byte(kp.Private+"\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	insp := Inspect(base, "")
	if insp.KeysTxtRecipient != kp.Recipient {
		t.Fatalf("derived recipient = %q, want %q", insp.KeysTxtRecipient, kp.Recipient)
	}
}

// TestInspectDetectsSopsYAML: an existing .sops.yaml is detected, and the
// SopsHQ-generated header is recognized as managed.
func TestInspectDetectsSopsYAML(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY_FILE", "")
	proj := t.TempDir()

	// Hand-authored .sops.yaml: detected, NOT managed.
	if err := os.WriteFile(filepath.Join(proj, ".sops.yaml"), []byte("creation_rules: []\n"), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	insp := Inspect(t.TempDir(), proj)
	if !insp.SopsYAMLExists || insp.SopsYAMLManaged {
		t.Fatalf("hand-authored .sops.yaml should be detected and unmanaged: %+v", insp)
	}

	// SopsHQ-generated .sops.yaml: detected AND managed.
	if err := os.WriteFile(filepath.Join(proj, ".sops.yaml"), []byte(keys.SopsYAML(nil)), 0o644); err != nil {
		t.Fatalf("write managed yaml: %v", err)
	}
	insp = Inspect(t.TempDir(), proj)
	if !insp.SopsYAMLExists || !insp.SopsYAMLManaged {
		t.Fatalf("SopsHQ .sops.yaml should be detected and managed: %+v", insp)
	}
}

// TestInspectEnvElsewhere: a SOPS_AGE_KEY_FILE pointing at a DIFFERENT path is
// flagged; one pointing at SopsHQ's own keys.txt is not.
func TestInspectEnvElsewhere(t *testing.T) {
	base := t.TempDir()

	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(t.TempDir(), "other", "keys.txt"))
	if !Inspect(base, "").EnvPointsElsewhere {
		t.Fatal("env var pointing elsewhere should be flagged")
	}

	t.Setenv("SOPS_AGE_KEY_FILE", KeyFile(base))
	if Inspect(base, "").EnvPointsElsewhere {
		t.Fatal("env var pointing at our own keys.txt should NOT be flagged")
	}
}

// TestReadPrivateKey: round-trips a private key and rejects a non-key file.
func TestReadPrivateKey(t *testing.T) {
	base := t.TempDir()
	want := "AGE-SECRET-KEY-1EXAMPLEEXAMPLEEXAMPLE"
	if err := os.WriteFile(KeyFile(base), []byte(want+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadPrivateKey(base)
	if err != nil || got != want {
		t.Fatalf("ReadPrivateKey = %q err=%v, want %q", got, err, want)
	}

	other := t.TempDir()
	if err := os.WriteFile(KeyFile(other), []byte("not a key\n"), 0o600); err != nil {
		t.Fatalf("write other: %v", err)
	}
	if _, err := ReadPrivateKey(other); err == nil {
		t.Fatal("expected error reading a non-key file")
	}
}

// TestReadPrivateKeyCommentHeaded parses the standard `age-keygen -o` shape (two
// "# ..." comment lines then the key line) - the format real machines
// produce. The detector tolerates it via age-keygen -y,
// so the importer must too.
func TestReadPrivateKeyCommentHeaded(t *testing.T) {
	base := t.TempDir()
	want := "AGE-SECRET-KEY-1EXAMPLEEXAMPLEEXAMPLE"
	content := "# created: 2026-06-24T20:00:00+02:00\r\n" +
		"# public key: age1exampleexampleexample\r\n" +
		want + "\r\n"
	if err := os.WriteFile(KeyFile(base), []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadPrivateKey(base)
	if err != nil || got != want {
		t.Fatalf("ReadPrivateKey(comment-headed) = %q err=%v, want %q", got, err, want)
	}
}
