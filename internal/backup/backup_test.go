package backup

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSet lays down a data dir (with a nested file and a known marker) plus a
// config file, and returns their paths.
func writeSet(t *testing.T, marker string) (dataDir, configPath string) {
	t.Helper()
	dataDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "key.json"), []byte(`[{"meta":{}}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "sub", "vault.json"), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath = filepath.Join(t.TempDir(), "config.jsonc")
	if err := os.WriteFile(configPath, []byte(`{"node_id":"abc"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return dataDir, configPath
}

func TestExportRestoreRoundTrip(t *testing.T) {
	const marker = "VAULT_MARKER_CONTENTS_42"
	dataDir, configPath := writeSet(t, marker)

	archive := filepath.Join(t.TempDir(), "backup.bin")
	if err := Export(dataDir, configPath, archive, "backup-pass"); err != nil {
		t.Fatalf("Export: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "restored")
	if err := Restore(archive, dst, "backup-pass"); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Data dir files restore under data/.
	if got, err := os.ReadFile(filepath.Join(dst, "data", "key.json")); err != nil || string(got) != `[{"meta":{}}]` {
		t.Fatalf("restored data/key.json = %q err=%v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(dst, "data", "sub", "vault.json")); err != nil || string(got) != marker {
		t.Fatalf("restored data/sub/vault.json = %q err=%v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(dst, "config.jsonc")); err != nil || string(got) != `{"node_id":"abc"}` {
		t.Fatalf("restored config.jsonc = %q err=%v", got, err)
	}
	// README restores and matches restoreReadme().
	got, err := os.ReadFile(filepath.Join(dst, "RESTORE_README.txt"))
	if err != nil {
		t.Fatalf("restored RESTORE_README.txt: %v", err)
	}
	if string(got) != restoreReadme() {
		t.Fatal("RESTORE_README.txt does not match restoreReadme()")
	}
}

func TestRestoreWrongPassphraseFails(t *testing.T) {
	dataDir, configPath := writeSet(t, "data")
	archive := filepath.Join(t.TempDir(), "b.bin")
	if err := Export(dataDir, configPath, archive, "right"); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if err := Restore(archive, t.TempDir(), "wrong"); err == nil {
		t.Fatal("restore with wrong passphrase must fail")
	}
}

func TestRestoreRejectsNonBackup(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.bin")
	if err := os.WriteFile(bad, []byte("not a backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Restore(bad, t.TempDir(), "p"); err == nil {
		t.Fatal("should reject a non-backup file")
	}
}

func TestSealedBlobHidesPlaintext(t *testing.T) {
	const marker = "SUPER_SECRET_MARKER_98765"
	dataDir, configPath := writeSet(t, marker)
	blob, err := Build(dataDir, configPath, "backup-pass")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if bytes.Contains(blob, []byte(marker)) {
		t.Fatal("sealed blob leaks plaintext file contents")
	}
}

func TestBuildEmptyPassphraseFails(t *testing.T) {
	dataDir, configPath := writeSet(t, "data")
	if _, err := Build(dataDir, configPath, ""); err == nil {
		t.Fatal("empty passphrase must be rejected")
	}
}

// TestRestoreIntoEmptyDirSucceeds covers the two ways a destination can be
// "empty": a path that does not exist yet (Restore creates it) and a
// directory that already exists but holds nothing.
func TestRestoreIntoEmptyDirSucceeds(t *testing.T) {
	dataDir, configPath := writeSet(t, "data")
	archive := filepath.Join(t.TempDir(), "b.bin")
	if err := Export(dataDir, configPath, archive, "pass"); err != nil {
		t.Fatalf("Export: %v", err)
	}

	nonexistent := filepath.Join(t.TempDir(), "restored")
	if err := Restore(archive, nonexistent, "pass"); err != nil {
		t.Fatalf("Restore into nonexistent dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(nonexistent, "config.jsonc")); err != nil {
		t.Fatalf("expected config.jsonc restored: %v", err)
	}

	existingEmpty := t.TempDir()
	if err := Restore(archive, existingEmpty, "pass"); err != nil {
		t.Fatalf("Restore into existing empty dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(existingEmpty, "config.jsonc")); err != nil {
		t.Fatalf("expected config.jsonc restored: %v", err)
	}
}

// TestRestoreIntoNonEmptyDirRefused proves the "-dir must be empty" contract
// is actually enforced: a destination that already holds something is
// refused with a clear error, and nothing beyond the pre-existing file is
// written - no partial extraction leaks through before the refusal.
func TestRestoreIntoNonEmptyDirRefused(t *testing.T) {
	dataDir, configPath := writeSet(t, "data")
	archive := filepath.Join(t.TempDir(), "b.bin")
	if err := Export(dataDir, configPath, archive, "pass"); err != nil {
		t.Fatalf("Export: %v", err)
	}

	dst := t.TempDir()
	preexisting := filepath.Join(dst, "keep.txt")
	if err := os.WriteFile(preexisting, []byte("do not touch"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := Restore(archive, dst, "pass")
	if err == nil {
		t.Fatal("restore into a non-empty directory must be refused")
	}
	if !strings.Contains(err.Error(), "is not empty") {
		t.Fatalf("error %q does not mention the non-empty destination", err.Error())
	}

	entries, err := os.ReadDir(dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "keep.txt" {
		t.Fatalf("destination directory was modified: %v", entries)
	}
	got, err := os.ReadFile(preexisting)
	if err != nil || string(got) != "do not touch" {
		t.Fatalf("pre-existing file was overwritten: %q err=%v", got, err)
	}
}

// TestDestDirNotEmpty covers the shared helper directly: nonexistent and
// existing-but-empty both report false; a directory holding anything reports
// true.
func TestDestDirNotEmpty(t *testing.T) {
	nonexistent := filepath.Join(t.TempDir(), "does-not-exist")
	if notEmpty, err := DestDirNotEmpty(nonexistent); err != nil || notEmpty {
		t.Fatalf("nonexistent dir: notEmpty=%v err=%v, want false/nil", notEmpty, err)
	}

	empty := t.TempDir()
	if notEmpty, err := DestDirNotEmpty(empty); err != nil || notEmpty {
		t.Fatalf("empty dir: notEmpty=%v err=%v, want false/nil", notEmpty, err)
	}

	if err := os.WriteFile(filepath.Join(empty, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if notEmpty, err := DestDirNotEmpty(empty); err != nil || !notEmpty {
		t.Fatalf("non-empty dir: notEmpty=%v err=%v, want true/nil", notEmpty, err)
	}
}
