package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"sopshq/internal/seal"
)

func testCrypter(t *testing.T) *seal.Crypter {
	t.Helper()
	key := make([]byte, seal.KeyLen)
	for i := range key {
		key[i] = byte(i + 7)
	}
	cr, err := seal.New(key)
	if err != nil {
		t.Fatalf("seal.New: %v", err)
	}
	return cr
}

// TestSealedStoreRoundTrip writes records through a sealed store and confirms the
// on-disk bytes are not plaintext JSON, while a reopen with the same key recovers
// the records.
func TestSealedStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cr := testCrypter(t)
	s, err := Open(dir, "nodeA", cr)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	p := newProject("super-secret-project")
	if err := s.Projects.Put(p); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// The collection file must be sealed and must not leak the project name.
	projPath := filepath.Join(dir, "project.json")
	raw, err := os.ReadFile(projPath)
	if err != nil {
		t.Fatalf("read project.json: %v", err)
	}
	if !seal.IsSealed(raw) {
		t.Fatal("project.json is not sealed")
	}
	if bytes.Contains(raw, []byte("super-secret-project")) {
		t.Fatal("plaintext project name found in sealed file")
	}

	// The oplog must be sealed too.
	opraw, err := os.ReadFile(filepath.Join(dir, "oplog.jsonl"))
	if err != nil {
		t.Fatalf("read oplog: %v", err)
	}
	if !seal.IsSealed(opraw) {
		t.Fatal("oplog.jsonl is not sealed")
	}

	// Reopen with the same key and confirm the record survived round-trip.
	s2, err := Open(dir, "nodeA", cr)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := s2.Projects.Get(p.M.UUID)
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if got.Name != "super-secret-project" {
		t.Fatalf("round-trip name mismatch: %q", got.Name)
	}
	events, err := s2.Oplog().Since(0)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(events) != 1 || events[0].Kind != "project" {
		t.Fatalf("oplog round-trip wrong: %+v", events)
	}
}

// TestPlaintextStoreMigratesToSealed writes a plaintext store (no key), then
// reopens it WITH a key and confirms the collection file and oplog are rewritten
// sealed while the records are preserved (the one-way at-rest upgrade).
func TestPlaintextStoreMigratesToSealed(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, "nodeA", nil)
	if err != nil {
		t.Fatalf("Open plaintext: %v", err)
	}
	p := newProject("legacy-project")
	if err := s.Projects.Put(p); err != nil {
		t.Fatalf("Put: %v", err)
	}

	projPath := filepath.Join(dir, "project.json")
	raw, _ := os.ReadFile(projPath)
	if seal.IsSealed(raw) {
		t.Fatal("plaintext store should not be sealed")
	}

	// Reopen with a key: load detects plaintext and migrates forward.
	cr := testCrypter(t)
	s2, err := Open(dir, "nodeA", cr)
	if err != nil {
		t.Fatalf("reopen with key: %v", err)
	}
	raw2, _ := os.ReadFile(projPath)
	if !seal.IsSealed(raw2) {
		t.Fatal("project.json was not migrated to sealed")
	}
	opraw, _ := os.ReadFile(filepath.Join(dir, "oplog.jsonl"))
	if !seal.IsSealed(opraw) {
		t.Fatal("oplog.jsonl was not migrated to sealed")
	}
	got, err := s2.Projects.Get(p.M.UUID)
	if err != nil {
		t.Fatalf("Get after migration: %v", err)
	}
	if got.Name != "legacy-project" {
		t.Fatalf("migrated name mismatch: %q", got.Name)
	}
}

// TestSealedStoreWrongKeyFails confirms a store sealed with one key cannot be
// loaded with a different key.
func TestSealedStoreWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	cr := testCrypter(t)
	s, err := Open(dir, "nodeA", cr)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Projects.Put(newProject("x")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	other, err := seal.New(make([]byte, seal.KeyLen))
	if err != nil {
		t.Fatalf("seal.New: %v", err)
	}
	if _, err := Open(dir, "nodeA", other); err == nil {
		t.Fatal("opened a sealed store with the wrong key")
	}
}
