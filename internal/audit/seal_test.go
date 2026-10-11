package audit

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
		key[i] = byte(i + 3)
	}
	cr, err := seal.New(key)
	if err != nil {
		t.Fatalf("seal.New: %v", err)
	}
	return cr
}

// TestSealedAuditRoundTrip writes entries through a sealed log and confirms the
// on-disk bytes are not plaintext JSONL, while reads recover the entries.
func TestSealedAuditRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cr := testCrypter(t)
	l := Open(path, "nodeA", cr)
	if err := l.Record("alice", "key_create", "secret-target", OK, "private-detail"); err != nil {
		t.Fatalf("Record 1: %v", err)
	}
	if err := l.Record("bob", "login", "bob", Denied, ""); err != nil {
		t.Fatalf("Record 2: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if !seal.IsSealed(raw) {
		t.Fatal("audit log is not sealed")
	}
	if bytes.Contains(raw, []byte("secret-target")) || bytes.Contains(raw, []byte("private-detail")) {
		t.Fatal("plaintext audit content found in sealed file")
	}

	got, err := l.Recent(10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 2 || got[0].Actor != "bob" || got[1].Action != "key_create" {
		t.Fatalf("sealed round-trip wrong: %+v", got)
	}
}

// TestPlaintextAuditMigratesToSealed writes a plaintext log (no key), then
// appends WITH a key and confirms the file is rewritten sealed while both the old
// and new entries are preserved (the one-way at-rest upgrade).
func TestPlaintextAuditMigratesToSealed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	pl := Open(path, "nodeA", nil)
	if err := pl.Record("alice", "first", "t1", OK, ""); err != nil {
		t.Fatalf("Record plaintext: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if seal.IsSealed(raw) {
		t.Fatal("plaintext log should not be sealed")
	}

	cr := testCrypter(t)
	sl := Open(path, "nodeA", cr)
	if err := sl.Record("bob", "second", "t2", OK, ""); err != nil {
		t.Fatalf("Record sealed append: %v", err)
	}
	raw2, _ := os.ReadFile(path)
	if !seal.IsSealed(raw2) {
		t.Fatal("audit log was not migrated to sealed")
	}
	got, err := sl.Recent(10)
	if err != nil {
		t.Fatalf("Recent after migration: %v", err)
	}
	if len(got) != 2 || got[0].Action != "second" || got[1].Action != "first" {
		t.Fatalf("migration lost entries: %+v", got)
	}
}

// TestSealedAuditPurgeKeepsSealed confirms the retention rewrite paths keep the
// log sealed.
func TestSealedAuditPurgeKeepsSealed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cr := testCrypter(t)
	l := Open(path, "nodeA", cr)
	for i := 0; i < 3; i++ {
		if err := l.Record("a", "act", "t", OK, ""); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if _, err := l.PurgeAll(); err != nil {
		t.Fatalf("PurgeAll: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if !seal.IsSealed(raw) {
		t.Fatal("log not sealed after PurgeAll")
	}
	n, err := l.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 0 {
		t.Fatalf("PurgeAll left %d entries", n)
	}
}
