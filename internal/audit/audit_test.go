package audit

import (
	"path/filepath"
	"testing"
)

func TestRecordAndRecentNewestFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := Open(path, "nodeA", nil)
	if err := l.Record("alice", "key_create", "proj-x", OK, "gen 1"); err != nil {
		t.Fatalf("Record 1: %v", err)
	}
	if err := l.Record("bob", "login", "bob", Denied, "bad totp"); err != nil {
		t.Fatalf("Record 2: %v", err)
	}
	got, err := l.Recent(10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	// Newest first.
	if got[0].Actor != "bob" || got[0].Outcome != Denied {
		t.Fatalf("newest-first ordering wrong: %+v", got[0])
	}
	if got[1].Actor != "alice" || got[1].Action != "key_create" {
		t.Fatalf("second entry wrong: %+v", got[1])
	}
	if got[0].Node != "nodeA" {
		t.Fatalf("node tag missing: %+v", got[0])
	}
}

func TestRecentLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := Open(path, "n", nil)
	for i := 0; i < 5; i++ {
		if err := l.Record("a", "act", "t", OK, ""); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	got, err := l.Recent(3)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("limit not honored: got %d", len(got))
	}
}

func TestRecentEmptyLog(t *testing.T) {
	l := Open(filepath.Join(t.TempDir(), "absent.jsonl"), "n", nil)
	got, err := l.Recent(10)
	if err != nil {
		t.Fatalf("Recent on empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no entries, got %d", len(got))
	}
}
