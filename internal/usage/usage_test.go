package usage

import (
	"path/filepath"
	"testing"
)

func TestRecordAllRecent(t *testing.T) {
	l := Open(filepath.Join(t.TempDir(), "usage.jsonl"))
	if err := l.Record(Event{User: "alice", Path: "/p/secrets.yaml", Source: "sops-shim"}); err != nil {
		t.Fatalf("record 1: %v", err)
	}
	if err := l.Record(Event{User: "bob", Path: "/q/secrets.yaml", KeyID: "k1", Source: "sops-shim"}); err != nil {
		t.Fatalf("record 2: %v", err)
	}
	all, err := l.All()
	if err != nil || len(all) != 2 {
		t.Fatalf("All: %d err=%v", len(all), err)
	}
	if all[0].Time == 0 {
		t.Fatal("Record should stamp Time")
	}
	rec, _ := l.Recent(10)
	if len(rec) != 2 || rec[0].User != "bob" {
		t.Fatalf("Recent newest-first wrong: %+v", rec)
	}
}

func TestRecentLimitAndEmpty(t *testing.T) {
	l := Open(filepath.Join(t.TempDir(), "usage.jsonl"))
	if rec, err := l.Recent(5); err != nil || len(rec) != 0 {
		t.Fatalf("empty Recent: %d err=%v", len(rec), err)
	}
	for i := 0; i < 4; i++ {
		l.Record(Event{User: "u", Path: "/p"})
	}
	rec, _ := l.Recent(2)
	if len(rec) != 2 {
		t.Fatalf("limit not honored: %d", len(rec))
	}
}
