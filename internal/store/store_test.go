package store

import (
	"testing"

	"sopshq/internal/model"
)

func newProject(name string) *model.Project {
	return &model.Project{M: model.Meta{UUID: NewID()}, Name: name}
}

func TestPutGetListPersist(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, "nodeA", nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	p := newProject("alpha")
	if err := s.Projects.Put(p); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if p.M.Updated.Zero() {
		t.Fatal("Put should stamp an HLC timestamp")
	}
	if p.M.Origin != "nodeA" {
		t.Fatalf("Put should stamp origin, got %q", p.M.Origin)
	}
	// Reopen from disk and confirm it persisted.
	s2, err := Open(dir, "nodeA", nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := s2.Projects.Get(p.M.UUID)
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if got.Name != "alpha" {
		t.Fatalf("persisted name mismatch: %q", got.Name)
	}
	if n := len(s2.Projects.List()); n != 1 {
		t.Fatalf("List len = %d, want 1", n)
	}
}

func TestDeleteTombstones(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, "nodeA", nil)
	p := newProject("beta")
	_ = s.Projects.Put(p)
	if err := s.Projects.Delete(p.M.UUID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Projects.Get(p.M.UUID); err != ErrNotFound {
		t.Fatalf("deleted record should be ErrNotFound, got %v", err)
	}
	if n := len(s.Projects.List()); n != 0 {
		t.Fatalf("List should hide tombstones, got %d", n)
	}
}

func TestOplogRecordsMutations(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, "nodeA", nil)
	p := newProject("gamma")
	_ = s.Projects.Put(p)
	_ = s.Projects.Delete(p.M.UUID)
	events, err := s.Oplog().Since(0)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 oplog events, got %d", len(events))
	}
	if events[0].Kind != "project" || events[0].Seq != 1 || events[1].Seq != 2 {
		t.Fatalf("unexpected oplog sequence: %+v", events)
	}
}

func TestApplyRemoteLastWriterWins(t *testing.T) {
	dirA := t.TempDir()
	a, _ := Open(dirA, "nodeA", nil)
	// nodeB makes a newer edit to the same UUID.
	dirB := t.TempDir()
	b, _ := Open(dirB, "nodeB", nil)

	p := newProject("orig")
	_ = a.Projects.Put(p)

	// Simulate B receiving A's record, then editing it later.
	bp := &model.Project{M: model.Meta{UUID: p.M.UUID}, Name: "from-A"}
	applied, _, err := b.Projects.ApplyRemote(cloneWithMeta(p))
	if err != nil || !applied {
		t.Fatalf("B apply A: applied=%v err=%v", applied, err)
	}
	_ = bp
	bEdit, _ := b.Projects.Get(p.M.UUID)
	bEdit.Name = "edited-on-B"
	_ = b.Projects.Put(bEdit)

	// A receives B's newer edit -> B wins.
	applied, conflict, err := a.Projects.ApplyRemote(cloneWithMeta(bEdit))
	if err != nil {
		t.Fatalf("A apply B: %v", err)
	}
	if !applied {
		t.Fatal("newer remote edit should be applied")
	}
	if !conflict {
		t.Fatal("independent edits from different origins should flag a conflict")
	}
	got, _ := a.Projects.Get(p.M.UUID)
	if got.Name != "edited-on-B" {
		t.Fatalf("LWW failed: got %q want edited-on-B", got.Name)
	}

	// Applying an OLDER remote must not overwrite.
	older := cloneWithMeta(p) // p still has its original (earlier) timestamp
	applied, _, _ = a.Projects.ApplyRemote(older)
	if applied {
		t.Fatal("older remote edit must not overwrite newer local")
	}
}

// cloneWithMeta makes a shallow copy preserving the replication envelope, as a
// peer would receive over the wire.
func cloneWithMeta(p *model.Project) *model.Project {
	cp := *p
	return &cp
}
