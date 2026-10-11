package store

import (
	"testing"

	"sopshq/internal/model"
)

// TestMapViewPutGetListPersist round-trips a MapView record through the store and
// confirms it survives a reopen with its ordering intact.
func TestMapViewPutGetListPersist(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, "nodeA", nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	v := &model.MapView{
		M:       model.Meta{UUID: NewID()},
		Name:    "By machine",
		GroupBy: []string{"Machine", "OSUser"},
		Leaf:    "Project",
	}
	if err := s.MapViews.Put(v); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if v.M.Origin != "nodeA" || v.M.Updated.Zero() {
		t.Fatalf("Put should stamp origin+clock, got origin=%q zero=%v", v.M.Origin, v.M.Updated.Zero())
	}

	s2, err := Open(dir, "nodeA", nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := s2.MapViews.Get(v.M.UUID)
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if got.Name != "By machine" || got.Leaf != "Project" {
		t.Fatalf("persisted fields mismatch: %+v", got)
	}
	if len(got.GroupBy) != 2 || got.GroupBy[0] != "Machine" || got.GroupBy[1] != "OSUser" {
		t.Fatalf("persisted GroupBy mismatch: %+v", got.GroupBy)
	}
	if n := len(s2.MapViews.List()); n != 1 {
		t.Fatalf("List len = %d, want 1", n)
	}
}

// TestMapViewApplyRemoteLastWriterWins confirms a MapView replicates through the
// ApplyEvent dispatch and that last-writer-wins resolves a concurrent edit.
func TestMapViewApplyRemoteLastWriterWins(t *testing.T) {
	a, _ := Open(t.TempDir(), "nodeA", nil)
	b, _ := Open(t.TempDir(), "nodeB", nil)

	v := &model.MapView{M: model.Meta{UUID: NewID()}, Name: "orig", GroupBy: []string{"Project"}, Leaf: "SecretName"}
	if err := a.MapViews.Put(v); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// B receives A's record via the kind-dispatched ApplyEvent path.
	events, err := a.Oplog().Since(0)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(events) != 1 || events[0].Kind != "map_view" {
		t.Fatalf("expected one map_view oplog event, got %+v", events)
	}
	applied, _, err := b.ApplyEvent(events[0])
	if err != nil || !applied {
		t.Fatalf("B ApplyEvent: applied=%v err=%v", applied, err)
	}

	// B edits it later; A must accept the newer edit (LWW) and flag the conflict.
	bEdit, _ := b.MapViews.Get(v.M.UUID)
	bEdit.Name = "edited-on-B"
	if err := b.MapViews.Put(bEdit); err != nil {
		t.Fatalf("B Put: %v", err)
	}
	applied, conflict, err := a.MapViews.ApplyRemote(cloneMapView(bEdit))
	if err != nil || !applied {
		t.Fatalf("A apply B: applied=%v err=%v", applied, err)
	}
	if !conflict {
		t.Fatal("independent edits from different origins should flag a conflict")
	}
	got, _ := a.MapViews.Get(v.M.UUID)
	if got.Name != "edited-on-B" {
		t.Fatalf("LWW failed: got %q want edited-on-B", got.Name)
	}
}

func cloneMapView(v *model.MapView) *model.MapView {
	cp := *v
	cp.GroupBy = append([]string(nil), v.GroupBy...)
	return &cp
}
