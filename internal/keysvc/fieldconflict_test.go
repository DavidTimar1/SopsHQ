package keysvc

import (
	"testing"

	"sopshq/internal/model"
	"sopshq/internal/store"
)

// TestFieldConflictSurfacesAndResolves is scenario (c) end to end: both machines edit
// the SAME field (a key's note) to different values; each surfaces exactly one field
// conflict on /conflicts with neither value lost; resolving it on one machine (the
// two-step pick) converges BOTH machines and clears the conflict everywhere.
func TestFieldConflictSurfacesAndResolves(t *testing.T) {
	svcA, stA := buildNode(t, "A")
	svcB, stB := buildNode(t, "B")

	// A shared key, generated-looking, replicated to both.
	k := &model.Key{
		M:          model.Meta{UUID: "k1"},
		Name:       "project-app",
		Type:       model.KeyShared,
		Status:     model.KeyActive,
		Recipient:  "age1pub0000000000000000000000000000000000000000",
		PrivSealed: "sealed-1",
		Generation: 1,
	}
	if err := stA.Keys.Put(k); err != nil {
		t.Fatalf("put: %v", err)
	}
	replicate(t, stA, stB)

	// Both edit the note to different values, concurrently.
	ka, _ := stA.Keys.Get("k1")
	ka.Note = "alice's note"
	_ = stA.Keys.Put(ka)
	kb, _ := stB.Keys.Get("k1")
	kb.Note = "bob's note"
	_ = stB.Keys.Put(kb)

	// Exchange both ways.
	replicate(t, stA, stB)
	replicate(t, stB, stA)

	// Both surface exactly one field conflict; neither value is lost.
	if n := svcA.FieldConflictCount(); n != 1 {
		t.Fatalf("A field conflicts = %d, want 1", n)
	}
	if n := svcB.FieldConflictCount(); n != 1 {
		t.Fatalf("B field conflicts = %d, want 1", n)
	}
	vmsA := svcA.DetectFieldConflicts()
	if vmsA[0].Group != model.KeyGroupNote || vmsA[0].Secret {
		t.Fatalf("unexpected conflict VM: %+v", vmsA[0])
	}
	if a := gotNote(t, stA); a != "alice's note" {
		t.Fatalf("A kept wrong value: %q", a)
	}
	if b := gotNote(t, stB); b != "bob's note" {
		t.Fatalf("B kept wrong value: %q", b)
	}

	// Resolve on A: take the peer's (B's) value. This is the value the web layer's
	// two-step confirm passes through.
	if err := svcA.ResolveFieldConflict(vmsA[0].ID, FieldPickRemote, "admin"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if n := svcA.FieldConflictCount(); n != 0 {
		t.Fatalf("A should have no conflict after resolving, got %d", n)
	}
	if a := gotNote(t, stA); a != "bob's note" {
		t.Fatalf("A should now hold the chosen value, got %q", a)
	}

	// The resolution replicates and converges B (its conflict clears automatically).
	replicate(t, stA, stB)
	if b := gotNote(t, stB); b != "bob's note" {
		t.Fatalf("B should converge to the resolved value, got %q", b)
	}
	if n := svcB.FieldConflictCount(); n != 0 {
		t.Fatalf("B conflict should clear after receiving the resolution, got %d", n)
	}

	// Idempotent: replaying does not resurrect the conflict or change the value.
	replicate(t, stB, stA)
	replicate(t, stA, stB)
	if svcA.FieldConflictCount() != 0 || svcB.FieldConflictCount() != 0 {
		t.Fatal("re-sync must not resurrect the resolved conflict")
	}
	if gotNote(t, stA) != "bob's note" || gotNote(t, stB) != "bob's note" {
		t.Fatal("re-sync must not change the converged value")
	}
}

func gotNote(t *testing.T, st *store.Store) string {
	t.Helper()
	k, err := st.Keys.Get("k1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	return k.Note
}
