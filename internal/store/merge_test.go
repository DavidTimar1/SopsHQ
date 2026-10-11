package store

import (
	"encoding/json"
	"testing"

	"sopshq/internal/hlc"
	"sopshq/internal/model"
)

// Per-field merge tests. A Key implements model.Merger, so two nodes that edit
// DIFFERENT field groups of the same key both keep their edit, a causal update
// applies without a conflict, and a genuine same-field divergence is recorded as a
// (machine-local) FieldConflict rather than silently overwritten.

// twoNodes opens two independent stores (distinct node ids) over temp dirs.
func twoNodes(t *testing.T) (*Store, *Store) {
	t.Helper()
	a, err := Open(t.TempDir(), "A", nil)
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	b, err := Open(t.TempDir(), "B", nil)
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	return a, b
}

// syncKeys replays every oplog event from -> to (idempotent), the real replication
// path (decode snapshot + ApplyRemote).
func syncKeys(t *testing.T, from, to *Store) {
	t.Helper()
	evs, err := from.Oplog().Since(0)
	if err != nil {
		t.Fatalf("oplog since: %v", err)
	}
	for _, ev := range evs {
		if _, _, err := to.ApplyEvent(ev); err != nil {
			t.Fatalf("apply %s:%s: %v", ev.Kind, ev.UUID, err)
		}
	}
}

// baseKey returns a generated-looking key (non-empty keypair, active).
func baseKey(uuid string) *model.Key {
	return &model.Key{
		M:          model.Meta{UUID: uuid},
		Name:       "project-app",
		Type:       model.KeyShared,
		Status:     model.KeyActive,
		Recipient:  "age1originalpublickey000000000000000000000000000",
		PrivSealed: "sealed-gen1",
		Generation: 1,
	}
}

// TestPerFieldDifferentFieldsBothSurvive is scenario (a): A edits Note, B rotates the
// keypair. After bidirectional sync both nodes hold A's note AND B's rotation.
func TestPerFieldDifferentFieldsBothSurvive(t *testing.T) {
	a, b := twoNodes(t)
	k := baseKey("k1")
	if err := a.Keys.Put(k); err != nil {
		t.Fatalf("put: %v", err)
	}
	syncKeys(t, a, b) // B adopts the identical key

	// A edits the note.
	ka, _ := a.Keys.Get("k1")
	ka.Note = "reviewed by alice"
	_ = a.Keys.Put(ka)

	// B rotates the keypair (the atomic trio moves together).
	kb, _ := b.Keys.Get("k1")
	kb.Recipient = "age1rotatedpublickey1111111111111111111111111111"
	kb.PrivSealed = "sealed-gen2"
	kb.Generation = 2
	_ = b.Keys.Put(kb)

	syncKeys(t, a, b)
	syncKeys(t, b, a)

	for name, st := range map[string]*Store{"A": a, "B": b} {
		got, err := st.Keys.Get("k1")
		if err != nil {
			t.Fatalf("%s get: %v", name, err)
		}
		if got.Note != "reviewed by alice" {
			t.Fatalf("%s: note lost, got %q", name, got.Note)
		}
		if got.Generation != 2 || got.Recipient != "age1rotatedpublickey1111111111111111111111111111" || got.PrivSealed != "sealed-gen2" {
			t.Fatalf("%s: rotation lost, gen=%d rec=%q priv=%q", name, got.Generation, got.Recipient, got.PrivSealed)
		}
		if n := len(st.FieldConflicts.List()); n != 0 {
			t.Fatalf("%s: expected no field conflicts, got %d", name, n)
		}
	}
}

// TestPerFieldCausalUpdateNoConflict is scenario (b): B edits a field A never touched;
// A applies it with NO conflict.
func TestPerFieldCausalUpdateNoConflict(t *testing.T) {
	a, b := twoNodes(t)
	k := baseKey("k1")
	_ = a.Keys.Put(k)
	syncKeys(t, a, b)

	// B edits the note (A never touches it).
	kb, _ := b.Keys.Get("k1")
	kb.Note = "from B only"
	_ = b.Keys.Put(kb)

	syncKeys(t, b, a)

	got, _ := a.Keys.Get("k1")
	if got.Note != "from B only" {
		t.Fatalf("causal note not applied: %q", got.Note)
	}
	if n := len(a.FieldConflicts.List()); n != 0 {
		t.Fatalf("a causal update must not conflict, got %d field conflicts", n)
	}
}

// TestPerFieldSameFieldDivergenceSurfaces is scenario (c) at the store layer: both
// nodes edit the SAME field (Note) to different values; each records a FieldConflict
// and neither value is lost (local value preserved on each side).
func TestPerFieldSameFieldDivergenceSurfaces(t *testing.T) {
	a, b := twoNodes(t)
	k := baseKey("k1")
	_ = a.Keys.Put(k)
	syncKeys(t, a, b)

	ka, _ := a.Keys.Get("k1")
	ka.Note = "A-note"
	_ = a.Keys.Put(ka)
	kb, _ := b.Keys.Get("k1")
	kb.Note = "B-note"
	_ = b.Keys.Put(kb)

	syncKeys(t, a, b)
	syncKeys(t, b, a)

	ga, _ := a.Keys.Get("k1")
	gb, _ := b.Keys.Get("k1")
	if ga.Note != "A-note" {
		t.Fatalf("A must keep its own value, got %q", ga.Note)
	}
	if gb.Note != "B-note" {
		t.Fatalf("B must keep its own value, got %q", gb.Note)
	}
	if n := len(a.FieldConflicts.List()); n != 1 {
		t.Fatalf("A should record exactly one field conflict, got %d", n)
	}
	if n := len(b.FieldConflicts.List()); n != 1 {
		t.Fatalf("B should record exactly one field conflict, got %d", n)
	}
	// The stashed candidate on A is B's value (never lost).
	fc := a.FieldConflicts.List()[0]
	if fc.Group != model.KeyGroupNote || fc.RecordUUID != "k1" {
		t.Fatalf("unexpected conflict row: %+v", fc)
	}
	var cand model.Key
	if err := json.Unmarshal(fc.RemoteSnapshot, &cand); err != nil {
		t.Fatalf("decode candidate: %v", err)
	}
	if cand.Note != "B-note" {
		t.Fatalf("A's stashed candidate must be B's value, got %q", cand.Note)
	}
}

// TestPerFieldAtomicGroupNeverSplits is scenario (d): a rotation's Recipient +
// PrivSealed + Generation always move together - never a half-old/half-new key.
func TestPerFieldAtomicGroupNeverSplits(t *testing.T) {
	a, b := twoNodes(t)
	k := baseKey("k1")
	_ = a.Keys.Put(k)
	syncKeys(t, a, b)

	// A rotates; B independently edits an unrelated field (status).
	ka, _ := a.Keys.Get("k1")
	ka.Recipient = "age1newpub2222222222222222222222222222222222222"
	ka.PrivSealed = "sealed-gen5"
	ka.Generation = 5
	_ = a.Keys.Put(ka)
	kb, _ := b.Keys.Get("k1")
	kb.Status = model.KeyRetired
	_ = b.Keys.Put(kb)

	syncKeys(t, a, b)
	syncKeys(t, b, a)

	for name, st := range map[string]*Store{"A": a, "B": b} {
		got, _ := st.Keys.Get("k1")
		// The keypair trio is consistent (all from the rotation), never mixed.
		if got.Recipient != "age1newpub2222222222222222222222222222222222222" || got.PrivSealed != "sealed-gen5" || got.Generation != 5 {
			t.Fatalf("%s: keypair group split, rec=%q priv=%q gen=%d", name, got.Recipient, got.PrivSealed, got.Generation)
		}
		if got.Status != model.KeyRetired {
			t.Fatalf("%s: independent status edit lost, got %q", name, got.Status)
		}
	}
}

// TestPerFieldConvergenceIdempotent is scenario (e): after convergence, replaying the
// same events changes nothing and both nodes are byte-equal on the merged record.
func TestPerFieldConvergenceIdempotent(t *testing.T) {
	a, b := twoNodes(t)
	k := baseKey("k1")
	_ = a.Keys.Put(k)
	syncKeys(t, a, b)

	ka, _ := a.Keys.Get("k1")
	ka.Note = "note-A"
	_ = a.Keys.Put(ka)
	kb, _ := b.Keys.Get("k1")
	kb.Generation = 2
	kb.Recipient = "age1rot333333333333333333333333333333333333333"
	kb.PrivSealed = "sealed-2"
	_ = b.Keys.Put(kb)

	// Converge, then replay again.
	syncKeys(t, a, b)
	syncKeys(t, b, a)
	ga1, _ := a.Keys.Get("k1")
	before := fingerprintsOf(ga1)
	syncKeys(t, a, b)
	syncKeys(t, b, a)
	ga2, _ := a.Keys.Get("k1")
	after := fingerprintsOf(ga2)
	for g := range before {
		if before[g] != after[g] {
			t.Fatalf("re-apply changed group %q: %q -> %q", g, before[g], after[g])
		}
	}
	// Both nodes agree on every field group.
	gb, _ := b.Keys.Get("k1")
	fa, fb := fingerprintsOf(ga2), fingerprintsOf(gb)
	for g := range fa {
		if fa[g] != fb[g] {
			t.Fatalf("nodes diverge on group %q: A=%q B=%q", g, fa[g], fb[g])
		}
	}
}

// TestLegacyRecordNoVVMergesByLWW is scenario (f): a record with NO per-field version
// vectors (a pre-upgrade record) merges by whole-record last-writer-wins and never
// spuriously surfaces a conflict.
func TestLegacyRecordNoVVMergesByLWW(t *testing.T) {
	a, _ := twoNodes(t)
	// A legacy local record: placed directly (no VV stamped), baseline seeded, as if
	// loaded from a pre-upgrade file.
	local := baseKey("k1")
	local.Note = "old"
	local.M.Updated = hlc.Timestamp{Wall: 1000, Node: "A"}
	a.Keys.mu.Lock()
	a.Keys.items["k1"] = local
	_ = a.Keys.save()
	a.Keys.snapshotSaved(local)
	a.Keys.mu.Unlock()
	if local.M.FieldVV != nil {
		t.Fatal("legacy record should have no field_vv")
	}

	// A newer legacy remote record (also no VV), differing note.
	remote := baseKey("k1")
	remote.Note = "new"
	remote.M.Updated = hlc.Timestamp{Wall: 2000, Node: "B"}
	remote.M.Origin = "B"

	applied, conflict, err := a.Keys.ApplyRemote(remote)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("newer legacy record should apply")
	}
	if conflict {
		t.Fatal("legacy records must not surface a per-field conflict")
	}
	got, _ := a.Keys.Get("k1")
	if got.Note != "new" {
		t.Fatalf("legacy LWW should adopt the newer note, got %q", got.Note)
	}
	if n := len(a.FieldConflicts.List()); n != 0 {
		t.Fatalf("legacy merge must not create a field conflict, got %d", n)
	}
}
