package keysvc

import (
	"testing"

	"sopshq/internal/model"
	"sopshq/internal/store"
)

// putConflictKey stores a key with an explicit UUID (so survivor ordering is deterministic).
func putConflictKey(t *testing.T, st *store.Store, id, rec, priv, note string) *model.Key {
	t.Helper()
	k := &model.Key{
		M:          model.Meta{UUID: id},
		Name:       "key-" + id,
		Type:       model.KeyShared,
		Recipient:  rec,
		PrivSealed: priv,
		Note:       note,
		Status:     model.KeyActive,
	}
	if err := st.Keys.Put(k); err != nil {
		t.Fatalf("put key %s: %v", id, err)
	}
	return k
}

// groupsByEntity indexes detected conflict groups by entity type.
func groupsByEntity(gs []ConflictGroup) map[string][]ConflictGroup {
	out := map[string][]ConflictGroup{}
	for _, g := range gs {
		out[g.EntityType] = append(out[g.EntityType], g)
	}
	return out
}

// TestDetectKeyConflictNotAutoMerged: two keys share a public key but hold DIFFERENT
// sealed private halves. Detection surfaces exactly one "key" conflict group naming the
// differing field, and the lossless reconcile pass leaves BOTH records intact.
func TestDetectKeyConflictNotAutoMerged(t *testing.T) {
	svc, st := buildNode(t, "N")
	putConflictKey(t, st, "k1", "age1same", "SEALED-A", "")
	putConflictKey(t, st, "k2", "age1same", "SEALED-B", "")

	groups := svc.DetectConflicts()
	byE := groupsByEntity(groups)
	if len(byE[ConflictKey]) != 1 {
		t.Fatalf("want exactly 1 key conflict group, got %d (all: %d)", len(byE[ConflictKey]), len(groups))
	}
	g := byE[ConflictKey][0]
	if len(g.Records) != 2 {
		t.Fatalf("want 2 records in the group, got %d", len(g.Records))
	}
	if !g.KeepBothOK {
		t.Fatal("keys should allow keep-both")
	}
	hasPriv := false
	for _, f := range g.Fields {
		if f.Key == "priv" {
			hasPriv = true
			if !f.Secret {
				t.Fatal("private-key field must be marked secret (never shows its value)")
			}
		}
	}
	if !hasPriv {
		t.Fatalf("expected the differing 'priv' field to be offered; got %+v", g.Fields)
	}

	// The lossless pass must NOT merge them away.
	svc.ReconcileCluster("system")
	if n := len(st.Keys.List()); n != 2 {
		t.Fatalf("a differing-field duplicate must be left intact, not auto-merged; keys=%d", n)
	}
	if svc.ConflictCount() != 1 {
		t.Fatalf("conflict count should still be 1 after reconcile; got %d", svc.ConflictCount())
	}
}

// TestResolveMergeKeysUnionsAndRepoints: merging the group applies the operator's picked
// private half, folds a field only the loser set (lossless), re-points the loser's
// assignment onto the survivor, and tombstones the loser - losing nothing unshown.
func TestResolveMergeKeysUnionsAndRepoints(t *testing.T) {
	svc, st := buildNode(t, "N")
	putConflictKey(t, st, "k1", "age1same", "SEALED-A", "")     // survivor (smallest UUID), no note
	putConflictKey(t, st, "k2", "age1same", "SEALED-B", "keep") // loser: differing priv + a note only it has

	// An assignment references the loser; it must move onto the survivor.
	asg := &model.Assignment{M: model.Meta{UUID: "asg1"}, KeyID: "k2", MachineID: "m", OSUserID: "u"}
	if err := st.Assignments.Put(asg); err != nil {
		t.Fatalf("assignment: %v", err)
	}

	// Operator picks the loser's private half as the winner.
	if err := svc.ResolveMerge(ConflictKey, []string{"k1", "k2"}, map[string]string{"priv": "k2"}, "tester"); err != nil {
		t.Fatalf("ResolveMerge: %v", err)
	}

	// Loser tombstoned, survivor kept.
	if _, err := st.Keys.Get("k2"); err == nil {
		t.Fatal("loser k2 must be tombstoned after merge")
	}
	sv, err := st.Keys.Get("k1")
	if err != nil {
		t.Fatalf("survivor k1 must remain: %v", err)
	}
	if sv.PrivSealed != "SEALED-B" {
		t.Fatalf("picked private half must win; got %q", sv.PrivSealed)
	}
	if sv.Note != "keep" {
		t.Fatalf("a field only the loser set must fold in losslessly; note=%q", sv.Note)
	}
	// The assignment now points at the survivor.
	moved, err := st.Assignments.Get("asg1")
	if err != nil {
		t.Fatalf("assignment must survive: %v", err)
	}
	if moved.KeyID != "k1" {
		t.Fatalf("assignment must re-point to the survivor; KeyID=%q", moved.KeyID)
	}
	if svc.ConflictCount() != 0 {
		t.Fatalf("conflict must be gone after merge; count=%d", svc.ConflictCount())
	}
}

// TestKeepBothStopsFlaggingAndConverges: keep-both writes a replicated marker so the
// group stops being surfaced, and a second node that receives the marker (and the same
// records) also stops surfacing it - convergence with no deletion.
func TestKeepBothStopsFlaggingAndConverges(t *testing.T) {
	svcA, stA := buildNode(t, "A")
	svcB, stB := buildNode(t, "B")
	putConflictKey(t, stA, "k1", "age1same", "SEALED-A", "")
	putConflictKey(t, stA, "k2", "age1same", "SEALED-B", "")

	// Replicate the two keys to B; both nodes see the same conflict.
	replicate(t, stA, stB)
	if svcA.ConflictCount() != 1 || svcB.ConflictCount() != 1 {
		t.Fatalf("both nodes should see the conflict; A=%d B=%d", svcA.ConflictCount(), svcB.ConflictCount())
	}

	// A keeps both; the marker must suppress the group on A immediately.
	if err := svcA.KeepBothDistinct(ConflictKey, []string{"k1", "k2"}, "tester"); err != nil {
		t.Fatalf("KeepBothDistinct: %v", err)
	}
	if svcA.ConflictCount() != 0 {
		t.Fatalf("A should stop flagging after keep-both; count=%d", svcA.ConflictCount())
	}
	// Nothing was deleted.
	if n := len(stA.Keys.List()); n != 2 {
		t.Fatalf("keep-both must delete nothing; keys=%d", n)
	}

	// The decision converges: replicate the marker to B and it stops flagging too.
	replicate(t, stA, stB)
	if svcB.ConflictCount() != 0 {
		t.Fatalf("B should converge and stop flagging after receiving the marker; count=%d", svcB.ConflictCount())
	}
}

// TestBackupSettingsMergeOnly: two backup-settings records for ONE machine that differ
// are surfaced as a merge-only conflict (keep-both is invalid and refused).
func TestBackupSettingsMergeOnly(t *testing.T) {
	svc, st := buildNode(t, "N")
	b1 := &model.BackupSettings{M: model.Meta{UUID: "b1"}, MachineID: "m1", DailyAt: "03:00"}
	b2 := &model.BackupSettings{M: model.Meta{UUID: "b2"}, MachineID: "m1", DailyAt: "04:00"}
	if err := st.BackupSettingsColl.Put(b1); err != nil {
		t.Fatalf("b1: %v", err)
	}
	if err := st.BackupSettingsColl.Put(b2); err != nil {
		t.Fatalf("b2: %v", err)
	}

	byE := groupsByEntity(svc.DetectConflicts())
	if len(byE[ConflictBackup]) != 1 {
		t.Fatalf("want 1 backup conflict group; got %d", len(byE[ConflictBackup]))
	}
	if byE[ConflictBackup][0].KeepBothOK {
		t.Fatal("backup settings must NOT offer keep-both (one record per machine)")
	}
	if err := svc.KeepBothDistinct(ConflictBackup, []string{"b1", "b2"}, "tester"); err != ErrKeepBothInvalid {
		t.Fatalf("keep-both on backup settings must be refused; got %v", err)
	}
}

// TestMergeLocalMachineUpdatesLocalID: when a machine merge absorbs THIS node's own
// record, the reconcile pass follows the redirect and reports the new local machine id,
// so the caller can persist cfg.LocalMachineID.
func TestMergeLocalMachineUpdatesLocalID(t *testing.T) {
	svc, st := buildNode(t, "N")
	// This node's own canonical record has the LARGER UUID, so the merge survivor is the
	// other canonical record and this node's identity is the one absorbed.
	local := &model.Machine{M: model.Meta{UUID: "m-self"}, Name: "nodeX", OS: model.OSLinux, Canonical: true, TailscaleHost: "100.0.0.9"}
	if err := st.Machines.Put(local); err != nil {
		t.Fatalf("local machine: %v", err)
	}
	svc.SetLocalMachine("m-self")
	other := &model.Machine{M: model.Meta{UUID: "m-aaa"}, Name: "nodeX", OS: model.OSLinux, Canonical: true, TailscaleHost: "100.0.0.1"}
	if err := st.Machines.Put(other); err != nil {
		t.Fatalf("other machine: %v", err)
	}

	// A differing advertised address makes this a real conflict the pass leaves intact.
	byE := groupsByEntity(svc.DetectConflicts())
	if len(byE[ConflictMachine]) != 1 {
		t.Fatalf("want 1 machine conflict group; got %d", len(byE[ConflictMachine]))
	}
	if byE[ConflictMachine][0].SurvivorID != "m-aaa" {
		t.Fatalf("survivor should be the smallest-UUID canonical; got %q", byE[ConflictMachine][0].SurvivorID)
	}

	if err := svc.ResolveMerge(ConflictMachine, []string{"m-self", "m-aaa"}, map[string]string{"host": "m-aaa"}, "tester"); err != nil {
		t.Fatalf("ResolveMerge machine: %v", err)
	}
	res := svc.ReconcileCluster("system")
	if !res.LocalChanged || res.LocalMachineID != "m-aaa" {
		t.Fatalf("merging this node's own record must move the local id to the survivor; changed=%v id=%q", res.LocalChanged, res.LocalMachineID)
	}
	if _, err := st.Machines.Get("m-self"); err == nil {
		t.Fatal("this node's absorbed record must be tombstoned")
	}
}
