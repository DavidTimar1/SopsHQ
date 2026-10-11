package keysvc

import (
	"testing"

	"sopshq/internal/model"
	"sopshq/internal/store"
)

// TestMergedKeyReferenceRepointsNotLost covers keys: node A merges k1<-k2, while
// node B independently creates an assignment naming k2 BEFORE syncing. After A's merge
// replicates to B and B reconciles, B's assignment must end up pointing at the survivor
// (k1) - the grant preserved, never dangling, never pruned.
func TestMergedKeyReferenceRepointsNotLost(t *testing.T) {
	svcA, stA := buildNode(t, "A")
	svcB, stB := buildNode(t, "B")

	// Both nodes hold the same two conflicting keys (same recipient, different sealed half).
	for _, st := range []*store.Store{stA, stB} {
		putConflictKey(t, st, "k1", "age1same", "SEALED-A", "")
		putConflictKey(t, st, "k2", "age1same", "SEALED-B", "")
	}
	// B also needs the account the assignment references so the grant is "live" (not
	// pruned for a missing OS user).
	osu := &model.OSUser{M: model.Meta{UUID: "ou"}, MachineID: "mB", Username: "dev", KeyBase: "/k"}
	if err := stB.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}

	// A resolves by merging k1 <- k2 (picking k2's sealed half).
	if err := svcA.ResolveMerge(ConflictKey, []string{"k1", "k2"}, map[string]string{"priv": "k2"}, "tester"); err != nil {
		t.Fatalf("A ResolveMerge: %v", err)
	}

	// B, unaware, creates an assignment against k2 (still live on B).
	asgB := &model.Assignment{M: model.Meta{UUID: "asgB"}, KeyID: "k2", MachineID: "mB", OSUserID: "ou"}
	if err := stB.Assignments.Put(asgB); err != nil {
		t.Fatalf("asgB: %v", err)
	}

	// A's merge (survivor update + k2 tombstone-with-MergedInto) replicates to B; B reconciles.
	replicate(t, stA, stB)
	svcB.ReconcileCluster("system")

	// The grant survives, re-pointed onto the survivor - not dangling, not pruned.
	got, err := stB.Assignments.Get("asgB")
	if err != nil {
		t.Fatalf("the concurrent grant must survive on B, not be pruned: %v", err)
	}
	if got.KeyID != "k1" {
		t.Fatalf("the grant must re-point to the survivor k1; KeyID=%q", got.KeyID)
	}
}

// TestMergedOSUserReferenceRepointsNotLost covers OS users and global-set readers:
// a concurrent assignment AND a global-set membership naming a merged-away account both
// move onto the survivor, never dropped.
func TestMergedOSUserReferenceRepointsNotLost(t *testing.T) {
	svcA, stA := buildNode(t, "A")
	svcB, stB := buildNode(t, "B")

	// Same account on the same machine, two records with a conflicting keystore base.
	for _, st := range []*store.Store{stA, stB} {
		if err := st.OSUsers.Put(&model.OSUser{M: model.Meta{UUID: "u1"}, MachineID: "m1", Username: "dev", KeyBase: "/a"}); err != nil {
			t.Fatalf("u1: %v", err)
		}
		if err := st.OSUsers.Put(&model.OSUser{M: model.Meta{UUID: "u2"}, MachineID: "m1", Username: "dev", KeyBase: "/b"}); err != nil {
			t.Fatalf("u2: %v", err)
		}
	}

	// A merges u1 <- u2 (keeping u2's keystore base).
	if err := svcA.ResolveMerge(ConflictOSUser, []string{"u1", "u2"}, map[string]string{"keybase": "u2"}, "tester"); err != nil {
		t.Fatalf("A ResolveMerge: %v", err)
	}

	// B, unaware, creates an assignment and a global-set membership naming u2.
	if err := stB.Assignments.Put(&model.Assignment{M: model.Meta{UUID: "asgB"}, KeyID: "k", MachineID: "m1", OSUserID: "u2"}); err != nil {
		t.Fatalf("asgB: %v", err)
	}
	gs := &model.GlobalSet{M: model.Meta{UUID: "gs"}, Name: "shared", MachineID: "m1", RecipientUserIDs: []string{"u2"}}
	if err := stB.GlobalSets.Put(gs); err != nil {
		t.Fatalf("gs: %v", err)
	}

	replicate(t, stA, stB)
	svcB.ReconcileCluster("system")

	got, err := stB.Assignments.Get("asgB")
	if err != nil {
		t.Fatalf("assignment must survive: %v", err)
	}
	if got.OSUserID != "u1" {
		t.Fatalf("assignment must re-point to survivor u1; OSUserID=%q", got.OSUserID)
	}
	gsAfter, err := stB.GlobalSets.Get("gs")
	if err != nil {
		t.Fatalf("global set must survive: %v", err)
	}
	found := false
	for _, id := range gsAfter.RecipientUserIDs {
		if id == "u1" {
			found = true
		}
		if id == "u2" {
			t.Fatalf("membership must not still name the merged-away account u2: %v", gsAfter.RecipientUserIDs)
		}
	}
	if !found {
		t.Fatalf("the global-set membership must move to the survivor u1, never dropped; got %v", gsAfter.RecipientUserIDs)
	}
}

// TestMergedProjectReferenceRepointsNotLost covers projects: a concurrent
// assignment naming a merged-away project moves onto the survivor.
func TestMergedProjectReferenceRepointsNotLost(t *testing.T) {
	svcA, stA := buildNode(t, "A")
	svcB, stB := buildNode(t, "B")

	// Two same-named projects that disagree on the path for the same machine.
	for _, st := range []*store.Store{stA, stB} {
		if err := st.Projects.Put(&model.Project{M: model.Meta{UUID: "p1"}, Name: "app", Paths: []model.ProjectPath{{MachineID: "m1", Path: "/a"}}}); err != nil {
			t.Fatalf("p1: %v", err)
		}
		if err := st.Projects.Put(&model.Project{M: model.Meta{UUID: "p2"}, Name: "app", Paths: []model.ProjectPath{{MachineID: "m1", Path: "/b"}}}); err != nil {
			t.Fatalf("p2: %v", err)
		}
	}
	// B needs the project's parent OS user so the grant is not pruned for a missing user.
	if err := stB.OSUsers.Put(&model.OSUser{M: model.Meta{UUID: "ou"}, MachineID: "m1", Username: "dev", KeyBase: "/k"}); err != nil {
		t.Fatalf("osuser: %v", err)
	}

	if err := svcA.ResolveMerge(ConflictProject, []string{"p1", "p2"}, map[string]string{"path_m1": "p1"}, "tester"); err != nil {
		t.Fatalf("A ResolveMerge: %v", err)
	}
	if err := stB.Assignments.Put(&model.Assignment{M: model.Meta{UUID: "asgB"}, KeyID: "k", ProjectID: "p2", MachineID: "m1", OSUserID: "ou"}); err != nil {
		t.Fatalf("asgB: %v", err)
	}

	replicate(t, stA, stB)
	svcB.ReconcileCluster("system")

	got, err := stB.Assignments.Get("asgB")
	if err != nil {
		t.Fatalf("assignment must survive, not be pruned: %v", err)
	}
	if got.ProjectID != "p1" {
		t.Fatalf("assignment must re-point to survivor p1; ProjectID=%q", got.ProjectID)
	}
}
