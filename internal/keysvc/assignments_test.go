package keysvc

import (
	"testing"

	"sopshq/internal/model"
	"sopshq/internal/store"
)

// riProject / riOSUser / riKey / riAssignment are terse record builders for
// the referential-integrity tests. They fail the test on a store error.
func riProject(t *testing.T, st *store.Store, name string) string {
	t.Helper()
	p := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: name}
	if err := st.Projects.Put(p); err != nil {
		t.Fatalf("project %s: %v", name, err)
	}
	return p.M.UUID
}

func riOSUser(t *testing.T, st *store.Store, machineID, name string) string {
	t.Helper()
	u := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: machineID, Username: name}
	if err := st.OSUsers.Put(u); err != nil {
		t.Fatalf("osuser %s: %v", name, err)
	}
	return u.M.UUID
}

func riKey(t *testing.T, st *store.Store, name string) string {
	t.Helper()
	k := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: name, Type: model.KeyShared, Recipient: "age1" + name}
	if err := st.Keys.Put(k); err != nil {
		t.Fatalf("key %s: %v", name, err)
	}
	return k.M.UUID
}

func riAssignment(t *testing.T, st *store.Store, keyID, projectID, machineID, osUserID string) string {
	t.Helper()
	a := &model.Assignment{M: model.Meta{UUID: store.NewID()}, KeyID: keyID, ProjectID: projectID, MachineID: machineID, OSUserID: osUserID}
	if err := st.Assignments.Put(a); err != nil {
		t.Fatalf("assignment: %v", err)
	}
	return a.M.UUID
}

// liveAssignmentIDs returns the set of still-live assignment UUIDs, so a test can
// assert exactly which ones survived a cascade or prune.
func liveAssignmentIDs(st *store.Store) map[string]bool {
	out := map[string]bool{}
	for _, a := range st.Assignments.List() {
		out[a.M.UUID] = true
	}
	return out
}

// TestLiveKeyAssignmentsCountsOnlyLive: the key-delete guard must count only
// assignments whose project AND user still exist. A dangling assignment (project
// or user already gone) must not count, so it never keeps the key stuck.
func TestLiveKeyAssignmentsCountsOnlyLive(t *testing.T) {
	svc, st, localID := build(t)
	proj := riProject(t, st, "app")
	user := riOSUser(t, st, localID, "dev")
	key := riKey(t, st, "shared")

	riAssignment(t, st, key, proj, localID, user)           // live: real project + user
	riAssignment(t, st, key, "gone-project", localID, user) // dangling: project missing
	riAssignment(t, st, key, proj, localID, "gone-user")    // dangling: user missing

	if n := svc.LiveKeyAssignments(key); n != 1 {
		t.Fatalf("only the fully-live assignment should count; want 1, got %d", n)
	}

	// Deleting the live project makes the first one dangle too, dropping the count
	// to zero (the key is then freely deletable - the operator's bug).
	if err := st.Projects.Delete(proj); err != nil {
		t.Fatalf("delete project: %v", err)
	}
	if n := svc.LiveKeyAssignments(key); n != 0 {
		t.Fatalf("after the project is deleted no assignment is live; want 0, got %d", n)
	}
}

// TestCascadeDeleteProjectScoping: deleting a project tombstones exactly its own
// assignments - never another project's, never a project-less user placement.
func TestCascadeDeleteProjectScoping(t *testing.T) {
	svc, st, localID := build(t)
	p1 := riProject(t, st, "one")
	p2 := riProject(t, st, "two")
	user := riOSUser(t, st, localID, "dev")
	key := riKey(t, st, "shared")

	a1 := riAssignment(t, st, key, p1, localID, user)     // this project - must go
	a2 := riAssignment(t, st, key, p2, localID, user)     // other project - must stay
	aPlace := riAssignment(t, st, key, "", localID, user) // project-less placement - must stay

	if err := st.Projects.Delete(p1); err != nil {
		t.Fatalf("delete p1: %v", err)
	}
	if n := svc.CascadeDeleteProjectAssignments(p1, "tester"); n != 1 {
		t.Fatalf("cascade should tombstone exactly 1 assignment; got %d", n)
	}
	live := liveAssignmentIDs(st)
	if live[a1] {
		t.Fatal("p1's assignment must be tombstoned")
	}
	if !live[a2] {
		t.Fatal("another project's assignment must be spared")
	}
	if !live[aPlace] {
		t.Fatal("a project-less user placement must be spared")
	}
	// The key, now used only by the deleted project, is free of live assignments.
	if n := svc.LiveKeyAssignments(key); n == 0 {
		t.Fatal("the placement + p2 assignment still make the key live")
	}
}

// TestCascadeDeleteOSUserScoping: deleting an OS user tombstones exactly its own
// assignments (project-scoped and project-less alike) and spares other users'.
func TestCascadeDeleteOSUserScoping(t *testing.T) {
	svc, st, localID := build(t)
	proj := riProject(t, st, "app")
	u1 := riOSUser(t, st, localID, "dev")
	u2 := riOSUser(t, st, localID, "ops")
	key := riKey(t, st, "shared")

	a1 := riAssignment(t, st, key, proj, localID, u1)     // u1, project-scoped - go
	a2 := riAssignment(t, st, key, "", localID, u1)       // u1, placement - go
	aOther := riAssignment(t, st, key, proj, localID, u2) // u2 - stay

	if err := st.OSUsers.Delete(u1); err != nil {
		t.Fatalf("delete u1: %v", err)
	}
	if n := svc.CascadeDeleteOSUserAssignments(u1, "tester"); n != 2 {
		t.Fatalf("cascade should tombstone both of u1's assignments; got %d", n)
	}
	live := liveAssignmentIDs(st)
	if live[a1] || live[a2] {
		t.Fatal("u1's assignments must be tombstoned")
	}
	if !live[aOther] {
		t.Fatal("another user's assignment must be spared")
	}
}

// TestPruneOrphanedAssignments: the self-heal pass tombstones assignments whose
// parent is PROVABLY gone (a tombstone is present) and leaves alone both a live
// project-less placement AND an assignment whose parent is merely not-yet-synced
// (unknown id, no tombstone) - pruning the latter would kill a valid grant during a
// partial sync. It is idempotent - a second pass finds nothing.
func TestPruneOrphanedAssignments(t *testing.T) {
	svc, st, localID := build(t)
	proj := riProject(t, st, "app")
	user := riOSUser(t, st, localID, "dev")
	key := riKey(t, st, "shared")

	aLive := riAssignment(t, st, key, proj, localID, user) // live project + user
	aPlace := riAssignment(t, st, key, "", localID, user)  // live project-less placement

	// A DELETED (tombstoned) project and user - provably gone, so their assignments prune.
	deadProj := riProject(t, st, "old")
	deadUser := riOSUser(t, st, localID, "gone")
	orphanProj := riAssignment(t, st, key, deadProj, localID, user)
	orphanUser := riAssignment(t, st, key, proj, localID, deadUser)
	if err := st.Projects.Delete(deadProj); err != nil {
		t.Fatalf("tombstone project: %v", err)
	}
	if err := st.OSUsers.Delete(deadUser); err != nil {
		t.Fatalf("tombstone user: %v", err)
	}

	// An assignment whose parent ids are UNKNOWN (never synced) must NOT be pruned: it
	// may be a valid grant that arrived before its records during a partial sync.
	unsynced := riAssignment(t, st, key, "not-synced-project", localID, user)

	if n := svc.PruneOrphanedAssignments("system"); n != 2 {
		t.Fatalf("prune should tombstone the 2 provably-orphaned assignments; got %d", n)
	}
	live := liveAssignmentIDs(st)
	if !live[aLive] || !live[aPlace] {
		t.Fatal("live and project-less-placement assignments must survive the prune")
	}
	if !live[unsynced] {
		t.Fatal("an assignment with a not-yet-synced parent must be kept, not pruned")
	}
	if live[orphanProj] || live[orphanUser] {
		t.Fatal("assignments whose parent is tombstoned must be pruned")
	}
	if n := svc.PruneOrphanedAssignments("system"); n != 0 {
		t.Fatalf("a second prune must be a no-op; got %d", n)
	}
}
