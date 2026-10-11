package keysvc

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"sopshq/internal/keys"
	"sopshq/internal/model"
	"sopshq/internal/place"
	"sopshq/internal/store"
)

// TestWireReuseAdoptedKeyNoDuplicate is the reported bug: after a user's keys.txt is
// adopted (creating "adopted-<user>"), wiring a project with REUSE against that same
// keystore must NOT mint a third "project-<name>" Key with the same public key. The
// project must reuse the already-in-custody adopted key. Before the dedup fix this
// created a duplicate Key; after it there is exactly one.
func TestWireReuseAdoptedKeyNoDuplicate(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)
	keyBase := t.TempDir()
	projDir := t.TempDir()

	// Plant an on-disk keys.txt and adopt it for the OS user -> "adopted-alice".
	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := os.WriteFile(place.KeyFile(keyBase), []byte(kp.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant key: %v", err)
	}
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "alice", KeyBase: keyBase}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	name, count, err := svc.AdoptExistingKeyForOSUser(osu.M.UUID, "tester")
	if err != nil || count != 1 || name != "adopted-alice" {
		t.Fatalf("adopt: name=%q count=%d err=%v", name, count, err)
	}
	adopted := st.Keys.List()[0]

	// A project whose local folder uses the SAME keystore (the user's key base).
	proj := &model.Project{
		M:     model.Meta{UUID: store.NewID()},
		Name:  "webshop",
		Paths: []model.ProjectPath{{MachineID: localID, Path: projDir}},
	}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}

	// Wire with REUSE (the operator picks Reuse on the existing keys.txt).
	if err := svc.WireProjectResolved(proj.M.UUID, WiringChoices{Key: DecideReuse}, "tester"); err != nil {
		t.Fatalf("WireProjectResolved reuse: %v", err)
	}

	// No third Key: the project reuses the adopted key (no "project-webshop" record).
	if n := len(st.Keys.List()); n != 1 {
		var names []string
		for _, k := range st.Keys.List() {
			names = append(names, k.Name)
		}
		t.Fatalf("wire+reuse created a duplicate Key; want 1, got %d (%v)", n, names)
	}

	// The project's assignment points at the adopted key.
	var projKeyID string
	projAsg := 0
	for _, a := range st.Assignments.List() {
		if a.ProjectID == proj.M.UUID {
			projKeyID = a.KeyID
			projAsg++
		}
	}
	if projAsg != 1 {
		t.Fatalf("expected exactly 1 project assignment, got %d", projAsg)
	}
	if projKeyID != adopted.M.UUID {
		t.Fatalf("project assignment points at %q, want the adopted key %q", projKeyID, adopted.M.UUID)
	}
}

// TestWireReuseMultiIdentityKeepsBothReaders locks in the multi-identity case: a
// keys.txt holding TWO identities is adopted (adopted-<user> + adopted-<user>-2), then
// a project wired with REUSE against that keystore reuses the FIRST adopted key (no new
// "project-<name>" record) while BOTH on-disk identities remain usable - and a later
// Apply, which rebuilds the key store from the vault, keeps both.
func TestWireReuseMultiIdentityKeepsBothReaders(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, st, localID := build(t)
	keyBase := t.TempDir()
	projDir := t.TempDir()

	kp1, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate kp1: %v", err)
	}
	kp2, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate kp2: %v", err)
	}
	if err := os.WriteFile(place.KeyFile(keyBase), []byte(kp1.Private+"\n"+kp2.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant keys: %v", err)
	}
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "alice", KeyBase: keyBase}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	if _, count, err := svc.AdoptExistingKeyForOSUser(osu.M.UUID, "tester"); err != nil || count != 2 {
		t.Fatalf("adopt both identities: count=%d err=%v", count, err)
	}

	proj := &model.Project{
		M:     model.Meta{UUID: store.NewID()},
		Name:  "webshop",
		Paths: []model.ProjectPath{{MachineID: localID, Path: projDir}},
	}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}
	if err := svc.WireProjectResolved(proj.M.UUID, WiringChoices{Key: DecideReuse}, "tester"); err != nil {
		t.Fatalf("WireProjectResolved reuse: %v", err)
	}

	// No new key: still the two adopted identities, none named "project-*".
	if n := len(st.Keys.List()); n != 2 {
		var names []string
		for _, k := range st.Keys.List() {
			names = append(names, k.Name)
		}
		t.Fatalf("wire+reuse minted a duplicate key; want 2, got %d (%v)", n, names)
	}
	// The project links to the FIRST adopted identity (kp1), an existing record.
	var projKeyRecipient string
	for _, a := range st.Assignments.List() {
		if a.ProjectID == proj.M.UUID {
			if k, err := st.Keys.Get(a.KeyID); err == nil {
				projKeyRecipient = k.Recipient
			}
		}
	}
	if projKeyRecipient != kp1.Recipient {
		t.Fatalf("project reuse should bind to the first adopted key (%s), got %s", kp1.Recipient, projKeyRecipient)
	}

	// A later Apply rebuilds keys.txt from the vault; BOTH identities must survive.
	if _, err := svc.ApplyLocal("tester", false); err != nil {
		t.Fatalf("ApplyLocal: %v", err)
	}
	after, _ := os.ReadFile(place.KeyFile(keyBase))
	if !strings.Contains(string(after), kp1.Private) || !strings.Contains(string(after), kp2.Private) {
		t.Fatalf("reuse+apply dropped an on-disk identity:\n%s", after)
	}
}

// TestHasAssignmentIdempotency verifies the four-part idempotency predicate every
// assignment-creating path shares: an existing key+project+machine+user grant is
// detected, while a different machine (or project) is treated as a distinct grant.
func TestHasAssignmentIdempotency(t *testing.T) {
	svc, st, localID := build(t)
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: t.TempDir()}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	k := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "k", Type: model.KeyShared, Recipient: "age1abc"}
	if err := st.Keys.Put(k); err != nil {
		t.Fatalf("key: %v", err)
	}
	proj := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "p"}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}

	if svc.HasAssignment(k.M.UUID, proj.M.UUID, localID, osu.M.UUID) {
		t.Fatal("no assignment exists yet")
	}
	a := &model.Assignment{M: model.Meta{UUID: store.NewID()}, KeyID: k.M.UUID, ProjectID: proj.M.UUID, MachineID: localID, OSUserID: osu.M.UUID}
	if err := st.Assignments.Put(a); err != nil {
		t.Fatalf("assignment: %v", err)
	}
	if !svc.HasAssignment(k.M.UUID, proj.M.UUID, localID, osu.M.UUID) {
		t.Fatal("existing assignment must be detected")
	}
	if svc.HasAssignment(k.M.UUID, proj.M.UUID, "other-machine", osu.M.UUID) {
		t.Fatal("a different machine is a distinct grant, not a duplicate")
	}
	if svc.HasAssignment(k.M.UUID, "other-project", localID, osu.M.UUID) {
		t.Fatal("a different project is a distinct grant, not a duplicate")
	}
}

// TestKeyByRecipientDedup verifies the shared dedup helper: it finds the in-custody
// Key with a matching public key and ignores an empty recipient.
func TestKeyByRecipientDedup(t *testing.T) {
	svc, st, _ := build(t)
	k := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "k", Type: model.KeyShared, Recipient: "age1match"}
	if err := st.Keys.Put(k); err != nil {
		t.Fatalf("key: %v", err)
	}
	got, ok := svc.keyByRecipient("age1match")
	if !ok || got.M.UUID != k.M.UUID {
		t.Fatalf("keyByRecipient should find the matching key; ok=%v got=%+v", ok, got)
	}
	if _, ok := svc.keyByRecipient("age1nope"); ok {
		t.Fatal("a non-matching recipient must not match")
	}
	if _, ok := svc.keyByRecipient(""); ok {
		t.Fatal("an empty recipient is not a real public key and must not match")
	}
}
