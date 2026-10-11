package keysvc

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"sopshq/internal/keys"
	"sopshq/internal/model"
	"sopshq/internal/place"
	"sopshq/internal/store"
)

// TestDiscoverSkipsOversizedKeystore proves the scan tolerates a KeyBase pointed at a
// huge keys.txt: the read cap makes it skip that user (nothing surfaced) rather than
// load the file whole or crash. It needs no age-keygen (the read is refused first).
func TestDiscoverSkipsOversizedKeystore(t *testing.T) {
	svc, st, localID := build(t)
	keyBase := t.TempDir()
	// 2 MiB, comfortably over the 1 MiB key-store cap.
	if err := os.WriteFile(place.KeyFile(keyBase), bytes.Repeat([]byte("x"), 2<<20), 0o600); err != nil {
		t.Fatalf("plant huge key file: %v", err)
	}
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: keyBase}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	if got := svc.DiscoverImportableKeys(); len(got) != 0 {
		t.Fatalf("oversized keystore must be skipped, got %+v", got)
	}
}

// TestDiscoverImportableSurfacesOnDiskKey is bug 2: an OS user whose keystore holds a
// keys.txt not yet in the database must be surfaced as importable, and the scan must
// write NOTHING (no placement, on-disk file untouched).
func TestDiscoverImportableSurfacesOnDiskKey(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, st, localID := build(t)

	// A placer that fails the test if any placement happens during the read-only scan.
	svc.SetPlacer(func(place.Opts) error {
		t.Fatal("discovery scan must never place/write")
		return nil
	})

	keyBase := t.TempDir()
	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := os.WriteFile(place.KeyFile(keyBase), []byte(kp.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant key: %v", err)
	}
	before, _ := os.ReadFile(place.KeyFile(keyBase))
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "alice", KeyBase: keyBase}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}

	found := svc.DiscoverImportableKeys()
	if len(found) != 1 {
		t.Fatalf("expected 1 keystore surfaced, got %d", len(found))
	}
	if found[0].OSUserID != osu.M.UUID || len(found[0].Importable) != 1 || found[0].Importable[0] != kp.Recipient {
		t.Fatalf("unexpected finding: %+v", found[0])
	}
	if len(found[0].PubOnly) != 0 {
		t.Fatalf("no keys.pub planted, PubOnly should be empty: %+v", found[0].PubOnly)
	}
	// Read-only: the on-disk key must be byte-identical, and nothing recorded.
	if after, _ := os.ReadFile(place.KeyFile(keyBase)); string(after) != string(before) {
		t.Fatal("scan modified the on-disk keys.txt")
	}
	if len(st.Keys.List()) != 0 || len(st.Assignments.List()) != 0 {
		t.Fatalf("scan must record nothing; keys=%d asg=%d", len(st.Keys.List()), len(st.Assignments.List()))
	}

	// Clicking Import (the real adopt path) creates exactly one Key + assignment,
	// after which the key is no longer importable.
	if _, count, err := svc.AdoptExistingKeyForOSUser(osu.M.UUID, "tester"); err != nil || count != 1 {
		t.Fatalf("import (adopt): count=%d err=%v", count, err)
	}
	if len(st.Keys.List()) != 1 || len(st.Assignments.List()) != 1 {
		t.Fatalf("import must create exactly one key + assignment; keys=%d asg=%d", len(st.Keys.List()), len(st.Assignments.List()))
	}
	if got := svc.DiscoverImportableKeys(); len(got) != 0 {
		t.Fatalf("after import the key must not be importable; got %+v", got)
	}
}

// TestDiscoverImportableDedupsKnownKey is the dedup guarantee: a key whose public key
// is ALREADY a Key in the database is never surfaced as importable, even when it sits
// on a second user's keystore that has no assignment of its own yet.
func TestDiscoverImportableDedupsKnownKey(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, st, localID := build(t)

	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// The key is already in custody in the database (public key known).
	k := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "known", Type: model.KeyShared, Status: model.KeyActive, Recipient: kp.Recipient}
	if err := st.Keys.Put(k); err != nil {
		t.Fatalf("key: %v", err)
	}
	// A user whose keystore holds THAT SAME key on disk, with no assignment of its own.
	keyBase := t.TempDir()
	if err := os.WriteFile(place.KeyFile(keyBase), []byte(kp.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant key: %v", err)
	}
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "bob", KeyBase: keyBase}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}

	if got := svc.DiscoverImportableKeys(); len(got) != 0 {
		t.Fatalf("a key already in the database must not be importable; got %+v", got)
	}
}

// TestDiscoverPubOnlyNotImportable: a keystore that has only keys.pub (a public key,
// no private) is surfaced as PubOnly (awareness) and never as importable - adopting
// needs the private half to seal.
func TestDiscoverPubOnlyNotImportable(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, st, localID := build(t)

	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	keyBase := t.TempDir()
	if err := os.WriteFile(place.PubFile(keyBase), []byte(kp.Recipient+"\n"), 0o644); err != nil {
		t.Fatalf("plant pub: %v", err)
	}
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "svc", KeyBase: keyBase}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}

	found := svc.DiscoverImportableKeys()
	if len(found) != 1 || len(found[0].Importable) != 0 || len(found[0].PubOnly) != 1 || found[0].PubOnly[0] != kp.Recipient {
		t.Fatalf("public-only keystore should surface as PubOnly, not importable: %+v", found)
	}
}

// TestDriftLocalFreshAfterProjectDelete is bug 1: local drift is computed from the
// LIVE database, so a project's ".sops.yaml recipients differ" entry is GONE the next
// time drift is computed after the project is deleted - no manual Sync needed.
func TestDriftLocalFreshAfterProjectDelete(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, st, localID := build(t)

	projDir := t.TempDir()
	keyBase := t.TempDir()
	proj := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "webshop", Paths: []model.ProjectPath{{MachineID: localID, Path: projDir}}}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: keyBase}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	key := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "app-key", Type: model.KeyShared, Status: model.KeyActive}
	if err := st.Keys.Put(key); err != nil {
		t.Fatalf("key: %v", err)
	}
	if err := svc.Generate(key.M.UUID, "tester"); err != nil {
		t.Fatalf("generate: %v", err)
	}
	asg := &model.Assignment{M: model.Meta{UUID: store.NewID()}, KeyID: key.M.UUID, ProjectID: proj.M.UUID, MachineID: localID, OSUserID: osu.M.UUID}
	if err := st.Assignments.Put(asg); err != nil {
		t.Fatalf("assignment: %v", err)
	}
	// A .sops.yaml on disk with the WRONG public key -> "recipients differ from desired".
	if err := os.WriteFile(projDir+string(os.PathSeparator)+".sops.yaml", []byte("creation_rules:\n  - age: age1wrongwrongwrong\n"), 0o600); err != nil {
		t.Fatalf("write sops.yaml: %v", err)
	}

	if !hasSopsDrift(t, svc, "webshop") {
		t.Fatal("expected a .sops.yaml drift for the project before delete")
	}

	// Delete the project. Recomputing drift (no Sync) must no longer list it.
	if err := st.Projects.Delete(proj.M.UUID); err != nil {
		t.Fatalf("delete project: %v", err)
	}
	if hasSopsDrift(t, svc, "webshop") {
		t.Fatal("stale .sops.yaml drift persisted after the project was deleted")
	}
}

// hasSopsDrift reports whether DriftLocal currently lists a .sops.yaml discrepancy for
// the named project.
func hasSopsDrift(t *testing.T, svc *Service, project string) bool {
	t.Helper()
	items, err := svc.DriftLocal()
	if err != nil {
		t.Fatalf("DriftLocal: %v", err)
	}
	for _, it := range items {
		if it.Kind == "sops.yaml" && it.Target == project {
			return true
		}
	}
	return false
}
