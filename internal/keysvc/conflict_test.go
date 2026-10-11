package keysvc

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sopshq/internal/keys"
	"sopshq/internal/model"
	"sopshq/internal/place"
	"sopshq/internal/store"
)

// keyByRec finds the in-custody Key with the given public key (test helper).
func keyByRec(t *testing.T, st *store.Store, rec string) *model.Key {
	t.Helper()
	for _, k := range st.Keys.List() {
		if k.Recipient == rec {
			return k
		}
	}
	t.Fatalf("no key in custody with recipient %s", rec)
	return nil
}

// projectAssignedRecipients returns the set of public keys assigned to a project.
func projectAssignedRecipients(st *store.Store, projectID string) map[string]bool {
	out := map[string]bool{}
	for _, a := range st.Assignments.List() {
		if a.ProjectID != projectID {
			continue
		}
		if k, err := st.Keys.Get(a.KeyID); err == nil && k.Recipient != "" {
			out[k.Recipient] = true
		}
	}
	return out
}

// sopsDriftFor returns the local ".sops.yaml" DriftItem for a project, if any.
func sopsDriftFor(t *testing.T, svc *Service, projectID string) (DriftItem, bool) {
	t.Helper()
	items, err := svc.DriftLocal()
	if err != nil {
		t.Fatalf("DriftLocal: %v", err)
	}
	for _, it := range items {
		if it.Kind == "sops.yaml" && it.ProjectID == projectID {
			return it, true
		}
	}
	return DriftItem{}, false
}

// TestReuseMatchesOnDiskIdentity is the reported bug (a): a keys.txt with TWO identities
// whose project folder's on-disk .sops.yaml uses IDENTITY-2. Reusing the project must
// assign it identity-2 (the public key the config already uses), not an arbitrary first
// identity, so DriftLocal shows NO drift after the reuse.
func TestReuseMatchesOnDiskIdentity(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)
	keyBase := t.TempDir()
	projDir := t.TempDir()

	kp1, _ := keys.Generate() // identity-1 (adopted-alice)
	kp2, _ := keys.Generate() // identity-2 (adopted-alice-2)
	if err := os.WriteFile(place.KeyFile(keyBase), []byte(kp1.Private+"\n"+kp2.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant keys: %v", err)
	}
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "alice", KeyBase: keyBase}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	// Alice has both identities in custody (as after pointing SopsHQ at his keystore).
	if _, count, err := svc.AdoptExistingKeyForOSUser(osu.M.UUID, "tester"); err != nil || count != 2 {
		t.Fatalf("adopt both: count=%d err=%v", count, err)
	}

	proj := &model.Project{
		M:     model.Meta{UUID: store.NewID()},
		Name:  "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: projDir}},
	}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}
	// The on-disk .sops.yaml uses IDENTITY-2 only; a secret is encrypted to it.
	if err := keys.WriteSopsYAML(projDir, []keys.Recipient{{Label: "two", Age: kp2.Recipient}}); err != nil {
		t.Fatalf("write .sops.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projDir, "secrets.yaml"), []byte("password: hunter2\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	if _, err := runSops(t, projDir, nil, "-e", "-i", "secrets.yaml"); err != nil {
		t.Fatalf("encrypt to identity-2: %v", err)
	}
	sopsBefore, _ := os.ReadFile(filepath.Join(projDir, ".sops.yaml"))

	// Re-add the project + reuse the keys.
	if err := svc.EnsureProjectWired(proj.M.UUID, "tester"); err != ErrWiringConflict {
		t.Fatalf("expected conflict (existing state), got %v", err)
	}
	if err := svc.WireProjectResolved(proj.M.UUID, WiringChoices{Key: DecideReuse}, "tester"); err != nil {
		t.Fatalf("WireProjectResolved reuse: %v", err)
	}

	// The project is assigned IDENTITY-2 (matches on disk), NOT identity-1.
	assigned := projectAssignedRecipients(st, proj.M.UUID)
	if !assigned[kp2.Recipient] {
		t.Fatalf("project must be assigned identity-2 (%s); got %v", kp2.Recipient, assigned)
	}
	if assigned[kp1.Recipient] {
		t.Fatalf("project must NOT be assigned identity-1; got %v", assigned)
	}
	// The reported bug: DriftLocal must be clean (no phantom "recipients differ").
	if it, ok := sopsDriftFor(t, svc, proj.M.UUID); ok {
		t.Fatalf("reuse must match on-disk so there is NO drift; got %q", it.Detail)
	}
	// Reuse-match never rewrites the on-disk .sops.yaml.
	if after, _ := os.ReadFile(filepath.Join(projDir, ".sops.yaml")); string(after) != string(sopsBefore) {
		t.Fatalf("reuse-match must not rewrite .sops.yaml\n got: %q\nwant: %q", after, sopsBefore)
	}
}

// TestReuseFreshFolderUnchanged is case (e): on a FRESH folder (no .sops.yaml) reuse
// keeps its original behavior - it adopts a SINGLE on-disk key even when the keystore
// holds several identities (there is no on-disk config to match).
func TestReuseFreshFolderUnchanged(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)
	keyBase := t.TempDir()
	projDir := t.TempDir()

	kp1, _ := keys.Generate()
	kp2, _ := keys.Generate()
	if err := os.WriteFile(place.KeyFile(keyBase), []byte(kp1.Private+"\n"+kp2.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant keys: %v", err)
	}
	proj, _ := wiredProject(t, svc, st, localID, projDir, keyBase)

	if err := svc.WireProjectResolved(proj.M.UUID, WiringChoices{Key: DecideReuse}, "tester"); err != nil {
		t.Fatalf("WireProjectResolved reuse (fresh folder): %v", err)
	}
	// A fresh folder has nothing to match, so exactly ONE key is assigned (the first).
	assigned := projectAssignedRecipients(st, proj.M.UUID)
	if len(assigned) != 1 || !assigned[kp1.Recipient] {
		t.Fatalf("fresh-folder reuse must adopt a single (first) identity; got %v", assigned)
	}
	if !svc.ProjectWiredLocally(proj.M.UUID) {
		t.Fatal("project should be wired after fresh-folder reuse")
	}
}

// TestDriftSameAccountMessage is case (b): a genuine same-account identity mismatch
// (desired uses adopted-alice, disk uses adopted-alice-2, both alice's) must read as an
// identity switch that names the account and says either decrypts - NOT "missing/extra".
func TestDriftSameAccountMessage(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, st, localID := build(t)
	keyBase := t.TempDir()
	projDir := t.TempDir()

	kp1, _ := keys.Generate()
	kp2, _ := keys.Generate()
	if err := os.WriteFile(place.KeyFile(keyBase), []byte(kp1.Private+"\n"+kp2.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant keys: %v", err)
	}
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "alice", KeyBase: keyBase}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	if _, count, err := svc.AdoptExistingKeyForOSUser(osu.M.UUID, "tester"); err != nil || count != 2 {
		t.Fatalf("adopt both: count=%d err=%v", count, err)
	}
	proj := &model.Project{
		M:     model.Meta{UUID: store.NewID()},
		Name:  "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: projDir}},
	}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}
	// Project desired = identity-1; on-disk config uses identity-2 (both alice's).
	k1 := keyByRec(t, st, kp1.Recipient)
	asg := &model.Assignment{M: model.Meta{UUID: store.NewID()}, KeyID: k1.M.UUID, ProjectID: proj.M.UUID, MachineID: localID, OSUserID: osu.M.UUID}
	if err := st.Assignments.Put(asg); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if err := keys.WriteSopsYAML(projDir, []keys.Recipient{{Label: "two", Age: kp2.Recipient}}); err != nil {
		t.Fatalf("write .sops.yaml: %v", err)
	}

	it, ok := sopsDriftFor(t, svc, proj.M.UUID)
	if !ok {
		t.Fatal("expected a sops.yaml drift item for the identity mismatch")
	}
	if !strings.Contains(it.Detail, "same account 'alice'") || !strings.Contains(it.Detail, "can decrypt either") {
		t.Fatalf("expected an account-aware message; got %q", it.Detail)
	}
	if strings.Contains(it.Detail, "missing") || strings.Contains(it.Detail, "does not include") {
		t.Fatalf("same-account swap must NOT read as missing/extra; got %q", it.Detail)
	}
}

// TestDriftDifferentAccountMissing is case (c): when the desired-but-absent key and the
// on-disk extra belong to DIFFERENT accounts, the precise "missing/extra" wording stays.
func TestDriftDifferentAccountMissing(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, st, localID := build(t)
	projDir := t.TempDir()

	kpAlice, _ := keys.Generate()
	kpBob, _ := keys.Generate()
	alice := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "alice", KeyBase: t.TempDir()}
	bob := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "bob", KeyBase: t.TempDir()}
	if err := st.OSUsers.Put(alice); err != nil {
		t.Fatalf("alice: %v", err)
	}
	if err := st.OSUsers.Put(bob); err != nil {
		t.Fatalf("bob: %v", err)
	}
	kA := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "alice-key", Type: model.KeyShared, Recipient: kpAlice.Recipient}
	kB := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "bob-key", Type: model.KeyShared, Recipient: kpBob.Recipient}
	if err := st.Keys.Put(kA); err != nil {
		t.Fatalf("kA: %v", err)
	}
	if err := st.Keys.Put(kB); err != nil {
		t.Fatalf("kB: %v", err)
	}
	proj := &model.Project{
		M:     model.Meta{UUID: store.NewID()},
		Name:  "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: projDir}},
	}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}
	// alice's key is the project's desired reader; bob's key is a user placement (so it
	// maps to bob's account) and is the on-disk extra.
	if err := st.Assignments.Put(&model.Assignment{M: model.Meta{UUID: store.NewID()}, KeyID: kA.M.UUID, ProjectID: proj.M.UUID, MachineID: localID, OSUserID: alice.M.UUID}); err != nil {
		t.Fatalf("assign alice: %v", err)
	}
	if err := st.Assignments.Put(&model.Assignment{M: model.Meta{UUID: store.NewID()}, KeyID: kB.M.UUID, MachineID: localID, OSUserID: bob.M.UUID}); err != nil {
		t.Fatalf("assign bob: %v", err)
	}
	if err := keys.WriteSopsYAML(projDir, []keys.Recipient{{Label: "bob", Age: kpBob.Recipient}}); err != nil {
		t.Fatalf("write .sops.yaml: %v", err)
	}

	it, ok := sopsDriftFor(t, svc, proj.M.UUID)
	if !ok {
		t.Fatal("expected a sops.yaml drift item for the different-account mismatch")
	}
	if strings.Contains(it.Detail, "same account") {
		t.Fatalf("different accounts must NOT read as same account; got %q", it.Detail)
	}
	if !strings.Contains(it.Detail, "missing") {
		t.Fatalf("a genuinely different absent account must read as missing; got %q", it.Detail)
	}
}

// TestMatchProjectToDiskClearsDriftWithoutReKey is case (d): "Match to the on-disk keys"
// makes the project's desired set equal what the config already uses, so drift clears
// with NO reader dropped and NO re-key of the secrets.
func TestMatchProjectToDiskClearsDriftWithoutReKey(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)
	keyBase := t.TempDir()
	projDir := t.TempDir()

	kp1, _ := keys.Generate()
	kp2, _ := keys.Generate()
	if err := os.WriteFile(place.KeyFile(keyBase), []byte(kp1.Private+"\n"+kp2.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant keys: %v", err)
	}
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "alice", KeyBase: keyBase}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	if _, count, err := svc.AdoptExistingKeyForOSUser(osu.M.UUID, "tester"); err != nil || count != 2 {
		t.Fatalf("adopt both: count=%d err=%v", count, err)
	}
	proj := &model.Project{
		M:     model.Meta{UUID: store.NewID()},
		Name:  "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: projDir}},
	}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}
	// Desired = identity-1; on-disk config + secret use identity-2.
	k1 := keyByRec(t, st, kp1.Recipient)
	if err := st.Assignments.Put(&model.Assignment{M: model.Meta{UUID: store.NewID()}, KeyID: k1.M.UUID, ProjectID: proj.M.UUID, MachineID: localID, OSUserID: osu.M.UUID}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if err := keys.WriteSopsYAML(projDir, []keys.Recipient{{Label: "two", Age: kp2.Recipient}}); err != nil {
		t.Fatalf("write .sops.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projDir, "secrets.yaml"), []byte("password: hunter2\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	if _, err := runSops(t, projDir, nil, "-e", "-i", "secrets.yaml"); err != nil {
		t.Fatalf("encrypt to identity-2: %v", err)
	}
	secretsBefore, _ := os.ReadFile(filepath.Join(projDir, "secrets.yaml"))
	sopsBefore, _ := os.ReadFile(filepath.Join(projDir, ".sops.yaml"))

	// Before matching, the mismatch is real drift, and the drift item names the
	// desired-only key (identity-1, added but not on disk) that Match will REMOVE.
	it, ok := sopsDriftFor(t, svc, proj.M.UUID)
	if !ok {
		t.Fatal("expected drift before Match to the on-disk keys")
	}
	if len(it.DesiredOnly) == 0 {
		t.Fatal("expected the drift item to name the added-but-not-applied key Match will drop")
	}
	joined := strings.Join(it.DesiredOnly, " ")
	if !strings.Contains(joined, "adopted-alice") {
		t.Fatalf("drop list must name identity-1 (adopted-alice); got %v", it.DesiredOnly)
	}

	if err := svc.MatchProjectToDisk(proj.M.UUID, "tester"); err != nil {
		t.Fatalf("MatchProjectToDisk: %v", err)
	}

	// Drift clears, the project now desires identity-2, and identity-1 was dropped from
	// the project (not from disk - it was never on disk).
	if it, ok := sopsDriftFor(t, svc, proj.M.UUID); ok {
		t.Fatalf("match must clear drift; got %q", it.Detail)
	}
	assigned := projectAssignedRecipients(st, proj.M.UUID)
	if !assigned[kp2.Recipient] || assigned[kp1.Recipient] {
		t.Fatalf("after match the project must desire identity-2 only; got %v", assigned)
	}
	// No unnecessary re-key: the encrypted secrets file is byte-identical (updatekeys
	// never ran) and the on-disk .sops.yaml is unchanged (it already matched).
	if after, _ := os.ReadFile(filepath.Join(projDir, "secrets.yaml")); string(after) != string(secretsBefore) {
		t.Fatal("Match to the on-disk keys must not re-key the secrets when the config already matches")
	}
	if after, _ := os.ReadFile(filepath.Join(projDir, ".sops.yaml")); string(after) != string(sopsBefore) {
		t.Fatal("Match to the on-disk keys must not rewrite the .sops.yaml when it already matches")
	}
	// No reader dropped: identity-2's key still decrypts the secret.
	kp2File := filepath.Join(t.TempDir(), "kp2.txt")
	if err := os.WriteFile(kp2File, []byte(kp2.Private+"\n"), 0o600); err != nil {
		t.Fatalf("write kp2: %v", err)
	}
	out, err := runSops(t, projDir, []string{"SOPS_AGE_KEY_FILE=" + kp2File}, "-d", "secrets.yaml")
	if err != nil || !strings.Contains(out, "hunter2") {
		t.Fatalf("identity-2 must still decrypt after match: out=%q err=%v", out, err)
	}
}

// TestMatchProjectToDiskPreValidatesAtomically proves the pre-validate hardening: when
// the on-disk config lists an EARLIER reader SopsHQ could adopt AND a LATER reader it
// cannot resolve, Match must fail having changed NOTHING - it neither adopts the earlier
// reader nor drops the project's existing assignment.
func TestMatchProjectToDiskPreValidatesAtomically(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, st, localID := build(t)
	keyBase := t.TempDir()
	projDir := t.TempDir()

	kp1, _ := keys.Generate() // the project's current key (in custody)
	kp2, _ := keys.Generate() // an on-disk reader: private present in the key store, adoptable
	kpX, _ := keys.Generate() // an on-disk reader SopsHQ has NO key for (never placed)
	// The key store holds kp1 and kp2 (kp2 is adoptable, but NOT yet in custody).
	if err := os.WriteFile(place.KeyFile(keyBase), []byte(kp1.Private+"\n"+kp2.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant keys: %v", err)
	}
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "alice", KeyBase: keyBase}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	// Put ONLY kp1 in custody and assign it to the project.
	k1 := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "adopted-alice", Type: model.KeyShared}
	if err := st.Keys.Put(k1); err != nil {
		t.Fatalf("k1: %v", err)
	}
	if err := svc.importPrivate(k1, kp1.Private, "tester"); err != nil {
		t.Fatalf("import kp1: %v", err)
	}
	proj := &model.Project{
		M:     model.Meta{UUID: store.NewID()},
		Name:  "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: projDir}},
	}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}
	if err := st.Assignments.Put(&model.Assignment{M: model.Meta{UUID: store.NewID()}, KeyID: k1.M.UUID, ProjectID: proj.M.UUID, MachineID: localID, OSUserID: osu.M.UUID}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	// On-disk config lists the adoptable reader FIRST, then the unresolvable stranger.
	if err := keys.WriteSopsYAML(projDir, []keys.Recipient{{Label: "two", Age: kp2.Recipient}, {Label: "x", Age: kpX.Recipient}}); err != nil {
		t.Fatalf("write .sops.yaml: %v", err)
	}

	keysBefore := len(st.Keys.List())
	asgBefore := len(st.Assignments.List())

	err := svc.MatchProjectToDisk(proj.M.UUID, "tester")
	if err == nil {
		t.Fatal("expected MatchProjectToDisk to refuse when an on-disk reader is unresolvable")
	}
	// Nothing changed: the earlier adoptable reader was NOT adopted, and the project's
	// existing assignment was NOT dropped.
	if got := len(st.Keys.List()); got != keysBefore {
		t.Fatalf("pre-validation failure must not adopt a key; keys before=%d after=%d", keysBefore, got)
	}
	if got := len(st.Assignments.List()); got != asgBefore {
		t.Fatalf("pre-validation failure must not add or drop an assignment; asg before=%d after=%d", asgBefore, got)
	}
	if !svc.HasAssignment(k1.M.UUID, proj.M.UUID, localID, osu.M.UUID) {
		t.Fatal("the project's existing assignment must survive a refused match")
	}
}
