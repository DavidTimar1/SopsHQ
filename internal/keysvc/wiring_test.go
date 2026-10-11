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

// wiredProject creates a project with a local path and an OS user with the given
// (isolated) key base, returning the project and the os user.
func wiredProject(t *testing.T, svc *Service, st *store.Store, localID, projDir, keyBase string) (*model.Project, *model.OSUser) {
	t.Helper()
	proj := &model.Project{
		M:     model.Meta{UUID: store.NewID()},
		Name:  "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: projDir}},
	}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: keyBase}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	return proj, osu
}

// TestInspectWiringCleanTarget: with an empty base and project dir, inspection
// reports nothing existing, and EnsureProjectWired proceeds without a conflict.
func TestInspectWiringCleanTarget(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)
	proj, _ := wiredProject(t, svc, st, localID, t.TempDir(), t.TempDir())

	insp, err := svc.InspectWiring(proj.M.UUID)
	if err != nil {
		t.Fatalf("InspectWiring: %v", err)
	}
	if insp.AnyExisting() {
		t.Fatalf("clean target should not report existing state: %+v", insp)
	}
	if err := svc.EnsureProjectWired(proj.M.UUID, "tester"); err != nil {
		t.Fatalf("EnsureProjectWired clean: %v", err)
	}
}

// TestEnsureProjectWiredRefusesExistingKeysTxt is the central guard: when a
// non-empty keys.txt already sits at the target base, EnsureProjectWired must
// REFUSE (ErrWiringConflict) rather than overwrite it.
func TestEnsureProjectWiredRefusesExistingKeysTxt(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, st, localID := build(t)
	keyBase := t.TempDir()
	proj, _ := wiredProject(t, svc, st, localID, t.TempDir(), keyBase)

	// Plant an existing private key on disk.
	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := os.WriteFile(place.KeyFile(keyBase), []byte(kp.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant key: %v", err)
	}
	before, _ := os.ReadFile(place.KeyFile(keyBase))

	if err := svc.EnsureProjectWired(proj.M.UUID, "tester"); err != ErrWiringConflict {
		t.Fatalf("expected ErrWiringConflict, got %v", err)
	}
	// The on-disk key must be untouched and NO records created.
	after, _ := os.ReadFile(place.KeyFile(keyBase))
	if string(before) != string(after) {
		t.Fatal("refused wiring must not modify the existing keys.txt")
	}
	if len(st.Keys.List()) != 0 || len(st.Assignments.List()) != 0 {
		t.Fatalf("refused wiring must not create records; keys=%d asg=%d",
			len(st.Keys.List()), len(st.Assignments.List()))
	}
}

// TestWireProjectReuseAdoptsExistingKey: when the operator chooses REUSE, wiring
// imports the on-disk key (byte-identical file) instead of generating a new one,
// and the key record's recipient matches the on-disk key.
func TestWireProjectReuseAdoptsExistingKey(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)
	keyBase := t.TempDir()
	projDir := t.TempDir()
	proj, _ := wiredProject(t, svc, st, localID, projDir, keyBase)

	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	keyPath := place.KeyFile(keyBase)
	if err := os.WriteFile(keyPath, []byte(kp.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant key: %v", err)
	}
	before, _ := os.ReadFile(keyPath)

	// EnsureProjectWired refuses; then resolve with REUSE.
	if err := svc.EnsureProjectWired(proj.M.UUID, "tester"); err != ErrWiringConflict {
		t.Fatalf("expected conflict, got %v", err)
	}
	if err := svc.WireProjectResolved(proj.M.UUID, WiringChoices{Key: DecideReuse}, "tester"); err != nil {
		t.Fatalf("WireProjectResolved reuse: %v", err)
	}

	// The adopted key file is byte-identical (REUSE must not rewrite it... but the
	// placer DOES re-assert the same content; assert content equality).
	after, _ := os.ReadFile(keyPath)
	if strings.TrimSpace(string(before)) != strings.TrimSpace(string(after)) {
		t.Fatal("REUSE changed the on-disk private key")
	}

	// The key record adopted the on-disk key's recipient (not a fresh one).
	if len(st.Keys.List()) != 1 {
		t.Fatalf("expected exactly 1 key, got %d", len(st.Keys.List()))
	}
	k := st.Keys.List()[0]
	if k.Recipient != kp.Recipient {
		t.Fatalf("adopted recipient = %q, want %q (the on-disk key's)", k.Recipient, kp.Recipient)
	}
	if !svc.ProjectWiredLocally(proj.M.UUID) {
		t.Fatal("project should be wired after reuse")
	}

	// The vault-sealed private must unseal back to the on-disk key.
	priv, err := svc.unsealPriv(k)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if priv != kp.Private {
		t.Fatal("sealed private does not match the adopted on-disk key")
	}
}

// TestWireProjectRecreateReplacesKey: when the operator chooses RE-CREATE, wiring
// generates a NEW keypair (different recipient) and overwrites keys.txt.
func TestWireProjectRecreateReplacesKey(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)
	keyBase := t.TempDir()
	proj, _ := wiredProject(t, svc, st, localID, t.TempDir(), keyBase)

	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	keyPath := place.KeyFile(keyBase)
	if err := os.WriteFile(keyPath, []byte(kp.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant key: %v", err)
	}

	if err := svc.WireProjectResolved(proj.M.UUID, WiringChoices{Key: DecideRecreate}, "tester"); err != nil {
		t.Fatalf("WireProjectResolved recreate: %v", err)
	}
	k := st.Keys.List()[0]
	if k.Recipient == kp.Recipient {
		t.Fatal("RE-CREATE should produce a new keypair, not adopt the old recipient")
	}
	// keys.txt should now hold the NEW private key.
	after, _ := os.ReadFile(keyPath)
	if strings.TrimSpace(string(after)) == kp.Private {
		t.Fatal("RE-CREATE should have overwritten keys.txt with the new key")
	}
}

// TestImportPrivateSealsAndDerives unit-tests the import seam without an on-disk
// file: a planted private key is sealed and its recipient derived correctly.
func TestImportPrivateSealsAndDerives(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, st, _ := build(t)
	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	k := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "imported", Type: model.KeyShared}
	if err := st.Keys.Put(k); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := svc.importPrivate(k, kp.Private, "tester"); err != nil {
		t.Fatalf("importPrivate: %v", err)
	}
	got, _ := st.Keys.Get(k.M.UUID)
	if got.Recipient != kp.Recipient {
		t.Fatalf("recipient = %q, want %q", got.Recipient, kp.Recipient)
	}
	if got.PrivSealed == "" || got.PrivSealed == kp.Private {
		t.Fatal("private must be sealed, not stored in the clear")
	}
	priv, err := svc.unsealPriv(got)
	if err != nil || priv != kp.Private {
		t.Fatalf("unseal mismatch: %v", err)
	}
	// Importing over an already-generated key is refused.
	if err := svc.importPrivate(got, kp.Private, "tester"); err == nil {
		t.Fatal("importing over an existing key should error")
	}
}

// TestImportPrivateNeverLeaksToAudit confirms the audit log never records the
// private key when importing.
func TestImportPrivateNeverLeaksToAudit(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, st, _ := build(t)
	kp, _ := keys.Generate()
	k := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "imported", Type: model.KeyShared}
	_ = st.Keys.Put(k)
	if err := svc.importPrivate(k, kp.Private, "tester"); err != nil {
		t.Fatalf("importPrivate: %v", err)
	}
	entries, err := svc.audit.Recent(50)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	for _, e := range entries {
		blob := strings.Join([]string{e.Actor, e.Action, e.Target, e.Detail}, " ")
		if strings.Contains(blob, kp.Private) {
			t.Fatalf("audit leaked the private key: %+v", e)
		}
	}
}

// TestWireProjectReuseKeepsExistingSopsYAML: when the operator chooses to REUSE an
// existing .sops.yaml, wiring must leave that file byte-identical (not rewrite it
// with SopsHQ recipients).
func TestWireProjectReuseKeepsExistingSopsYAML(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, st, localID := build(t)
	keyBase := t.TempDir()
	projDir := t.TempDir()
	proj, _ := wiredProject(t, svc, st, localID, projDir, keyBase)

	// A hand-authored .sops.yaml the operator wants kept.
	sopsPath := filepath.Join(projDir, ".sops.yaml")
	want := "# hand authored\ncreation_rules:\n  - age: age1keepme\n"
	if err := os.WriteFile(sopsPath, []byte(want), 0o644); err != nil {
		t.Fatalf("plant yaml: %v", err)
	}

	// Plant an on-disk key too and reuse it, so wiring takes the reusing path.
	kp, _ := keys.Generate()
	if err := os.WriteFile(place.KeyFile(keyBase), []byte(kp.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant key: %v", err)
	}

	if err := svc.WireProjectResolved(proj.M.UUID,
		WiringChoices{Key: DecideReuse, SopsYAML: DecideReuse}, "tester"); err != nil {
		t.Fatalf("WireProjectResolved: %v", err)
	}
	got, _ := os.ReadFile(sopsPath)
	if string(got) != want {
		t.Fatalf("REUSE must leave .sops.yaml unchanged.\n got: %q\nwant: %q", got, want)
	}
}

// TestWireProjectReuseCommentHeadedKeyFile is the regression for the live REUSE
// bug: a real `age-keygen -o keys.txt` file has two leading "# ..." comment lines
// before the AGE-SECRET-KEY-1 line (the shape real machines produce). REUSE must parse that, adopt the key, leave the file byte-identical,
// derive the matching recipient, and let a secret round-trip.
func TestWireProjectReuseCommentHeadedKeyFile(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)
	keyBase := t.TempDir()
	projDir := t.TempDir()
	proj, _ := wiredProject(t, svc, st, localID, projDir, keyBase)

	// Produce a REAL age-keygen file (comment-headed) at the key base.
	keyPath := place.KeyFile(keyBase)
	if out, err := exec.Command("age-keygen", "-o", keyPath).CombinedOutput(); err != nil {
		t.Fatalf("age-keygen -o: %v: %s", err, out)
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if !strings.Contains(string(raw), "# public key:") || !strings.Contains(string(raw), "AGE-SECRET-KEY-1") {
		t.Fatalf("planted file is not in the comment-headed shape:\n%s", raw)
	}
	wantRecipient, err := keys.RecipientFor(string(raw))
	if err != nil {
		t.Fatalf("derive recipient: %v", err)
	}
	before := string(raw)

	// EnsureProjectWired must refuse (state exists); then REUSE adopts it.
	if err := svc.EnsureProjectWired(proj.M.UUID, "tester"); err != ErrWiringConflict {
		t.Fatalf("expected conflict, got %v", err)
	}
	if err := svc.WireProjectResolved(proj.M.UUID, WiringChoices{Key: DecideReuse}, "tester"); err != nil {
		t.Fatalf("WireProjectResolved reuse (comment-headed): %v", err)
	}

	// File byte-identical, recipient adopted, project editable.
	after, _ := os.ReadFile(keyPath)
	if string(after) != before {
		t.Fatalf("REUSE changed the comment-headed key file.\n got: %q\nwant: %q", after, before)
	}
	if len(st.Keys.List()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(st.Keys.List()))
	}
	if got := st.Keys.List()[0].Recipient; got != wantRecipient {
		t.Fatalf("adopted recipient = %q, want %q", got, wantRecipient)
	}

	// A secret encrypted to the project key decrypts with the on-disk key file.
	if err := svc.SetSecret(proj.M.UUID, "DB_PASSWORD", "hunter2", "tester"); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	got, err := svc.GetSecretValue(proj.M.UUID, "DB_PASSWORD")
	if err != nil || got != "hunter2" {
		t.Fatalf("secret round-trip: got=%q err=%v", got, err)
	}
}

// TestWireProjectReuseImportFailureRollsBack: if adopting the on-disk key fails
// (the file is present but not a parseable age key), wire() must NOT leave an
// orphaned empty Key record behind.
func TestWireProjectReuseImportFailureRollsBack(t *testing.T) {
	svc, st, localID := build(t)
	keyBase := t.TempDir()
	proj, _ := wiredProject(t, svc, st, localID, t.TempDir(), keyBase)

	// A non-empty file that is NOT an age key: detected as existing, but import fails.
	if err := os.WriteFile(place.KeyFile(keyBase), []byte("# created: whenever\nnot-a-key\n"), 0o600); err != nil {
		t.Fatalf("plant junk: %v", err)
	}

	err := svc.WireProjectResolved(proj.M.UUID, WiringChoices{Key: DecideReuse}, "tester")
	if err == nil {
		t.Fatal("expected import to fail on a non-key file")
	}
	if n := len(st.Keys.List()); n != 0 {
		t.Fatalf("failed REUSE import must roll back its Key record; keys=%d", n)
	}
	if n := len(st.Assignments.List()); n != 0 {
		t.Fatalf("failed REUSE import must not create an assignment; asg=%d", n)
	}
}

// TestWireProjectReuseDoesNotRepointEnv proves the env-preserve branch: when
// SOPS_AGE_KEY_FILE already points elsewhere and the operator keeps it (REUSE),
// wiring writes the key store directly (WriteKeyStore) and never runs the
// discovery/setx placer. We detect "discovery ran" by spying on s.placer, which
// the keepEnv path must NOT call.
func TestWireProjectReuseDoesNotRepointEnv(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)
	keyBase := t.TempDir()
	projDir := t.TempDir()
	proj, _ := wiredProject(t, svc, st, localID, projDir, keyBase)

	// SOPS_AGE_KEY_FILE points at a DIFFERENT path, so EnvPointsElsewhere is true.
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(t.TempDir(), "other", "keys.txt"))

	// Plant an on-disk key to adopt.
	kp, _ := keys.Generate()
	if err := os.WriteFile(place.KeyFile(keyBase), []byte(kp.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant key: %v", err)
	}

	// Spy placer: records whether the discovery placer was invoked. The keepEnv
	// reuse path must use place.WriteKeyStore directly, NOT this.
	discoveryRan := false
	svc.SetPlacer(func(o place.Opts) error {
		discoveryRan = true
		return place.WriteKeyStore(o)
	})

	if err := svc.WireProjectResolved(proj.M.UUID,
		WiringChoices{Key: DecideReuse, EnvKeyFile: DecideReuse}, "tester"); err != nil {
		t.Fatalf("WireProjectResolved (keep env): %v", err)
	}
	if discoveryRan {
		t.Fatal("REUSE with kept env must NOT run the discovery/setx placer")
	}
	// The key store is still written (byte-identical to the adopted key).
	if b, _ := os.ReadFile(place.KeyFile(keyBase)); strings.TrimSpace(string(b)) != kp.Private {
		t.Fatal("key store should hold the adopted key after reuse")
	}
	if !svc.ProjectWiredLocally(proj.M.UUID) {
		t.Fatal("project should be wired after reuse")
	}
	_ = st
}

// TestAdoptExistingKeyForOSUser is the Item-C case the operator hit: pointing an OS
// user at a keystore that already holds keys.txt must IMPORT that key as a Key record
// (with an assignment linking user+machine) so it appears on the Keys page and is
// usable - without modifying the on-disk file. A second call is a no-op (the user now
// has a key).
func TestAdoptExistingKeyForOSUser(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, st, localID := build(t)
	keyBase := t.TempDir()

	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	keyPath := place.KeyFile(keyBase)
	if err := os.WriteFile(keyPath, []byte(kp.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant key: %v", err)
	}
	before, _ := os.ReadFile(keyPath)

	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "alice", KeyBase: keyBase}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}

	name, count, err := svc.AdoptExistingKeyForOSUser(osu.M.UUID, "tester")
	if err != nil || count != 1 {
		t.Fatalf("adopt: name=%q count=%d err=%v", name, count, err)
	}
	if name != "adopted-alice" {
		t.Fatalf("adopted key name = %q, want adopted-alice", name)
	}
	// The on-disk key must be byte-identical (adopt = read + record).
	if after, _ := os.ReadFile(keyPath); string(after) != string(before) {
		t.Fatal("adopt modified the on-disk keys.txt")
	}
	// Exactly one Key with the on-disk key's recipient, and an assignment linking it.
	if len(st.Keys.List()) != 1 {
		t.Fatalf("expected 1 key, got %d", len(st.Keys.List()))
	}
	k := st.Keys.List()[0]
	if k.Recipient != kp.Recipient {
		t.Fatalf("adopted recipient = %q, want %q", k.Recipient, kp.Recipient)
	}
	asgs := st.Assignments.List()
	if len(asgs) != 1 || asgs[0].KeyID != k.M.UUID || asgs[0].OSUserID != osu.M.UUID || asgs[0].MachineID != localID {
		t.Fatalf("assignment must link key<->osuser<->machine; got %+v", asgs)
	}
	// The sealed private unseals back to the on-disk key.
	if priv, err := svc.unsealPriv(k); err != nil || priv != kp.Private {
		t.Fatalf("sealed private mismatch: %v", err)
	}
	// Second call: the user already has a key -> no-op.
	if _, count2, err := svc.AdoptExistingKeyForOSUser(osu.M.UUID, "tester"); err != nil || count2 != 0 {
		t.Fatalf("second adopt should be a no-op; count=%d err=%v", count2, err)
	}
	if len(st.Keys.List()) != 1 {
		t.Fatalf("second adopt must not create another key; keys=%d", len(st.Keys.List()))
	}
}

// TestAdoptExistingKeyForOSUserNothingToAdopt: an empty keystore (no keys.txt) is a
// safe no-op, not an error.
func TestAdoptExistingKeyForOSUserNothingToAdopt(t *testing.T) {
	svc, st, localID := build(t)
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: t.TempDir()}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	name, count, err := svc.AdoptExistingKeyForOSUser(osu.M.UUID, "tester")
	if err != nil || count != 0 || name != "" {
		t.Fatalf("expected clean no-op, got name=%q count=%d err=%v", name, count, err)
	}
	if len(st.Keys.List()) != 0 || len(st.Assignments.List()) != 0 {
		t.Fatalf("no-op adopt must create nothing; keys=%d asg=%d", len(st.Keys.List()), len(st.Assignments.List()))
	}
}

// TestReuseRecreateSopsYAMLPreservesExistingRecipients is the Item-D guarantee: when
// the operator REUSES the on-disk key but RE-CREATES the .sops.yaml, wiring must NOT
// drop a second reader already listed in that .sops.yaml (a public key the secrets
// were encrypted to). It unions the existing on-disk readers into the re-written file,
// so the second reader's key still decrypts.
func TestReuseRecreateSopsYAMLPreservesExistingRecipients(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)
	keyBase := t.TempDir()
	projDir := t.TempDir()
	proj, _ := wiredProject(t, svc, st, localID, projDir, keyBase)

	// kp1 is the on-disk key SopsHQ adopts (reuse); kp2 is a SECOND reader that is
	// already listed in the project's .sops.yaml and must survive.
	kp1, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate kp1: %v", err)
	}
	kp2, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate kp2: %v", err)
	}
	if err := os.WriteFile(place.KeyFile(keyBase), []byte(kp1.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant key: %v", err)
	}
	// A .sops.yaml listing BOTH readers, and a secret encrypted to both.
	if err := keys.WriteSopsYAML(projDir, []keys.Recipient{{Label: "one", Age: kp1.Recipient}, {Label: "two", Age: kp2.Recipient}}); err != nil {
		t.Fatalf("write .sops.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projDir, "secrets.yaml"), []byte("password: hunter2\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	if _, err := runSops(t, projDir, nil, "-e", "-i", "secrets.yaml"); err != nil {
		t.Fatalf("encrypt to both readers: %v", err)
	}

	// The footgun combo: reuse the key, re-create the .sops.yaml.
	if err := svc.WireProjectResolved(proj.M.UUID,
		WiringChoices{Key: DecideReuse, SopsYAML: DecideRecreate}, "tester"); err != nil {
		t.Fatalf("WireProjectResolved reuse+recreate: %v", err)
	}

	// The re-created .sops.yaml must still list BOTH readers.
	sy, _ := os.ReadFile(filepath.Join(projDir, ".sops.yaml"))
	if !strings.Contains(string(sy), kp1.Recipient) || !strings.Contains(string(sy), kp2.Recipient) {
		t.Fatalf("re-created .sops.yaml dropped a reader:\n%s", sy)
	}
	// The SECOND reader's key still decrypts the secret (never locked out).
	kp2File := filepath.Join(t.TempDir(), "kp2.txt")
	if err := os.WriteFile(kp2File, []byte(kp2.Private+"\n"), 0o600); err != nil {
		t.Fatalf("write kp2: %v", err)
	}
	out, err := runSops(t, projDir, []string{"SOPS_AGE_KEY_FILE=" + kp2File}, "-d", "secrets.yaml")
	if err != nil || !strings.Contains(out, "hunter2") {
		t.Fatalf("second reader can no longer decrypt after re-create: out=%q err=%v", out, err)
	}
	_ = st
}

// TestExistingReadersLayouts proves the reader harvest is layout-agnostic: a second
// reader must be found (and unioned in) whether .sops.yaml uses an inline list, a
// folded scalar, a block sequence, or spreads readers across two creation_rules -
// the real-sops forms that a naive single-`age:`-line parser would drop.
func TestExistingReadersLayouts(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, _, _ := build(t)
	kp1, err := keys.Generate()
	if err != nil {
		t.Fatalf("gen1: %v", err)
	}
	kp2, err := keys.Generate()
	if err != nil {
		t.Fatalf("gen2: %v", err)
	}
	r1, r2 := kp1.Recipient, kp2.Recipient
	cases := []struct{ name, yaml string }{
		{"inline", "creation_rules:\n  - path_regex: secrets.*\\.ya?ml$\n    age: " + r1 + "," + r2 + "\n"},
		{"folded-scalar", "creation_rules:\n  - path_regex: secrets.*\\.ya?ml$\n    age: >-\n      " + r1 + ",\n      " + r2 + "\n"},
		{"block-sequence", "creation_rules:\n  - path_regex: secrets.*\\.ya?ml$\n    age:\n      - " + r1 + "\n      - " + r2 + "\n"},
		{"two-creation-rules", "creation_rules:\n  - path_regex: other\\.yaml$\n    age: " + r1 + "\n  - path_regex: secrets.*\\.ya?ml$\n    age: " + r2 + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ".sops.yaml"), []byte(tc.yaml), 0o644); err != nil {
				t.Fatalf("write yaml: %v", err)
			}
			readers, present := svc.existingReaders(dir)
			if !present {
				t.Fatalf("%s: present should be true", tc.name)
			}
			got := map[string]bool{}
			for _, r := range readers {
				got[r] = true
			}
			if !got[r1] || !got[r2] {
				t.Fatalf("%s: harvest dropped a reader; got %v", tc.name, readers)
			}
			// The union (desired = only r1) must still carry r2 forward.
			union, uerr := svc.unionExistingRecipients(dir, []keys.Recipient{{Label: "mine", Age: r1}})
			if uerr != nil {
				t.Fatalf("%s: union: %v", tc.name, uerr)
			}
			ages := map[string]bool{}
			for _, u := range union {
				ages[u.Age] = true
			}
			if !ages[r1] || !ages[r2] {
				t.Fatalf("%s: union dropped a reader; got %v", tc.name, union)
			}
		})
	}
}

// TestUnionFailsClosedOnUnreadableReaders: when .sops.yaml clearly signals recipients
// (an "age:" key) but none can be harvested (a format SopsHQ cannot read), the union
// REFUSES to rewrite rather than silently produce a reduced set that would lock a
// reader out.
func TestUnionFailsClosedOnUnreadableReaders(t *testing.T) {
	svc, _, _ := build(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".sops.yaml"),
		[]byte("creation_rules:\n  - age: THIS_IS_NOT_A_VALID_AGE_RECIPIENT\n"), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	_, err := svc.unionExistingRecipients(dir, []keys.Recipient{{Label: "mine", Age: "age1mine"}})
	if err == nil {
		t.Fatal("expected fail-closed error when readers are signalled but unreadable")
	}
	if !strings.Contains(err.Error(), "not rewriting") {
		t.Fatalf("error should explain the fail-closed refusal; got %v", err)
	}
}

// TestExistingReadersFromSecretsMetadata proves the ENCRYPTED secrets file is treated
// as the authoritative reader list: even after .sops.yaml is reduced to one reader,
// the secret's sops metadata still reveals the second reader, so the union restores it.
func TestExistingReadersFromSecretsMetadata(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, _, _ := build(t)
	dir := t.TempDir()
	kp1, _ := keys.Generate()
	kp2, _ := keys.Generate()
	// Encrypt a secret to BOTH readers via a two-reader .sops.yaml.
	if err := keys.WriteSopsYAML(dir, []keys.Recipient{{Label: "one", Age: kp1.Recipient}, {Label: "two", Age: kp2.Recipient}}); err != nil {
		t.Fatalf("write .sops.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte("password: hunter2\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	if _, err := runSops(t, dir, nil, "-e", "-i", "secrets.yaml"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Now REDUCE .sops.yaml to only the first reader (as a hand-edit might).
	if err := keys.WriteSopsYAML(dir, []keys.Recipient{{Label: "one", Age: kp1.Recipient}}); err != nil {
		t.Fatalf("shrink .sops.yaml: %v", err)
	}
	readers, present := svc.existingReaders(dir)
	if !present {
		t.Fatal("present should be true")
	}
	got := map[string]bool{}
	for _, r := range readers {
		got[r] = true
	}
	if !got[kp1.Recipient] || !got[kp2.Recipient] {
		t.Fatalf("the encrypted secret's metadata must reveal the second reader; got %v", readers)
	}
}

// TestReuseRecreateFoldedSopsYAMLPreservesReaders is the end-to-end regression:
// a REAL folded-scalar .sops.yaml with two readers, reuse the on-disk key and
// re-create .sops.yaml, then confirm the SECOND reader still decrypts after updatekeys.
func TestReuseRecreateFoldedSopsYAMLPreservesReaders(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)
	keyBase := t.TempDir()
	projDir := t.TempDir()
	proj, _ := wiredProject(t, svc, st, localID, projDir, keyBase)

	kp1, _ := keys.Generate()
	kp2, _ := keys.Generate()
	if err := os.WriteFile(place.KeyFile(keyBase), []byte(kp1.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant key: %v", err)
	}
	// Folded-scalar .sops.yaml listing BOTH readers (a form a line-based parser mishandles).
	folded := "creation_rules:\n  - path_regex: secrets.*\\.ya?ml$\n    age: >-\n      " +
		kp1.Recipient + ",\n      " + kp2.Recipient + "\n"
	if err := os.WriteFile(filepath.Join(projDir, ".sops.yaml"), []byte(folded), 0o644); err != nil {
		t.Fatalf("write folded .sops.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projDir, "secrets.yaml"), []byte("password: hunter2\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	if _, err := runSops(t, projDir, nil, "-e", "-i", "secrets.yaml"); err != nil {
		t.Fatalf("encrypt to both: %v", err)
	}

	if err := svc.WireProjectResolved(proj.M.UUID,
		WiringChoices{Key: DecideReuse, SopsYAML: DecideRecreate}, "tester"); err != nil {
		t.Fatalf("wire reuse+recreate: %v", err)
	}

	sy, _ := os.ReadFile(filepath.Join(projDir, ".sops.yaml"))
	if !strings.Contains(string(sy), kp1.Recipient) || !strings.Contains(string(sy), kp2.Recipient) {
		t.Fatalf("re-created .sops.yaml dropped a folded-scalar reader:\n%s", sy)
	}
	kp2File := filepath.Join(t.TempDir(), "kp2.txt")
	if err := os.WriteFile(kp2File, []byte(kp2.Private+"\n"), 0o600); err != nil {
		t.Fatalf("write kp2: %v", err)
	}
	out, err := runSops(t, projDir, []string{"SOPS_AGE_KEY_FILE=" + kp2File}, "-d", "secrets.yaml")
	if err != nil || !strings.Contains(out, "hunter2") {
		t.Fatalf("second reader locked out after re-create: out=%q err=%v", out, err)
	}
}

// TestAdoptMultiIdentityKeysTxtSurvivesApply is the regression: a keys.txt with
// TWO identities must be fully adopted, and a later ApplyLocal (which rebuilds the
// user's key store from the vault) must NOT drop either identity.
func TestAdoptMultiIdentityKeysTxtSurvivesApply(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, st, localID := build(t)
	keyBase := t.TempDir()
	kp1, _ := keys.Generate()
	kp2, _ := keys.Generate()
	if err := os.WriteFile(place.KeyFile(keyBase), []byte(kp1.Private+"\n"+kp2.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant keys: %v", err)
	}
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "alice", KeyBase: keyBase}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}

	_, count, err := svc.AdoptExistingKeyForOSUser(osu.M.UUID, "tester")
	if err != nil || count != 2 {
		t.Fatalf("expected both identities adopted; count=%d err=%v", count, err)
	}
	if len(st.Keys.List()) != 2 || len(st.Assignments.List()) != 2 {
		t.Fatalf("adopt must create 2 keys + 2 assignments; keys=%d asg=%d", len(st.Keys.List()), len(st.Assignments.List()))
	}

	// A later Apply rebuilds keys.txt from the vault; both identities must survive.
	if _, err := svc.ApplyLocal("tester", false); err != nil {
		t.Fatalf("ApplyLocal: %v", err)
	}
	after, _ := os.ReadFile(place.KeyFile(keyBase))
	if !strings.Contains(string(after), kp1.Private) || !strings.Contains(string(after), kp2.Private) {
		t.Fatalf("ApplyLocal dropped an identity from keys.txt:\n%s", after)
	}
}

// TestEnsureProjectWiredRefusesExistingSopsYAML: a pre-existing .sops.yaml (even
// hand-authored) trips the guard.
func TestEnsureProjectWiredRefusesExistingSopsYAML(t *testing.T) {
	svc, st, localID := build(t)
	projDir := t.TempDir()
	proj, _ := wiredProject(t, svc, st, localID, projDir, t.TempDir())
	if err := os.WriteFile(filepath.Join(projDir, ".sops.yaml"), []byte("creation_rules: []\n"), 0o644); err != nil {
		t.Fatalf("plant yaml: %v", err)
	}
	if err := svc.EnsureProjectWired(proj.M.UUID, "tester"); err != ErrWiringConflict {
		t.Fatalf("expected ErrWiringConflict for existing .sops.yaml, got %v", err)
	}
}
