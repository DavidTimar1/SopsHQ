package keysvc

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sopshq/internal/model"
	"sopshq/internal/store"
)

// TestResolveEditablePreconditions checks the error ladder when a project is not
// editable yet: no local machine -> no local path -> not wired.
func TestResolveEditablePreconditions(t *testing.T) {
	svc, st, localID := build(t)

	proj := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "app"}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}

	// No local path yet.
	if _, _, err := svc.resolveEditable(proj.M.UUID); err != ErrProjectNoLocalPath {
		t.Fatalf("expected ErrProjectNoLocalPath, got %v", err)
	}

	// Add a local path; still no key assigned.
	proj.Paths = []model.ProjectPath{{MachineID: localID, Path: t.TempDir()}}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project path: %v", err)
	}
	if _, _, err := svc.resolveEditable(proj.M.UUID); err != ErrProjectNotWired {
		t.Fatalf("expected ErrProjectNotWired, got %v", err)
	}
	if svc.ProjectWiredLocally(proj.M.UUID) {
		t.Fatal("project should not be wired locally yet")
	}

	// No local machine designated at all.
	svc.SetLocalMachine("")
	if _, _, err := svc.resolveEditable(proj.M.UUID); err != ErrNoLocalMachine {
		t.Fatalf("expected ErrNoLocalMachine, got %v", err)
	}
}

// TestEnsureProjectWiredAndEdit drives the onboarding glue end to end against the
// real age/sops binaries: a project with only a local path becomes wired (key
// generated + assigned + applied), then secrets can be listed/set/got/deleted.
func TestEnsureProjectWiredAndEdit(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)

	projDir := t.TempDir()
	proj := &model.Project{
		M:     model.Meta{UUID: store.NewID()},
		Name:  "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: projDir}},
	}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}

	// Pre-create the local OS user with an ISOLATED key base so wiring never
	// touches the real $HOME/.sops on the test host (which would also trip the
	// safe-wiring conflict guard against pre-existing state).
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: t.TempDir()}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}

	// Wire it: should reuse the OS user, create a key, an assignment, and apply.
	if err := svc.EnsureProjectWired(proj.M.UUID, "tester"); err != nil {
		t.Fatalf("EnsureProjectWired: %v", err)
	}
	if len(st.Keys.List()) != 1 || len(st.Assignments.List()) != 1 || len(st.OSUsers.List()) != 1 {
		t.Fatalf("wiring should create 1 key, 1 assignment, reuse 1 os user; got keys=%d asg=%d users=%d",
			len(st.Keys.List()), len(st.Assignments.List()), len(st.OSUsers.List()))
	}
	if _, err := os.Stat(filepath.Join(projDir, ".sops.yaml")); err != nil {
		t.Fatalf(".sops.yaml not written by wiring: %v", err)
	}
	if !svc.ProjectWiredLocally(proj.M.UUID) {
		t.Fatal("project should be wired after EnsureProjectWired")
	}

	// Idempotent: a second call is a no-op (no extra key/assignment).
	if err := svc.EnsureProjectWired(proj.M.UUID, "tester"); err != nil {
		t.Fatalf("EnsureProjectWired second call: %v", err)
	}
	if len(st.Keys.List()) != 1 {
		t.Fatalf("second wiring should not create another key; keys=%d", len(st.Keys.List()))
	}

	// Now the editor works.
	if names, err := svc.ListSecrets(proj.M.UUID); err != nil || len(names) != 0 {
		t.Fatalf("initial list: names=%v err=%v", names, err)
	}
	if err := svc.SetSecret(proj.M.UUID, "DB_PASSWORD", "hunter2", "tester"); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	names, err := svc.ListSecrets(proj.M.UUID)
	if err != nil || len(names) != 1 || names[0] != "DB_PASSWORD" {
		t.Fatalf("list after set: names=%v err=%v", names, err)
	}
	got, err := svc.GetSecretValue(proj.M.UUID, "DB_PASSWORD")
	if err != nil || got != "hunter2" {
		t.Fatalf("get: got=%q err=%v", got, err)
	}
	if err := svc.DeleteSecret(proj.M.UUID, "DB_PASSWORD", "tester"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	names, _ = svc.ListSecrets(proj.M.UUID)
	if len(names) != 0 {
		t.Fatalf("list after delete: names=%v", names)
	}

	// The audit log records the NAME but never the value.
	entries, err := svc.audit.Recent(50)
	if err != nil {
		t.Fatalf("audit recent: %v", err)
	}
	sawSet := false
	for _, e := range entries {
		blob := strings.Join([]string{e.Actor, e.Action, e.Target, e.Detail}, " ")
		if strings.Contains(blob, "hunter2") {
			t.Fatalf("audit entry leaked the secret value: %+v", e)
		}
		if e.Action == "secret_set" && strings.Contains(e.Target, "DB_PASSWORD") {
			sawSet = true
		}
	}
	if !sawSet {
		t.Fatal("expected a secret_set audit row naming DB_PASSWORD")
	}
}

// TestProjectAppliedLocally confirms the editor-readiness check distinguishes a
// project that is wired in the store (a generated key assigned + local path) from
// one that has ALSO had its .sops.yaml written to disk. The manual path (create a
// key + assignment without running Apply) leaves the project wired-but-not-applied,
// which must NOT present the secrets editor.
func TestProjectAppliedLocally(t *testing.T) {
	svc, st, localID := build(t)

	dir := t.TempDir()
	proj := &model.Project{
		M:     model.Meta{UUID: store.NewID()},
		Name:  "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: dir}},
	}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}

	// Records present but no Apply: a generated key sealed into the vault and
	// assigned locally. (No age/sops needed - the private blob is opaque here.)
	sealed, err := svc.vault.Seal([]byte("AGE-SECRET-KEY-1TESTONLY"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	k := &model.Key{
		M: model.Meta{UUID: store.NewID()}, Name: "k", Type: model.KeyShared,
		Recipient: "age1testonly", PrivSealed: sealed, Generation: 1, Status: model.KeyActive,
	}
	if err := st.Keys.Put(k); err != nil {
		t.Fatalf("key: %v", err)
	}
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: t.TempDir()}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	a := &model.Assignment{
		M: model.Meta{UUID: store.NewID()}, KeyID: k.M.UUID,
		ProjectID: proj.M.UUID, MachineID: localID, OSUserID: osu.M.UUID,
	}
	if err := st.Assignments.Put(a); err != nil {
		t.Fatalf("assignment: %v", err)
	}

	if !svc.ProjectWiredLocally(proj.M.UUID) {
		t.Fatal("records present -> should be wired locally")
	}
	if svc.ProjectAppliedLocally(proj.M.UUID) {
		t.Fatal("no .sops.yaml on disk -> must NOT be applied (editor hidden)")
	}

	// Writing .sops.yaml flips it to applied.
	if err := os.WriteFile(filepath.Join(dir, ".sops.yaml"), []byte("creation_rules: []\n"), 0o644); err != nil {
		t.Fatalf("write .sops.yaml: %v", err)
	}
	if !svc.ProjectAppliedLocally(proj.M.UUID) {
		t.Fatal(".sops.yaml present -> should be applied (editor shown)")
	}
}

// TestEnsureProjectWiredRequiresPath confirms wiring refuses a project with no
// local folder.
func TestEnsureProjectWiredRequiresPath(t *testing.T) {
	svc, st, _ := build(t)
	proj := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "app"}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}
	if err := svc.EnsureProjectWired(proj.M.UUID, "tester"); err != ErrProjectNoLocalPath {
		t.Fatalf("expected ErrProjectNoLocalPath, got %v", err)
	}
}

// TestEnsureProjectWiredRequiresOSUser confirms that wiring a project with a local
// path but NO OS user on this machine returns ErrNoLocalOSUser and creates nothing -
// SopsHQ must never silently invent the OS user (a deliberate security choice).
func TestEnsureProjectWiredRequiresOSUser(t *testing.T) {
	svc, st, localID := build(t)
	proj := &model.Project{
		M:     model.Meta{UUID: store.NewID()},
		Name:  "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: t.TempDir()}},
	}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}
	if err := svc.EnsureProjectWired(proj.M.UUID, "tester"); err != ErrNoLocalOSUser {
		t.Fatalf("expected ErrNoLocalOSUser, got %v", err)
	}
	// WireProjectResolved must guard the same way.
	if err := svc.WireProjectResolved(proj.M.UUID, WiringChoices{Key: DecideRecreate}, "tester"); err != ErrNoLocalOSUser {
		t.Fatalf("WireProjectResolved expected ErrNoLocalOSUser, got %v", err)
	}
	// Nothing was created as a side effect: no OS user, key, or assignment.
	if n := len(st.OSUsers.List()); n != 0 {
		t.Fatalf("no OS user must be auto-created; got %d", n)
	}
	if n := len(st.Keys.List()); n != 0 {
		t.Fatalf("no key must be created; got %d", n)
	}
	if n := len(st.Assignments.List()); n != 0 {
		t.Fatalf("no assignment must be created; got %d", n)
	}
}
