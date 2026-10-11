package keysvc

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sopshq/internal/audit"
	"sopshq/internal/model"
	"sopshq/internal/place"
	"sopshq/internal/store"
	"sopshq/internal/vault"
)

// build wires a Service over temp store + unlocked vault, with the safe
// WriteKeyStore placer (no discovery side effects on the test host).
func build(t *testing.T) (*Service, *store.Store, string) {
	t.Helper()
	// Hermetic inspection: clear any SOPS_AGE_KEY_FILE leaking from the parent
	// shell so place.Inspect does not see host state during wiring tests.
	t.Setenv("SOPS_AGE_KEY_FILE", "")
	dir := t.TempDir()
	v, err := vault.Init(filepath.Join(dir, "vault"), "pass")
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	st, err := store.Open(filepath.Join(dir, "data"), "node", nil)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	a := audit.Open(filepath.Join(dir, "audit.jsonl"), "node", nil)

	mc := &model.Machine{M: model.Meta{UUID: store.NewID()}, Name: "local", OS: model.OSWindows}
	if err := st.Machines.Put(mc); err != nil {
		t.Fatalf("machine: %v", err)
	}
	svc := New(st, v, a, mc.M.UUID)
	svc.SetPlacer(place.WriteKeyStore) // avoid junction/setx on the test host
	// Backstop: neutralize the OS-level discovery side effects (setx/mklink/bashrc)
	// for this test binary. The reuse/adopt wiring path runs discovery WITHOUT the
	// placer, so the real place.EnsureDiscovery still executes (the security refusal
	// test depends on it) but can never mutate the host.
	place.DisableEffectsForTest(t)
	return svc, st, mc.M.UUID
}

func runSops(t *testing.T, dir string, env []string, args ...string) (string, error) {
	t.Helper()
	bin, err := exec.LookPath("sops")
	if err != nil {
		t.Skip("sops not on PATH")
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), &runErr{err, errb.String()}
	}
	return out.String(), nil
}

type runErr struct {
	err error
	out string
}

func (e *runErr) Error() string { return e.err.Error() + ": " + e.out }

func TestApplyAndRotateLocal(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)

	projDir := t.TempDir()
	keyBase := t.TempDir()

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
	key := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "app-key", Type: model.KeyShared, Status: model.KeyActive}
	if err := st.Keys.Put(key); err != nil {
		t.Fatalf("key: %v", err)
	}
	if err := svc.Generate(key.M.UUID, "tester"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	asg := &model.Assignment{M: model.Meta{UUID: store.NewID()}, KeyID: key.M.UUID, ProjectID: proj.M.UUID, MachineID: localID, OSUserID: osu.M.UUID}
	if err := st.Assignments.Put(asg); err != nil {
		t.Fatalf("assignment: %v", err)
	}

	// Apply: places the key and writes .sops.yaml.
	rep, err := svc.ApplyLocal("tester", false)
	if err != nil {
		t.Fatalf("ApplyLocal: %v", err)
	}
	if rep.KeysPlaced != 1 || rep.ProjectsWired != 1 {
		t.Fatalf("unexpected report: %+v", rep)
	}
	placedKey := filepath.Join(keyBase, "keys.txt")
	if b, err := os.ReadFile(placedKey); err != nil || !strings.HasPrefix(strings.TrimSpace(string(b)), "AGE-SECRET-KEY-1") {
		t.Fatalf("private key not placed: err=%v", err)
	}
	gen1, _ := st.Keys.Get(key.M.UUID)
	if sy, _ := os.ReadFile(filepath.Join(projDir, ".sops.yaml")); !strings.Contains(string(sy), gen1.Recipient) {
		t.Fatalf(".sops.yaml missing recipient")
	}

	// Encrypt a secret using the generated .sops.yaml, then decrypt with the
	// placed key.
	if err := os.WriteFile(filepath.Join(projDir, "secrets.yaml"), []byte("password: hunter2\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	if _, err := runSops(t, projDir, nil, "-e", "-i", "secrets.yaml"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	out, err := runSops(t, projDir, []string{"SOPS_AGE_KEY_FILE=" + placedKey}, "-d", "secrets.yaml")
	if err != nil || !strings.Contains(out, "hunter2") {
		t.Fatalf("decrypt with placed key: out=%q err=%v", out, err)
	}

	// Save the OLD private key to prove it stops working after rotation.
	oldPriv, _ := os.ReadFile(placedKey)
	oldKeyFile := filepath.Join(t.TempDir(), "old.txt")
	_ = os.WriteFile(oldKeyFile, oldPriv, 0o600)
	oldRecipient := gen1.Recipient

	// Rotate.
	if err := svc.RotateLocal(key.M.UUID, "tester"); err != nil {
		t.Fatalf("RotateLocal: %v", err)
	}
	gen2, _ := st.Keys.Get(key.M.UUID)
	if gen2.Recipient == oldRecipient {
		t.Fatal("recipient should change after rotation")
	}
	if gen2.Generation != 2 {
		t.Fatalf("generation should be 2, got %d", gen2.Generation)
	}

	// New placed key decrypts; old key no longer can.
	out, err = runSops(t, projDir, []string{"SOPS_AGE_KEY_FILE=" + placedKey}, "-d", "secrets.yaml")
	if err != nil || !strings.Contains(out, "hunter2") {
		t.Fatalf("decrypt with NEW key after rotate: out=%q err=%v", out, err)
	}
	if _, err := runSops(t, projDir, []string{"SOPS_AGE_KEY_FILE=" + oldKeyFile}, "-d", "secrets.yaml"); err == nil {
		t.Fatal("OLD key should NOT decrypt after rotation")
	}
	// .sops.yaml should no longer list the old recipient.
	if sy, _ := os.ReadFile(filepath.Join(projDir, ".sops.yaml")); strings.Contains(string(sy), oldRecipient) {
		t.Fatal(".sops.yaml still lists the retired recipient")
	}
}

func TestApplyLocalRequiresLocalMachine(t *testing.T) {
	dir := t.TempDir()
	v, _ := vault.Init(filepath.Join(dir, "vault"), "p")
	st, _ := store.Open(filepath.Join(dir, "data"), "node", nil)
	a := audit.Open(filepath.Join(dir, "audit.jsonl"), "node", nil)
	svc := New(st, v, a, "") // no local machine
	if _, err := svc.ApplyLocal("t", false); err != ErrNoLocalMachine {
		t.Fatalf("expected ErrNoLocalMachine, got %v", err)
	}
}
