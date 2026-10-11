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
	"sopshq/internal/stamps"
	"sopshq/internal/store"
)

// applyWiredProject builds a project wired to one generated key on the local
// machine, applies it (placing the key and writing .sops.yaml), and returns the
// service, project dir, and the key store dir. It skips when age-keygen/sops are
// absent.
func applyWiredProject(t *testing.T) (svc *Service, st *store.Store, localID, projID, projDir, keyBase string) {
	t.Helper()
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID = build(t)
	projDir = t.TempDir()
	keyBase = t.TempDir()
	proj := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: projDir}}}
	st.Projects.Put(proj)
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: keyBase}
	st.OSUsers.Put(osu)
	key := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "app-key", Type: model.KeyShared}
	st.Keys.Put(key)
	if err := svc.Generate(key.M.UUID, "t"); err != nil {
		t.Fatalf("generate: %v", err)
	}
	st.Assignments.Put(&model.Assignment{M: model.Meta{UUID: store.NewID()},
		KeyID: key.M.UUID, ProjectID: proj.M.UUID, MachineID: localID, OSUserID: osu.M.UUID})
	if _, err := svc.ApplyLocal("t", false); err != nil {
		t.Fatalf("apply: %v", err)
	}
	return svc, st, localID, proj.M.UUID, projDir, keyBase
}

// TestDriftDetailNamesExactKey checks the .sops.yaml drift Detail names the exact
// missing/extra public key (by name where known) instead of a vague "differ".
func TestDriftDetailNamesExactKey(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, _, _ := build(t)
	projDir := t.TempDir()
	localID := svc.localMachineID
	proj := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: projDir}}}
	svc.store.Projects.Put(proj)
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: t.TempDir()}
	svc.store.OSUsers.Put(osu)
	key := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "app-key", Type: model.KeyShared}
	svc.store.Keys.Put(key)
	if err := svc.Generate(key.M.UUID, "t"); err != nil {
		t.Fatalf("generate: %v", err)
	}
	svc.store.Assignments.Put(&model.Assignment{M: model.Meta{UUID: store.NewID()},
		KeyID: key.M.UUID, ProjectID: proj.M.UUID, MachineID: localID, OSUserID: osu.M.UUID})

	// A .sops.yaml on disk that lists a DIFFERENT public key: the project's own key is
	// missing and an unknown extra key is present. The "age:" line is on its own line,
	// as SopsHQ writes it, so it parses.
	extra := "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsx0dpz"
	os.WriteFile(filepath.Join(projDir, ".sops.yaml"),
		[]byte("creation_rules:\n  - path_regex: secrets.*\\.ya?ml$\n    age: "+extra+"\n"), 0o644)

	items, err := svc.DriftLocal()
	if err != nil {
		t.Fatalf("DriftLocal: %v", err)
	}
	var sops *DriftItem
	for i := range items {
		if items[i].Kind == "sops.yaml" {
			sops = &items[i]
		}
	}
	if sops == nil {
		t.Fatalf("expected a sops.yaml drift, got %+v", items)
	}
	d := sops.Detail
	if strings.Contains(d, "differ") {
		t.Fatalf("Detail should not be vague; got %q", d)
	}
	if !strings.Contains(d, "public key 'app-key'") {
		t.Fatalf("Detail should name the missing key by name; got %q", d)
	}
	if !strings.Contains(d, "does not include") {
		t.Fatalf("Detail should call out the extra public key; got %q", d)
	}
	if len(sops.ExtraOnDisk) != 1 || sops.ExtraOnDisk[0] != extra {
		t.Fatalf("ExtraOnDisk should name the extra key; got %v", sops.ExtraOnDisk)
	}
}

// TestAdoptReadersKeepsBothKeys wires a project to key A, then plants a SECOND
// identity B as an extra public key on disk (its private key in the local key
// store). "Adopt readers" must clear the drift AND keep B able to decrypt.
func TestAdoptReadersKeepsBothKeys(t *testing.T) {
	svc, _, _, projID, projDir, keyBase := applyWiredProject(t)

	// A real second identity B.
	bKp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate B: %v", err)
	}
	// Put B's private into dev's local key store (dev now holds A and B).
	storePath := place.KeyFile(keyBase)
	cur, _ := os.ReadFile(storePath)
	os.WriteFile(storePath, append(append([]byte(nil), cur...), []byte("\n"+bKp.Private+"\n")...), 0o600)

	// Encrypt a secret (to A only, per the applied .sops.yaml).
	os.WriteFile(filepath.Join(projDir, "secrets.yaml"), []byte("password: hunter2\n"), 0o600)
	if _, err := runSops(t, projDir, nil, "-e", "-i", "secrets.yaml"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Hand-add B as an extra public key on disk -> drift.
	sy, _ := os.ReadFile(filepath.Join(projDir, ".sops.yaml"))
	edited := strings.Replace(string(sy), "age: ", "age: "+bKp.Recipient+",", 1)
	os.WriteFile(filepath.Join(projDir, ".sops.yaml"), []byte(edited), 0o644)
	if items, _ := svc.DriftLocal(); len(items) == 0 {
		t.Fatal("expected drift after planting the extra public key")
	}

	// Adopt readers: B is taken into custody, assigned, and secrets re-keyed to A+B.
	if err := svc.AdoptReaders(projID, "t"); err != nil {
		t.Fatalf("AdoptReaders: %v", err)
	}
	if items, _ := svc.DriftLocal(); len(items) != 0 {
		t.Fatalf("drift should clear after adopt, got %+v", items)
	}

	// B alone must decrypt (proves no reader was dropped).
	bFile := filepath.Join(t.TempDir(), "b.txt")
	os.WriteFile(bFile, []byte(bKp.Private+"\n"), 0o600)
	out, err := runSops(t, projDir, []string{"SOPS_AGE_KEY_FILE=" + bFile}, "-d", "secrets.yaml")
	if err != nil || !strings.Contains(out, "hunter2") {
		t.Fatalf("B should still decrypt after adopt: out=%q err=%v", out, err)
	}
}

// TestRekeyToDesiredDropsExtra wires a project to key A, plants an extra public key
// B on disk, then "Re-key to desired" must drop B (B can no longer decrypt) while A
// still can, and the drift clears.
func TestRekeyToDesiredDropsExtra(t *testing.T) {
	svc, _, _, projID, projDir, keyBase := applyWiredProject(t)

	bKp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate B: %v", err)
	}

	os.WriteFile(filepath.Join(projDir, "secrets.yaml"), []byte("password: hunter2\n"), 0o600)
	if _, err := runSops(t, projDir, nil, "-e", "-i", "secrets.yaml"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Add B on disk and re-key the secret to A+B, so B can currently decrypt.
	sy, _ := os.ReadFile(filepath.Join(projDir, ".sops.yaml"))
	edited := strings.Replace(string(sy), "age: ", "age: "+bKp.Recipient+",", 1)
	os.WriteFile(filepath.Join(projDir, ".sops.yaml"), []byte(edited), 0o644)
	if _, err := runSops(t, projDir, []string{"SOPS_AGE_KEY_FILE=" + place.KeyFile(keyBase)}, "updatekeys", "-y", "secrets.yaml"); err != nil {
		t.Fatalf("updatekeys to A+B: %v", err)
	}

	items, _ := svc.DriftLocal()
	if len(items) != 1 || len(items[0].ExtraOnDisk) != 1 || items[0].ExtraOnDisk[0] != bKp.Recipient {
		t.Fatalf("drift should name the extra public key B; got %+v", items)
	}

	// Re-key to desired: B is dropped.
	if err := svc.RekeyToDesired(projID, "t"); err != nil {
		t.Fatalf("RekeyToDesired: %v", err)
	}
	if items, _ := svc.DriftLocal(); len(items) != 0 {
		t.Fatalf("drift should clear after re-key, got %+v", items)
	}
	// B can no longer decrypt; A still can.
	bFile := filepath.Join(t.TempDir(), "b.txt")
	os.WriteFile(bFile, []byte(bKp.Private+"\n"), 0o600)
	if _, err := runSops(t, projDir, []string{"SOPS_AGE_KEY_FILE=" + bFile}, "-d", "secrets.yaml"); err == nil {
		t.Fatal("B should NOT decrypt after re-key to desired")
	}
	out, err := runSops(t, projDir, []string{"SOPS_AGE_KEY_FILE=" + place.KeyFile(keyBase)}, "-d", "secrets.yaml")
	if err != nil || !strings.Contains(out, "hunter2") {
		t.Fatalf("A should still decrypt after re-key: out=%q err=%v", out, err)
	}
}

// TestMoveLocalPathMovesManagedSops changes a project's local folder and checks the
// SopsHQ-managed .sops.yaml moves to the new folder byte-for-byte, is removed from
// the old folder, and the drift clears.
func TestMoveLocalPathMovesManagedSops(t *testing.T) {
	svc, _, _, projID, projDir, _ := applyWiredProject(t)
	stmp, err := stamps.Open(filepath.Join(t.TempDir(), "stamps.json"))
	if err != nil {
		t.Fatalf("stamps: %v", err)
	}
	svc.SetStamps(stmp)
	// Re-apply so the managed .sops.yaml is stamped by this stamp store.
	if _, err := svc.ApplyLocal("t", false); err != nil {
		t.Fatalf("re-apply to stamp: %v", err)
	}
	oldSops := filepath.Join(projDir, ".sops.yaml")
	orig, err := os.ReadFile(oldSops)
	if err != nil {
		t.Fatalf("read old .sops.yaml: %v", err)
	}

	newDir := t.TempDir()
	if err := svc.MoveLocalPath(projID, newDir, "t"); err != nil {
		t.Fatalf("MoveLocalPath: %v", err)
	}
	if _, err := os.Stat(oldSops); !os.IsNotExist(err) {
		t.Fatalf("old .sops.yaml should be gone, stat err=%v", err)
	}
	moved, err := os.ReadFile(filepath.Join(newDir, ".sops.yaml"))
	if err != nil {
		t.Fatalf("new .sops.yaml missing: %v", err)
	}
	if string(moved) != string(orig) {
		t.Fatal("moved .sops.yaml was regenerated, not byte-preserved")
	}
	p, _ := svc.store.Projects.Get(projID)
	if svc.localProjectPath(p) != newDir {
		t.Fatalf("record path not updated to new folder; got %q", svc.localProjectPath(p))
	}
	if items, _ := svc.DriftLocal(); len(items) != 0 {
		t.Fatalf("drift should be clear after the move, got %+v", items)
	}
}

// TestMoveLocalPathBlocksDestSecretsOverwrite checks a folder move REFUSES (with no
// destructive step) when a DIFFERENT secrets.yaml already sits at the new folder, so
// its unrelated encrypted data is never clobbered.
func TestMoveLocalPathBlocksDestSecretsOverwrite(t *testing.T) {
	svc, _, _, projID, projDir, _ := applyWiredProject(t)
	stmp, err := stamps.Open(filepath.Join(t.TempDir(), "stamps.json"))
	if err != nil {
		t.Fatalf("stamps: %v", err)
	}
	svc.SetStamps(stmp)
	if _, err := svc.ApplyLocal("t", false); err != nil {
		t.Fatalf("re-apply to stamp: %v", err)
	}
	// A SopsHQ-tracked secrets.yaml at the old folder.
	if err := svc.SetSecret(projID, "A", "val-a", "t"); err != nil {
		t.Fatalf("set secret: %v", err)
	}
	oldSops := filepath.Join(projDir, ".sops.yaml")
	oldSecrets := filepath.Join(projDir, "secrets.yaml")

	// A DIFFERENT, unrelated secrets.yaml already at the new folder.
	newDir := t.TempDir()
	unrelated := []byte("unrelated: keep-me\n")
	newSecrets := filepath.Join(newDir, "secrets.yaml")
	os.WriteFile(newSecrets, unrelated, 0o600)

	err = svc.MoveLocalPath(projID, newDir, "t")
	if err == nil || !strings.Contains(err.Error(), "secrets.yaml") {
		t.Fatalf("move should be refused over a different dest secrets.yaml; got %v", err)
	}
	// Nothing moved or removed.
	if _, e := os.Stat(oldSops); e != nil {
		t.Fatalf("old .sops.yaml should remain; err=%v", e)
	}
	if _, e := os.Stat(oldSecrets); e != nil {
		t.Fatalf("old secrets.yaml should remain; err=%v", e)
	}
	if got, _ := os.ReadFile(newSecrets); string(got) != string(unrelated) {
		t.Fatal("dest secrets.yaml was overwritten")
	}
	if _, e := os.Stat(filepath.Join(newDir, ".sops.yaml")); !os.IsNotExist(e) {
		t.Fatalf("no .sops.yaml should have been written at the new folder; err=%v", e)
	}
	p, _ := svc.store.Projects.Get(projID)
	if svc.localProjectPath(p) != projDir {
		t.Fatalf("record path should be unchanged after a refused move; got %q", svc.localProjectPath(p))
	}
}

// TestAdoptReadersFailsClosed checks AdoptReaders refuses (changing nothing) when the
// on-disk state SIGNALS public keys but none can be harvested, so it never re-keys
// WITHOUT a reader and locks them out.
func TestAdoptReadersFailsClosed(t *testing.T) {
	svc, st, localID := build(t)
	dir := t.TempDir()
	proj := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: dir}}}
	st.Projects.Put(proj)

	// Signals public keys ("age:") but no harvestable age1 token (a format SopsHQ
	// cannot read).
	garbage := []byte("creation_rules:\n  - path_regex: secrets.*\\.ya?ml$\n    age: >-\n      folded-unreadable\n")
	sopsPath := filepath.Join(dir, ".sops.yaml")
	os.WriteFile(sopsPath, garbage, 0o644)

	err := svc.AdoptReaders(proj.M.UUID, "t")
	if err == nil || !strings.Contains(err.Error(), "existing public keys") {
		t.Fatalf("AdoptReaders should fail closed; got %v", err)
	}
	if got, _ := os.ReadFile(sopsPath); string(got) != string(garbage) {
		t.Fatal("AdoptReaders must not rewrite when it fails closed")
	}
}

// TestMoveLocalPathLeavesHandAuthored checks a hand-authored .sops.yaml (no SopsHQ
// header) is NEVER moved or deleted by a folder change.
func TestMoveLocalPathLeavesHandAuthored(t *testing.T) {
	svc, st, localID := build(t)
	stmp, err := stamps.Open(filepath.Join(t.TempDir(), "stamps.json"))
	if err != nil {
		t.Fatalf("stamps: %v", err)
	}
	svc.SetStamps(stmp)
	oldDir := t.TempDir()
	proj := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: oldDir}}}
	st.Projects.Put(proj)

	hand := []byte("creation_rules:\n  - age: age1handauthored\n")
	oldSops := filepath.Join(oldDir, ".sops.yaml")
	os.WriteFile(oldSops, hand, 0o644)

	newDir := t.TempDir()
	if err := svc.MoveLocalPath(proj.M.UUID, newDir, "t"); err != nil {
		t.Fatalf("MoveLocalPath: %v", err)
	}
	got, err := os.ReadFile(oldSops)
	if err != nil {
		t.Fatalf("hand-authored .sops.yaml must stay in place, read err=%v", err)
	}
	if string(got) != string(hand) {
		t.Fatal("hand-authored .sops.yaml was modified")
	}
	if _, err := os.Stat(filepath.Join(newDir, ".sops.yaml")); !os.IsNotExist(err) {
		t.Fatal("hand-authored .sops.yaml must not be copied to the new folder")
	}
}
