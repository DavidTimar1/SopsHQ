package keysvc

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"sopshq/internal/model"
	"sopshq/internal/place"
	"sopshq/internal/store"
)

func TestDriftLocalDetectsAndClears(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, st, localID := build(t)
	projDir := t.TempDir()
	keyBase := t.TempDir()

	proj := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: projDir}}}
	st.Projects.Put(proj)
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: keyBase}
	st.OSUsers.Put(osu)
	key := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "k", Type: model.KeyShared}
	st.Keys.Put(key)
	if err := svc.Generate(key.M.UUID, "t"); err != nil {
		t.Fatalf("generate: %v", err)
	}
	st.Assignments.Put(&model.Assignment{M: model.Meta{UUID: store.NewID()},
		KeyID: key.M.UUID, ProjectID: proj.M.UUID, MachineID: localID, OSUserID: osu.M.UUID})

	if _, err := svc.ApplyLocal("t", false); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Clean after apply.
	if items, _ := svc.DriftLocal(); len(items) != 0 {
		t.Fatalf("expected no drift after apply, got %+v", items)
	}

	// Remove the placed key -> placement drift.
	os.Remove(place.KeyFile(keyBase))
	items, _ := svc.DriftLocal()
	if len(items) != 1 || items[0].Kind != "placement" {
		t.Fatalf("expected placement drift, got %+v", items)
	}

	// Re-apply fixes it.
	if _, err := svc.ApplyLocal("t", false); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if items, _ := svc.DriftLocal(); len(items) != 0 {
		t.Fatalf("re-apply should clear drift, got %+v", items)
	}

	// Hand-edit .sops.yaml recipients -> sops.yaml drift.
	os.WriteFile(filepath.Join(projDir, ".sops.yaml"), []byte("creation_rules:\n  - age: age1tampered\n"), 0o644)
	items, _ = svc.DriftLocal()
	if len(items) != 1 || items[0].Kind != "sops.yaml" {
		t.Fatalf("expected sops.yaml drift, got %+v", items)
	}
}
