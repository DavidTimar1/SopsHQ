package keysvc

import (
	"os/exec"
	"testing"

	"sopshq/internal/model"
	"sopshq/internal/store"
)

// TestQuickAddValidation checks the non-destructive pre-flight blocks without any
// age/sops dependency.
func TestQuickAddValidation(t *testing.T) {
	svc, st, localID := build(t)
	u := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: t.TempDir()}
	_ = st.OSUsers.Put(u)

	// No name, no users -> blocks.
	if a := svc.ValidateQuickAdd(QuickAddInput{Scope: "project"}); !hasBlock(a) {
		t.Fatalf("expected blocks for empty input, got %v", a)
	}
	// Project scope with a valid name + user but no project/path -> blocks.
	in := QuickAddInput{Name: "API_KEY", Value: "x", Scope: "project", UserIDs: []string{u.M.UUID}}
	if a := svc.ValidateQuickAdd(in); !hasBlock(a) {
		t.Fatalf("expected block (no project/path), got %v", a)
	}
	// New project + path -> no block.
	in.NewProjectName = "app"
	in.ProjectPath = t.TempDir()
	if a := svc.ValidateQuickAdd(in); hasBlock(a) {
		t.Fatalf("expected no block, got %v", a)
	}
}

// TestQuickAddGlobalScope runs the wizard end to end for the global scope.
func TestQuickAddGlobalScope(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)
	dev, _, devPriv, _ := userWithKey(t, svc, st, localID, "dev", t.TempDir())

	in := QuickAddInput{
		Name: "OPENROUTER_API_KEY", Value: "sk-quick", Scope: "global",
		NewSetName: "apikeys", UserIDs: []string{dev.M.UUID},
	}
	if _, err := svc.RunQuickAdd(in, "tester"); err != nil {
		t.Fatalf("RunQuickAdd global: %v", err)
	}
	var setID string
	for _, s := range svc.GlobalSets() {
		if s.Name == "apikeys" {
			setID = s.M.UUID
		}
	}
	if setID == "" {
		t.Fatal("set not created")
	}
	if v, err := svc.RevealGlobalSecret(setID, "OPENROUTER_API_KEY", "tester"); err != nil || v != "sk-quick" {
		t.Fatalf("reveal = %q err=%v", v, err)
	}
	_ = devPriv
}

// TestQuickAddProjectScope runs the wizard end to end for the project scope: a new
// project + path is created, wired, applied, and the secret encrypted.
func TestQuickAddProjectScope(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)
	dev := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: t.TempDir()}
	if err := st.OSUsers.Put(dev); err != nil {
		t.Fatalf("osuser: %v", err)
	}

	in := QuickAddInput{
		Name: "DB_PASSWORD", Value: "hunter2", Scope: "project",
		NewProjectName: "webapp", ProjectPath: t.TempDir(), UserIDs: []string{dev.M.UUID},
	}
	if _, err := svc.RunQuickAdd(in, "tester"); err != nil {
		t.Fatalf("RunQuickAdd project: %v", err)
	}
	var projID string
	for _, p := range st.Projects.List() {
		if p.Name == "webapp" {
			projID = p.M.UUID
		}
	}
	if projID == "" {
		t.Fatal("project not created")
	}
	names, err := svc.ListSecrets(projID)
	if err != nil || len(names) != 1 || names[0] != "DB_PASSWORD" {
		t.Fatalf("project secrets = %v err=%v", names, err)
	}
	if got, err := svc.GetSecretValue(projID, "DB_PASSWORD"); err != nil || got != "hunter2" {
		t.Fatalf("value = %q err=%v", got, err)
	}
}
