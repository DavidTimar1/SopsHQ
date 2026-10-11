package keysvc

import (
	"os/exec"
	"testing"

	"sopshq/internal/keys"
	"sopshq/internal/model"
	"sopshq/internal/store"
)

// readyProject sets up a decryptable project (path + .sops.yaml + an assignment of
// the shared key) without going through wiring, so several can coexist in one test.
func readyProject(t *testing.T, svc *Service, st *store.Store, localID, name, dir string, k *model.Key) string {
	t.Helper()
	p := &model.Project{
		M:     model.Meta{UUID: store.NewID()},
		Name:  name,
		Paths: []model.ProjectPath{{MachineID: localID, Path: dir}},
	}
	if err := st.Projects.Put(p); err != nil {
		t.Fatalf("project %s: %v", name, err)
	}
	a := &model.Assignment{M: model.Meta{UUID: store.NewID()}, KeyID: k.M.UUID, ProjectID: p.M.UUID, MachineID: localID}
	if err := st.Assignments.Put(a); err != nil {
		t.Fatalf("assign %s: %v", name, err)
	}
	if err := keys.WriteSopsYAML(dir, []keys.Recipient{{Label: name, Age: k.Recipient}}); err != nil {
		t.Fatalf("sops.yaml %s: %v", name, err)
	}
	return p.M.UUID
}

// TestMassUpdateSecret confirms name+value matching across projects + a global set,
// that a same-name-different-value secret is left alone, and rename + revalue work.
func TestMassUpdateSecret(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)

	// One shared key the three projects are encrypted to.
	kp, _ := keys.Generate()
	sealed, _ := svc.vault.Seal([]byte(kp.Private))
	shared := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "shared", Type: model.KeyShared, Recipient: kp.Recipient, PrivSealed: sealed, Generation: 1, Status: model.KeyActive}
	if err := st.Keys.Put(shared); err != nil {
		t.Fatalf("key: %v", err)
	}

	webapp := readyProject(t, svc, st, localID, "webapp", t.TempDir(), shared)
	api := readyProject(t, svc, st, localID, "api", t.TempDir(), shared)
	jobs := readyProject(t, svc, st, localID, "jobs", t.TempDir(), shared)
	for _, p := range []string{webapp, api} {
		if err := svc.SetSecret(p, "OPENROUTER_API_KEY", "sk-1", "tester"); err != nil {
			t.Fatalf("set sk-1: %v", err)
		}
	}
	if err := svc.SetSecret(jobs, "OPENROUTER_API_KEY", "sk-2", "tester"); err != nil {
		t.Fatalf("set sk-2: %v", err)
	}

	// A global set that also holds the same name+value.
	_, devKey, _, _ := userWithKey(t, svc, st, localID, "dev", t.TempDir())
	set, err := svc.CreateGlobalSet("g", []string{devKey.M.UUID}, "tester")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := svc.SetGlobalSecret(set.M.UUID, "OPENROUTER_API_KEY", "sk-1", "tester"); err != nil {
		t.Fatalf("set global: %v", err)
	}

	// Find: webapp + api (projects) + g (global) - NOT jobs (sk-2).
	occ := svc.FindSecretOccurrences("OPENROUTER_API_KEY", "sk-1")
	if len(occ) != 3 {
		t.Fatalf("occurrences = %d, want 3: %+v", len(occ), occ)
	}

	// Revalue across all matches.
	for _, r := range svc.MassUpdateSecret(occ, "OPENROUTER_API_KEY", "OPENROUTER_API_KEY", "sk-NEW", "tester") {
		if !r.OK {
			t.Fatalf("update %s/%s failed: %s", r.Kind, r.Label, r.Err)
		}
	}
	for _, p := range []string{webapp, api} {
		if v, _ := svc.GetSecretValue(p, "OPENROUTER_API_KEY"); v != "sk-NEW" {
			t.Fatalf("project value = %q, want sk-NEW", v)
		}
	}
	if v, _ := svc.GetSecretValue(jobs, "OPENROUTER_API_KEY"); v != "sk-2" {
		t.Fatalf("jobs should be untouched, got %q", v)
	}
	if v, _ := svc.RevealGlobalSecret(set.M.UUID, "OPENROUTER_API_KEY", "tester"); v != "sk-NEW" {
		t.Fatalf("global value = %q, want sk-NEW", v)
	}

	// Rename across the (now sk-NEW) matches.
	occ2 := svc.FindSecretOccurrences("OPENROUTER_API_KEY", "sk-NEW")
	for _, r := range svc.MassUpdateSecret(occ2, "OPENROUTER_API_KEY", "OR_KEY", "sk-NEW", "tester") {
		if !r.OK {
			t.Fatalf("rename failed: %s", r.Err)
		}
	}
	names, _ := svc.ListSecrets(webapp)
	hasOld, hasNew := false, false
	for _, n := range names {
		if n == "OPENROUTER_API_KEY" {
			hasOld = true
		}
		if n == "OR_KEY" {
			hasNew = true
		}
	}
	if hasOld || !hasNew {
		t.Fatalf("after rename: names=%v (old present=%v, new present=%v)", names, hasOld, hasNew)
	}
}
