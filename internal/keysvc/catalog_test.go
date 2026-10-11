package keysvc

import (
	"os/exec"
	"strings"
	"testing"

	"sopshq/internal/model"
	"sopshq/internal/store"
)

// TestSecretsCatalogGroupsByValue wires a project, sets three secrets where two
// share one value, and confirms SecretsCatalog groups by value with correct
// counts and a value-free, name-only audit trail.
func TestSecretsCatalogGroupsByValue(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)

	proj := &model.Project{
		M:     model.Meta{UUID: store.NewID()},
		Name:  "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: t.TempDir()}},
	}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: t.TempDir()}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	if err := svc.EnsureProjectWired(proj.M.UUID, "tester"); err != nil {
		t.Fatalf("wire: %v", err)
	}

	const shared = "shared-secret-xyz"
	const unique = "unique-value-123"
	for name, val := range map[string]string{"API_A": shared, "API_B": shared, "API_C": unique} {
		if err := svc.SetSecret(proj.M.UUID, name, val, "tester"); err != nil {
			t.Fatalf("set %s: %v", name, err)
		}
	}

	groups, err := svc.SecretsCatalog("tester")
	if err != nil {
		t.Fatalf("SecretsCatalog: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 value groups, got %d: %+v", len(groups), groups)
	}
	// Most-shared first.
	if groups[0].Count != 2 || groups[1].Count != 1 {
		t.Fatalf("counts = %d,%d, want 2,1", groups[0].Count, groups[1].Count)
	}
	if got := []string{groups[0].Usages[0].Name, groups[0].Usages[1].Name}; got[0] != "API_A" || got[1] != "API_B" {
		t.Fatalf("shared-group names = %v, want [API_A API_B]", got)
	}
	if groups[0].RevealName != "API_A" || groups[0].RevealProjectID != proj.M.UUID {
		t.Fatalf("reveal representative = %s/%s", groups[0].RevealProjectID, groups[0].RevealName)
	}
	for _, u := range groups[0].Usages {
		if u.Project != "app" || u.User != "dev" {
			t.Fatalf("usage context = %+v, want project app / user dev", u)
		}
	}

	// The bulk sweep is audited by counts only; no plaintext value anywhere in the
	// audit log.
	entries, err := svc.audit.Recent(100)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	sawCatalog := false
	for _, e := range entries {
		blob := strings.Join([]string{e.Actor, e.Action, e.Target, e.Detail}, " ")
		if strings.Contains(blob, shared) || strings.Contains(blob, unique) {
			t.Fatalf("audit leaked a secret value: %+v", e)
		}
		if e.Action == "secrets_catalog" {
			sawCatalog = true
		}
	}
	if !sawCatalog {
		t.Fatal("expected a secrets_catalog audit entry")
	}
}

// TestSecretsCatalogFoldsGlobalSets confirms the catalog also sweeps local global
// sets: a global secret appears as a usage carrying the set Name + SetID and a
// blank Project, a value shared between a project and a global set groups
// together, and no plaintext value leaks into the returned structures.
func TestSecretsCatalogFoldsGlobalSets(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)

	// A wired project with one shared and one project-only secret.
	proj := &model.Project{
		M:     model.Meta{UUID: store.NewID()},
		Name:  "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: t.TempDir()}},
	}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: t.TempDir()}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	if err := svc.EnsureProjectWired(proj.M.UUID, "tester"); err != nil {
		t.Fatalf("wire: %v", err)
	}

	const shared = "shared-pg-value-xyz"
	const projOnly = "project-only-value-111"
	const globOnly = "global-only-value-222"
	if err := svc.SetSecret(proj.M.UUID, "PROJ_SHARED", shared, "tester"); err != nil {
		t.Fatalf("set PROJ_SHARED: %v", err)
	}
	if err := svc.SetSecret(proj.M.UUID, "PROJ_UNIQUE", projOnly, "tester"); err != nil {
		t.Fatalf("set PROJ_UNIQUE: %v", err)
	}

	// A global set (one recipient) with the same shared value plus a unique one.
	_, rcptKey, _, _ := userWithKey(t, svc, st, localID, "globuser", t.TempDir())
	set, err := svc.CreateGlobalSet("teamkeys", []string{rcptKey.M.UUID}, "tester")
	if err != nil {
		t.Fatalf("CreateGlobalSet: %v", err)
	}
	if err := svc.SetGlobalSecret(set.M.UUID, "GLOB_SHARED", shared, "tester"); err != nil {
		t.Fatalf("set GLOB_SHARED: %v", err)
	}
	if err := svc.SetGlobalSecret(set.M.UUID, "GLOB_UNIQUE", globOnly, "tester"); err != nil {
		t.Fatalf("set GLOB_UNIQUE: %v", err)
	}

	groups, err := svc.SecretsCatalog("tester")
	if err != nil {
		t.Fatalf("SecretsCatalog: %v", err)
	}

	// Find the shared group (count 2): one project usage + one global usage.
	var sharedGroup *SecretGroup
	var globalUsage *SecretUsage
	leakValues := []string{shared, projOnly, globOnly}
	for gi := range groups {
		g := &groups[gi]
		for ui := range g.Usages {
			u := &g.Usages[ui]
			// No structure may carry a plaintext value in any field.
			blob := strings.Join([]string{u.Project, u.GlobalSet, u.SetID, u.Name, u.Machine, u.User, u.Key, u.Path}, " ")
			for _, v := range leakValues {
				if strings.Contains(blob, v) {
					t.Fatalf("usage leaked a value %q: %+v", v, u)
				}
			}
			if u.Name == "GLOB_SHARED" {
				sharedGroup = g
				globalUsage = u
			}
		}
	}
	if globalUsage == nil {
		t.Fatal("global secret GLOB_SHARED not found in catalog")
	}
	if globalUsage.GlobalSet != "teamkeys" || globalUsage.SetID != set.M.UUID {
		t.Fatalf("global usage = %+v, want GlobalSet=teamkeys SetID=%s", globalUsage, set.M.UUID)
	}
	if globalUsage.Project != "" || globalUsage.ProjectID != "" {
		t.Fatalf("global usage should have blank project: %+v", globalUsage)
	}
	if globalUsage.User != "globuser" {
		t.Fatalf("global usage user = %q, want globuser", globalUsage.User)
	}
	if sharedGroup.Count != 2 {
		t.Fatalf("shared group count = %d, want 2 (project + global)", sharedGroup.Count)
	}
	// A shared (mixed) group's reveal representative is the PROJECT usage.
	if sharedGroup.RevealProjectID != proj.M.UUID || sharedGroup.RevealName != "PROJ_SHARED" {
		t.Fatalf("shared group rep = %s/%s, want project rep %s/PROJ_SHARED",
			sharedGroup.RevealProjectID, sharedGroup.RevealName, proj.M.UUID)
	}

	// The audit detail mentions sets by count, never a value.
	entries, _ := svc.audit.Recent(100)
	sawCatalog := false
	for _, e := range entries {
		blob := strings.Join([]string{e.Actor, e.Action, e.Target, e.Detail}, " ")
		for _, v := range leakValues {
			if strings.Contains(blob, v) {
				t.Fatalf("audit leaked a value: %+v", e)
			}
		}
		if e.Action == "secrets_catalog" && strings.Contains(e.Detail, "global set") {
			sawCatalog = true
		}
	}
	if !sawCatalog {
		t.Fatal("expected a secrets_catalog audit entry mentioning global sets")
	}
}

// TestBulkReuseSecrets copies values from existing secrets into the same project
// under new names, confirms the values round-trip, skips a name that already
// exists, and never leaks a value to the audit log.
func TestBulkReuseSecrets(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)

	proj := &model.Project{
		M:     model.Meta{UUID: store.NewID()},
		Name:  "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: t.TempDir()}},
	}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: t.TempDir()}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	if err := svc.EnsureProjectWired(proj.M.UUID, "tester"); err != nil {
		t.Fatalf("wire: %v", err)
	}
	const secret = "copy-me-please"
	if err := svc.SetSecret(proj.M.UUID, "SOURCE", secret, "tester"); err != nil {
		t.Fatalf("set source: %v", err)
	}
	if err := svc.SetSecret(proj.M.UUID, "TAKEN", "other", "tester"); err != nil {
		t.Fatalf("set taken: %v", err)
	}

	items := []ReuseItem{
		{SourceProjectID: proj.M.UUID, SourceName: "SOURCE", TargetName: "COPY"},  // ok
		{SourceProjectID: proj.M.UUID, SourceName: "SOURCE", TargetName: "TAKEN"}, // collision -> skip
	}
	added, skipped, err := svc.BulkReuseSecrets(proj.M.UUID, items, "tester")
	if err != nil {
		t.Fatalf("BulkReuseSecrets: %v", err)
	}
	if len(added) != 1 || added[0] != "COPY" {
		t.Fatalf("added = %v, want [COPY]", added)
	}
	if len(skipped) != 1 || skipped[0] != "TAKEN" {
		t.Fatalf("skipped = %v, want [TAKEN]", skipped)
	}
	// The copied value matches the source.
	got, err := svc.GetSecretValue(proj.M.UUID, "COPY")
	if err != nil || got != secret {
		t.Fatalf("COPY value = %q err=%v, want %q", got, err, secret)
	}
	// The pre-existing TAKEN was not overwritten.
	if got, _ := svc.GetSecretValue(proj.M.UUID, "TAKEN"); got != "other" {
		t.Fatalf("TAKEN was overwritten: %q", got)
	}
	// No audit entry carries the plaintext value.
	entries, _ := svc.audit.Recent(100)
	for _, e := range entries {
		if strings.Contains(strings.Join([]string{e.Actor, e.Action, e.Target, e.Detail}, " "), secret) {
			t.Fatalf("audit leaked a value: %+v", e)
		}
	}
}
