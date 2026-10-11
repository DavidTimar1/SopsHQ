package keysvc

import (
	"errors"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sopshq/internal/keys"
	"sopshq/internal/model"
	"sopshq/internal/stamps"
	"sopshq/internal/store"
)

// wireForGuard sets up a wired, applied project on the local machine and returns
// its id plus the on-disk project dir. The service has the external-change guard
// enabled. Requires age-keygen + sops.
func wireForGuard(t *testing.T) (*Service, string, string) {
	t.Helper()
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)
	stmp, err := stamps.Open(filepath.Join(t.TempDir(), "stamps.json"))
	if err != nil {
		t.Fatalf("stamps: %v", err)
	}
	svc.SetStamps(stmp)

	projDir := t.TempDir()
	proj := &model.Project{
		M:     model.Meta{UUID: store.NewID()},
		Name:  "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: projDir}},
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
	return svc, proj.M.UUID, projDir
}

// TestSecretExternalChangeDetectedAndAdopted is the core Path-1 flow for a
// secrets.yaml: SopsHQ records the name-set on each write; a secret added OUTSIDE
// SopsHQ is detected by NAME (never value) on the next write and blocks it; adopt
// re-stamps so the new name is tracked and the next write proceeds.
func TestSecretExternalChangeDetectedAndAdopted(t *testing.T) {
	svc, projID, projDir := wireForGuard(t)

	if err := svc.SetSecret(projID, "A", "val-a", "tester"); err != nil {
		t.Fatalf("set A: %v", err)
	}

	// Simulate an external editor adding secret B straight into secrets.yaml,
	// bypassing the guard (this is what a hand-edit looks like).
	_, priv, err := svc.resolveEditable(projID)
	if err != nil {
		t.Fatalf("resolveEditable: %v", err)
	}
	if err := keys.SetSecret(projDir, "B", "secret-b-value", priv); err != nil {
		t.Fatalf("external add B: %v", err)
	}

	// The next managed write must be refused with a non-secret diff naming B.
	err = svc.SetSecret(projID, "C", "val-c", "tester")
	var ec *ExternalChange
	if !errors.As(err, &ec) {
		t.Fatalf("expected ExternalChange, got %v", err)
	}
	if !errors.Is(err, ErrChangedExternally) {
		t.Fatalf("errors.Is(ErrChangedExternally) should match, got %v", err)
	}
	if ec.Diff.Kind != ChangeSecretsYAML {
		t.Fatalf("kind: want secrets.yaml, got %q", ec.Diff.Kind)
	}
	if got := strings.Join(ec.Diff.NamesAdded, ","); got != "B" {
		t.Fatalf("NamesAdded: want [B], got %v", ec.Diff.NamesAdded)
	}
	// The value must never appear anywhere in the diff or its error text.
	blob := strings.Join(append(append([]string{ec.Error()}, ec.Diff.NamesAdded...), ec.Diff.NamesRemoved...), " ")
	if strings.Contains(blob, "secret-b-value") {
		t.Fatalf("diff leaked a secret value: %q", blob)
	}

	// C was NOT written (the write was refused before sops ran).
	names, _ := svc.ListSecrets(projID)
	if slices.Contains(names, "C") {
		t.Fatalf("C should not have been written; names=%v", names)
	}

	// Adopt the on-disk version: re-stamp with the new name-set.
	if err := svc.ReconcileAdopt(ChangeSecretsYAML, projID, "", "tester"); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	// Now the write proceeds and B is preserved alongside the new C.
	if err := svc.SetSecret(projID, "C", "val-c", "tester"); err != nil {
		t.Fatalf("set C after adopt: %v", err)
	}
	names, _ = svc.ListSecrets(projID)
	for _, want := range []string{"A", "B", "C"} {
		if !slices.Contains(names, want) {
			t.Fatalf("after adopt+set, missing %q; names=%v", want, names)
		}
	}

	// No audit row ever carries the value.
	entries, _ := svc.audit.Recent(100)
	for _, e := range entries {
		row := strings.Join([]string{e.Actor, e.Action, e.Target, e.Detail}, " ")
		if strings.Contains(row, "secret-b-value") {
			t.Fatalf("audit leaked a secret value: %+v", e)
		}
	}
}

// TestSecretExternalChangeOverwrite confirms reconcile-overwrite re-keys the file
// (values preserved) and re-stamps, so the next write proceeds.
func TestSecretExternalChangeOverwrite(t *testing.T) {
	svc, projID, projDir := wireForGuard(t)
	if err := svc.SetSecret(projID, "A", "val-a", "tester"); err != nil {
		t.Fatalf("set A: %v", err)
	}
	_, priv, _ := svc.resolveEditable(projID)
	if err := keys.SetSecret(projDir, "D", "val-d", priv); err != nil {
		t.Fatalf("external add D: %v", err)
	}
	if err := svc.SetSecret(projID, "E", "val-e", "tester"); !errors.Is(err, ErrChangedExternally) {
		t.Fatalf("expected block, got %v", err)
	}
	if err := svc.ReconcileOverwrite(ChangeSecretsYAML, projID, "", "tester"); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	// Overwrite re-keys (values preserved), so D survives; the write now proceeds.
	if err := svc.SetSecret(projID, "E", "val-e", "tester"); err != nil {
		t.Fatalf("set E after overwrite: %v", err)
	}
	names, _ := svc.ListSecrets(projID)
	for _, want := range []string{"A", "D", "E"} {
		if !slices.Contains(names, want) {
			t.Fatalf("after overwrite, missing %q; names=%v", want, names)
		}
	}
}
