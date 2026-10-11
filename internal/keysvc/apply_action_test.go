package keysvc

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sopshq/internal/model"
	"sopshq/internal/place"
	"sopshq/internal/store"
)

// actionsByKind returns the actions in rep matching one Kind, preserving order.
func actionsByKind(rep ApplyReport, kind string) []ApplyAction {
	var out []ApplyAction
	for _, a := range rep.Actions {
		if a.Kind == kind {
			out = append(out, a)
		}
	}
	return out
}

// basicLocalFixture wires one OS user, one project with a local folder, one shared
// key, and an assignment binding them on the local machine. It returns the project
// directory and the user's key-store base so a test can inspect placement results.
func basicLocalFixture(t *testing.T, svc *Service, st *store.Store, localID string) (projDir, keyBase string) {
	t.Helper()
	projDir = t.TempDir()
	keyBase = t.TempDir()

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
	return projDir, keyBase
}

// assertActionCountsMatchTotals checks the per-kind action counts line up with the
// aggregate fields, so the detailed log and the headline numbers never disagree.
func assertActionCountsMatchTotals(t *testing.T, rep ApplyReport) {
	t.Helper()
	if n := len(actionsByKind(rep, ActionKeyPlaced)); n != rep.KeysPlaced {
		t.Fatalf("key-placed actions=%d want KeysPlaced=%d", n, rep.KeysPlaced)
	}
	if n := len(actionsByKind(rep, ActionProjectWired)); n != rep.ProjectsWired {
		t.Fatalf("project-wired actions=%d want ProjectsWired=%d", n, rep.ProjectsWired)
	}
	if n := len(actionsByKind(rep, ActionSkipped)); n != len(rep.Skipped) {
		t.Fatalf("skipped actions=%d want len(Skipped)=%d", n, len(rep.Skipped))
	}
}

// TestApplyLocalActions covers the dry run and the real apply over the same
// fixture: each yields one key-placed action and one project-wired action, with
// the right Scope/Kind/Target/OK, and the per-kind counts match the totals.
func TestApplyLocalActions(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	for _, dry := range []bool{true, false} {
		dry := dry
		name := "real"
		if dry {
			name = "dry"
		}
		t.Run(name, func(t *testing.T) {
			svc, st, localID := build(t)
			projDir, keyBase := basicLocalFixture(t, svc, st, localID)

			rep, err := svc.ApplyLocal("tester", dry)
			if err != nil {
				t.Fatalf("ApplyLocal(dry=%v): %v", dry, err)
			}
			if rep.KeysPlaced != 1 || rep.ProjectsWired != 1 || rep.FilesRekeyed != 0 {
				t.Fatalf("unexpected totals: %+v", rep)
			}
			if len(rep.Skipped) != 0 {
				t.Fatalf("unexpected skips: %v", rep.Skipped)
			}
			assertActionCountsMatchTotals(t, rep)

			placed := actionsByKind(rep, ActionKeyPlaced)[0]
			if placed.Scope != scopeThisMachine || !placed.OK {
				t.Fatalf("key-placed scope/ok wrong: %+v", placed)
			}
			if placed.Target != "dev@local" {
				t.Fatalf("key-placed target = %q want dev@local", placed.Target)
			}
			wantKeyFile := place.KeyFile(keyBase)
			if !strings.Contains(placed.Detail, "app-key") || !strings.Contains(placed.Detail, wantKeyFile) || !strings.Contains(placed.Detail, "->") {
				t.Fatalf("key-placed detail = %q want name+'->'+keyfile %q", placed.Detail, wantKeyFile)
			}

			wired := actionsByKind(rep, ActionProjectWired)[0]
			if wired.Scope != scopeThisMachine || !wired.OK || wired.Target != "app" {
				t.Fatalf("project-wired scope/ok/target wrong: %+v", wired)
			}
			wantSops := filepath.Join(projDir, ".sops.yaml")
			if wired.Detail != wantSops {
				t.Fatalf("project-wired detail = %q want %q", wired.Detail, wantSops)
			}

			if dry {
				// A dry run records the same actions but writes nothing.
				if _, err := os.Stat(place.KeyFile(keyBase)); !os.IsNotExist(err) {
					t.Fatalf("dry run must not place keys.txt (stat err=%v)", err)
				}
				return
			}

			// A real apply must not leak the placed private key into any action.
			data, err := os.ReadFile(place.KeyFile(keyBase))
			if err != nil {
				t.Fatalf("read keys.txt: %v", err)
			}
			var secret string
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "AGE-SECRET-KEY-1") {
					secret = strings.TrimSpace(line)
				}
			}
			if secret == "" {
				t.Fatal("expected a private key line in keys.txt")
			}
			for _, a := range rep.Actions {
				joined := a.Scope + a.Kind + a.Target + a.Detail
				if strings.Contains(joined, secret) {
					t.Fatalf("private key leaked into action %+v", a)
				}
			}
		})
	}
}

// TestApplyLocalActionsSkip checks that an assignment whose key is not generated
// yet produces exactly one skipped action (OK=false) whose Detail equals the
// matching Skipped note, with nothing placed or wired.
func TestApplyLocalActionsSkip(t *testing.T) {
	svc, st, localID := build(t)

	proj := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: t.TempDir()}}}
	st.Projects.Put(proj)
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: t.TempDir()}
	st.OSUsers.Put(osu)
	// Key with NO recipient: never generated, so it cannot be placed.
	key := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "ungen-key", Type: model.KeyShared}
	st.Keys.Put(key)
	st.Assignments.Put(&model.Assignment{M: model.Meta{UUID: store.NewID()},
		KeyID: key.M.UUID, ProjectID: proj.M.UUID, MachineID: localID, OSUserID: osu.M.UUID})

	rep, err := svc.ApplyLocal("tester", false)
	if err != nil {
		t.Fatalf("ApplyLocal: %v", err)
	}
	if rep.KeysPlaced != 0 || rep.ProjectsWired != 0 || rep.FilesRekeyed != 0 {
		t.Fatalf("nothing should be placed/wired: %+v", rep)
	}
	assertActionCountsMatchTotals(t, rep)
	skips := actionsByKind(rep, ActionSkipped)
	if len(skips) != 1 {
		t.Fatalf("expected 1 skip action, got %d (%+v)", len(skips), skips)
	}
	s := skips[0]
	if s.OK || s.Scope != scopeThisMachine || s.Target != "ungen-key" {
		t.Fatalf("skip action ok/scope/target wrong: %+v", s)
	}
	if !strings.Contains(s.Detail, "not generated yet") {
		t.Fatalf("skip detail = %q want 'not generated yet'", s.Detail)
	}
	if len(rep.Skipped) != 1 || rep.Skipped[0] != s.Detail {
		t.Fatalf("Skipped note must mirror the action detail: %v vs %q", rep.Skipped, s.Detail)
	}
}

// TestApplyLocalActionsRekey verifies the secrets-rekeyed action: after the first
// apply wires .sops.yaml, an encrypted secret is added and a second apply re-keys
// it, recording one secrets-rekeyed action whose Detail carries the file count and
// whose count feeds FilesRekeyed.
func TestApplyLocalActionsRekey(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)
	projDir, _ := basicLocalFixture(t, svc, st, localID)

	// First apply writes .sops.yaml (no secret files yet -> no rekey action).
	first, err := svc.ApplyLocal("tester", false)
	if err != nil {
		t.Fatalf("first ApplyLocal: %v", err)
	}
	if first.FilesRekeyed != 0 || len(actionsByKind(first, ActionSecretsRekeyed)) != 0 {
		t.Fatalf("first apply should re-key nothing: %+v", first)
	}

	// Encrypt one secret against the freshly written .sops.yaml.
	if err := os.WriteFile(filepath.Join(projDir, "secrets.yaml"), []byte("password: hunter2\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	if _, err := runSops(t, projDir, nil, "-e", "-i", "secrets.yaml"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Second apply re-keys the one secret file.
	rep, err := svc.ApplyLocal("tester", false)
	if err != nil {
		t.Fatalf("second ApplyLocal: %v", err)
	}
	if rep.FilesRekeyed != 1 {
		t.Fatalf("FilesRekeyed = %d want 1", rep.FilesRekeyed)
	}
	rekeys := actionsByKind(rep, ActionSecretsRekeyed)
	if len(rekeys) != 1 {
		t.Fatalf("expected 1 secrets-rekeyed action, got %d (%+v)", len(rekeys), rekeys)
	}
	rk := rekeys[0]
	if rk.Scope != scopeThisMachine || !rk.OK || rk.Target != "app" {
		t.Fatalf("rekey scope/ok/target wrong: %+v", rk)
	}
	if rk.Detail != "1 file(s)" {
		t.Fatalf("rekey detail = %q want '1 file(s)'", rk.Detail)
	}
	// The known secret value must never reach an action string.
	for _, a := range rep.Actions {
		if strings.Contains(a.Scope+a.Kind+a.Target+a.Detail, "hunter2") {
			t.Fatalf("secret value leaked into action %+v", a)
		}
	}
}
