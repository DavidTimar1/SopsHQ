package keysvc

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"sopshq/internal/model"
	"sopshq/internal/place"
	"sopshq/internal/store"
)

// TestApplyPlacesAllKeysForOneUser is the regression for the "placed key differs
// (stale?)" drift: when one OS user is assigned several project keys, Apply must
// write ALL of them into the user's keys.txt (not let each overwrite the last), and
// drift must then be clean.
func TestApplyPlacesAllKeysForOneUser(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, st, machineID := build(t)

	keyBase := t.TempDir()
	u := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: machineID, Username: "alice", KeyBase: keyBase}
	if err := st.OSUsers.Put(u); err != nil {
		t.Fatalf("osuser: %v", err)
	}

	// Two projects, two shared keys, both assigned to the SAME user.
	for _, name := range []string{"alpha", "beta"} {
		proj := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: name}
		st.Projects.Put(proj)
		key := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "key-" + name, Type: model.KeyShared}
		st.Keys.Put(key)
		if err := svc.Generate(key.M.UUID, "tester"); err != nil {
			t.Fatalf("generate %s: %v", name, err)
		}
		st.Assignments.Put(&model.Assignment{M: model.Meta{UUID: store.NewID()},
			KeyID: key.M.UUID, ProjectID: proj.M.UUID, MachineID: machineID, OSUserID: u.M.UUID})
	}

	rep, err := svc.ApplyLocal("tester", false)
	if err != nil {
		t.Fatalf("ApplyLocal: %v", err)
	}
	if rep.KeysPlaced != 2 {
		t.Fatalf("expected 2 keys placed, got %d", rep.KeysPlaced)
	}

	// keys.txt must hold BOTH private keys (count only - never print key material).
	data, err := os.ReadFile(place.KeyFile(keyBase))
	if err != nil {
		t.Fatalf("read keys.txt: %v", err)
	}
	if n := strings.Count(string(data), "AGE-SECRET-KEY-1"); n != 2 {
		t.Fatalf("expected 2 private keys in keys.txt, found %d", n)
	}

	// No placement drift should remain.
	items, err := svc.DriftLocal()
	if err != nil {
		t.Fatalf("DriftLocal: %v", err)
	}
	for _, it := range items {
		if it.Kind == "placement" {
			t.Fatalf("unexpected placement drift after apply: %+v", items)
		}
	}
}
