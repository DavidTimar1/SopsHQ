package keysvc

import (
	"path/filepath"
	"testing"

	"sopshq/internal/model"
	"sopshq/internal/store"
	"sopshq/internal/usage"
)

func TestUsageAttributionByPathAndExplicitKey(t *testing.T) {
	svc, st, localID := build(t)
	svc.SetUsage(usage.Open(filepath.Join(t.TempDir(), "usage.jsonl")))

	projDir := filepath.FromSlash("/srv/app")
	proj := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "app",
		Paths: []model.ProjectPath{{MachineID: localID, Path: projDir}}}
	st.Projects.Put(proj)
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: t.TempDir()}
	st.OSUsers.Put(osu)
	key := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "app-key", Type: model.KeyShared, Recipient: "age1x"}
	st.Keys.Put(key)
	st.Assignments.Put(&model.Assignment{M: model.Meta{UUID: store.NewID()},
		KeyID: key.M.UUID, ProjectID: proj.M.UUID, MachineID: localID, OSUserID: osu.M.UUID})

	// A decrypt inside the project folder attributes to the project's key by path.
	if err := svc.RecordUse("dev", filepath.FromSlash("/srv/app/secrets.yaml"), "", "sops-shim"); err != nil {
		t.Fatalf("record: %v", err)
	}
	// A decrypt elsewhere with an explicit key_id attributes directly.
	svc.RecordUse("dev", filepath.FromSlash("/other/place.yaml"), key.M.UUID, "manual")
	// A decrypt unrelated to this key attributes to neither.
	svc.RecordUse("dev", filepath.FromSlash("/nowhere/x.yaml"), "", "sops-shim")

	u := svc.UsageForKey(key.M.UUID)
	if u.Count != 2 {
		t.Fatalf("expected 2 attributed uses, got %d", u.Count)
	}
	if u.Last == 0 {
		t.Fatal("expected a last-used time")
	}

	// A different key has no attributed usage.
	other := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "other"}
	st.Keys.Put(other)
	if svc.UsageForKey(other.M.UUID).Count != 0 {
		t.Fatal("unrelated key should have zero usage")
	}

	rec, _ := svc.RecentUsage(10)
	if len(rec) != 3 {
		t.Fatalf("expected 3 recent events, got %d", len(rec))
	}
}

func TestUsageDisabledIsNoOp(t *testing.T) {
	svc, _, _ := build(t) // no SetUsage
	if err := svc.RecordUse("u", "/p", "", "s"); err != nil {
		t.Fatalf("RecordUse without usage should be a no-op, got %v", err)
	}
	if svc.UsageForKey("anything").Count != 0 {
		t.Fatal("UsageForKey without usage should be zero")
	}
}
