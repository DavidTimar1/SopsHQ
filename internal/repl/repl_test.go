package repl

import (
	"os"
	"path/filepath"
	"testing"

	"sopshq/internal/audit"
	"sopshq/internal/model"
	"sopshq/internal/store"
	"sopshq/internal/vault"
)

// localOplog adapts a store's oplog to the OplogSource interface (an in-process
// stand-in for a peer's agent client).
type localOplog struct{ o *store.Oplog }

func (l localOplog) Oplog(since int64) ([]store.Event, error) { return l.o.Since(since) }

func newStore(t *testing.T, node string) (*store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "data"), node, nil)
	if err != nil {
		t.Fatalf("open %s: %v", node, err)
	}
	return st, dir
}

func TestPullAppliesAndAdvancesWatermark(t *testing.T) {
	a, _ := newStore(t, "A")
	b, dirB := newStore(t, "B")
	syncer := NewSyncer(b, audit.Open(filepath.Join(dirB, "audit.jsonl"), "B", nil), dirB)
	src := localOplog{a.Oplog()}

	p := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "orig"}
	if err := a.Projects.Put(p); err != nil {
		t.Fatalf("A put: %v", err)
	}
	res, err := syncer.Pull("A", "A", src)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if res.Applied != 1 {
		t.Fatalf("expected 1 applied, got %+v", res)
	}
	got, err := b.Projects.Get(p.M.UUID)
	if err != nil || got.Name != "orig" {
		t.Fatalf("B did not receive project: %v", err)
	}
	if syncer.Watermark("A") == 0 {
		t.Fatal("watermark should advance")
	}

	// Second pull with no new events does nothing.
	res, _ = syncer.Pull("A", "A", src)
	if res.Pulled != 0 || res.Applied != 0 {
		t.Fatalf("incremental pull should fetch nothing, got %+v", res)
	}

	// A edits; next pull applies the update.
	p.Name = "updated"
	a.Projects.Put(p)
	res, _ = syncer.Pull("A", "A", src)
	if res.Applied != 1 {
		t.Fatalf("expected the update to apply, got %+v", res)
	}
	got, _ = b.Projects.Get(p.M.UUID)
	if got.Name != "updated" {
		t.Fatalf("update not reflected: %q", got.Name)
	}
}

func TestPullSurfacesConflict(t *testing.T) {
	a, _ := newStore(t, "A")
	b, dirB := newStore(t, "B")
	auditLog := audit.Open(filepath.Join(dirB, "audit.jsonl"), "B", nil)
	src := localOplog{a.Oplog()}

	p := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "orig"}
	a.Projects.Put(p)
	NewSyncer(b, auditLog, dirB).Pull("A", "A", src) // B now has "orig"

	// B makes its own, newer edit.
	bp, _ := b.Projects.Get(p.M.UUID)
	bp.Name = "edited-on-B"
	b.Projects.Put(bp)

	// A fresh syncer (watermark 0) re-applies A's OLDER event -> conflict, B wins.
	fresh := NewSyncer(b, auditLog, t.TempDir())
	res, err := fresh.Pull("A", "A", src)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if res.Conflicts != 1 || res.Applied != 0 {
		t.Fatalf("expected 1 conflict, 0 applied, got %+v", res)
	}
	got, _ := b.Projects.Get(p.M.UUID)
	if got.Name != "edited-on-B" {
		t.Fatalf("B's newer edit should survive, got %q", got.Name)
	}
	// The conflict should be in the audit log.
	entries, _ := auditLog.Recent(10)
	found := false
	for _, e := range entries {
		if e.Action == "replication_conflict" {
			found = true
		}
	}
	if !found {
		t.Fatal("conflict was not surfaced in the audit log")
	}
}

func TestSealedKeyBlobReplicatesAndOpens(t *testing.T) {
	a, dirA := newStore(t, "A")
	b, dirB := newStore(t, "B")

	// Node A initializes its vault. For cross-node opening, node B must share BOTH
	// the passphrase AND the (non-secret) vault metadata (salt/iter) - this is what
	// enrollment copies. Same passphrase + DIFFERENT salt would derive a different
	// key and fail, so we copy the metadata to simulate enrollment.
	vaultDirA := filepath.Join(dirA, "vault")
	vaultDirB := filepath.Join(dirB, "vault")
	vaultA, err := vault.Init(vaultDirA, "shared-pass")
	if err != nil {
		t.Fatalf("vault A: %v", err)
	}
	if err := os.MkdirAll(vaultDirB, 0o700); err != nil {
		t.Fatalf("mkdir vault B: %v", err)
	}
	meta, err := os.ReadFile(filepath.Join(vaultDirA, "vault.json"))
	if err != nil {
		t.Fatalf("read A meta: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vaultDirB, "vault.json"), meta, 0o600); err != nil {
		t.Fatalf("write B meta: %v", err)
	}
	vaultB, err := vault.Load(vaultDirB)
	if err != nil {
		t.Fatalf("load vault B: %v", err)
	}
	if err := vaultB.Unlock("shared-pass"); err != nil {
		t.Fatalf("unlock vault B: %v", err)
	}

	secret := "AGE-SECRET-KEY-1SECRETSECRETSECRETSECRETSECRET"
	sealed, err := vaultA.Seal([]byte(secret))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	k := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "k", Type: model.KeyShared,
		Recipient: "age1xyz", PrivSealed: sealed}
	a.Projects.Put(&model.Project{M: model.Meta{UUID: store.NewID()}, Name: "p"}) // unrelated noise
	a.Keys.Put(k)

	syncer := NewSyncer(b, audit.Open(filepath.Join(dirB, "audit.jsonl"), "B", nil), dirB)
	if _, err := syncer.Pull("A", "A", localOplog{a.Oplog()}); err != nil {
		t.Fatalf("pull: %v", err)
	}

	bk, err := b.Keys.Get(k.M.UUID)
	if err != nil {
		t.Fatalf("B did not receive key: %v", err)
	}
	if bk.PrivSealed != sealed {
		t.Fatal("sealed blob changed in transit")
	}
	// B opens the replicated blob with its own (same-passphrase) vault.
	opened, err := vaultB.Open(bk.PrivSealed)
	if err != nil || string(opened) != secret {
		t.Fatalf("B could not open replicated sealed key: %v", err)
	}
}
