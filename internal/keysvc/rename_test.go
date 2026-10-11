package keysvc

import (
	"errors"
	"testing"

	"sopshq/internal/model"
	"sopshq/internal/store"
)

// putKey stores a generated-looking key with the given name and returns it. It
// fills Recipient/PrivSealed so the test can assert the crypto is untouched by a
// rename.
func putKey(t *testing.T, st *store.Store, name string) *model.Key {
	t.Helper()
	k := &model.Key{
		M:          model.Meta{UUID: store.NewID()},
		Name:       name,
		Type:       model.KeyShared,
		Status:     model.KeyActive,
		Recipient:  "age1examplerecipientfor" + name,
		PrivSealed: "sealed-" + name,
		Generation: 1,
	}
	if err := st.Keys.Put(k); err != nil {
		t.Fatalf("put key %q: %v", name, err)
	}
	return k
}

// TestRenameKeySuccess: a rename changes Name while leaving the public key and the
// sealed private key byte-identical.
func TestRenameKeySuccess(t *testing.T) {
	svc, st, _ := build(t)
	k := putKey(t, st, "adopted-alice")
	rec, sealed := k.Recipient, k.PrivSealed

	if err := svc.RenameKey(k.M.UUID, "  billing  ", "tester"); err != nil {
		t.Fatalf("RenameKey: %v", err)
	}
	got, err := st.Keys.Get(k.M.UUID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "billing" {
		t.Fatalf("name = %q, want trimmed %q", got.Name, "billing")
	}
	if got.Recipient != rec || got.PrivSealed != sealed {
		t.Fatalf("rename must not touch crypto: recipient=%q privsealed=%q", got.Recipient, got.PrivSealed)
	}
}

// TestRenameKeyEmptyRejected: an empty (or whitespace-only) name is refused.
func TestRenameKeyEmptyRejected(t *testing.T) {
	svc, st, _ := build(t)
	k := putKey(t, st, "adopted-alice")
	if err := svc.RenameKey(k.M.UUID, "   ", "tester"); !errors.Is(err, ErrKeyNameEmpty) {
		t.Fatalf("expected ErrKeyNameEmpty, got %v", err)
	}
	if got, _ := st.Keys.Get(k.M.UUID); got.Name != "adopted-alice" {
		t.Fatalf("name changed on rejected rename: %q", got.Name)
	}
}

// TestRenameKeyDuplicateRejected: a name held by ANOTHER live key is refused,
// case-insensitively.
func TestRenameKeyDuplicateRejected(t *testing.T) {
	svc, st, _ := build(t)
	putKey(t, st, "billing")
	k := putKey(t, st, "adopted-alice")
	if err := svc.RenameKey(k.M.UUID, "BILLING", "tester"); !errors.Is(err, ErrKeyNameTaken) {
		t.Fatalf("expected ErrKeyNameTaken, got %v", err)
	}
	// Renaming to its OWN name (different case) is allowed - it excludes itself.
	if err := svc.RenameKey(k.M.UUID, "Adopted-Alice", "tester"); err != nil {
		t.Fatalf("self-rename should be allowed: %v", err)
	}
}

// TestRenameKeyDeletedNameReusable: a deleted (tombstoned) key's name is free to
// reuse - it is hidden by the store's List, so it does not block the rename.
func TestRenameKeyDeletedNameReusable(t *testing.T) {
	svc, st, _ := build(t)
	old := putKey(t, st, "billing")
	if err := st.Keys.Delete(old.M.UUID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	k := putKey(t, st, "adopted-alice")
	if err := svc.RenameKey(k.M.UUID, "billing", "tester"); err != nil {
		t.Fatalf("deleted key's name should be reusable: %v", err)
	}
}

// TestRenameKeyReplicates: a rename appends to the oplog so it flows to peers.
func TestRenameKeyReplicates(t *testing.T) {
	svc, st, _ := build(t)
	k := putKey(t, st, "adopted-alice")
	before, err := st.Oplog().Since(0)
	if err != nil {
		t.Fatalf("oplog since: %v", err)
	}
	if err := svc.RenameKey(k.M.UUID, "billing", "tester"); err != nil {
		t.Fatalf("RenameKey: %v", err)
	}
	after, err := st.Oplog().Since(0)
	if err != nil {
		t.Fatalf("oplog since: %v", err)
	}
	if len(after) <= len(before) {
		t.Fatalf("rename did not append to the oplog: before=%d after=%d", len(before), len(after))
	}
}
