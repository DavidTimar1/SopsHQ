package keysvc

import (
	"strings"
	"testing"

	"sopshq/internal/keys"
	"sopshq/internal/model"
	"sopshq/internal/store"
)

// TestGlobalSetWithDefinedKeyAutoGenerates proves the key-lifecycle contract for the
// Global page: a per_user key OWNED by a local OS user is an eligible set candidate even
// when its keypair is not generated yet (the precondition does not block on "no
// generated key"), and building a set from it mints the keypair on use and derives the
// owner as the set's reader. It uses a deterministic fake generator so it needs no
// age-keygen binary, and confirms no private material leaks into the audit log.
func TestGlobalSetWithDefinedKeyAutoGenerates(t *testing.T) {
	svc, st, localID := build(t)
	// Deterministic keypair so the test does not depend on the age-keygen binary.
	const fakeRecipient = "age1fakerecipientvalueforthelifecycletest"
	const fakePrivate = "AGE-SECRET-KEY-1FAKEPRIVATEFORLIFECYCLETEST"
	svc.SetGenerator(func() (keys.Keypair, error) {
		return keys.Keypair{Recipient: fakeRecipient, Private: fakePrivate}, nil
	})

	// An OS user who OWNS a per_user key DEFINED only (name + type), with no keypair yet.
	u := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: t.TempDir()}
	if err := st.OSUsers.Put(u); err != nil {
		t.Fatalf("put user: %v", err)
	}
	k := &model.Key{
		M:           model.Meta{UUID: store.NewID()},
		Name:        "billing",
		Type:        model.KeyPerUser,
		OwnerUserID: u.M.UUID,
		Status:      model.KeyActive,
	}
	if err := st.Keys.Put(k); err != nil {
		t.Fatalf("put key: %v", err)
	}

	// Precondition fix: the owned per_user key is a candidate even with no keypair yet.
	cands := svc.GlobalKeyCandidates()
	if len(cands) != 1 || cands[0].KeyID != k.M.UUID || cands[0].OwnerUserID != u.M.UUID {
		t.Fatalf("candidates = %+v, want the one owned defined key", cands)
	}

	// Building the set from only that defined key succeeds, generates the keypair, and
	// makes the owner the set's reader.
	set, err := svc.CreateGlobalSet("shared", []string{k.M.UUID}, "tester")
	if err != nil {
		t.Fatalf("CreateGlobalSet with a defined owned key should succeed: %v", err)
	}
	if len(set.RecipientUserIDs) != 1 || set.RecipientUserIDs[0] != u.M.UUID {
		t.Fatalf("readers = %v, want the key owner", set.RecipientUserIDs)
	}
	got, err := st.Keys.Get(k.M.UUID)
	if err != nil || got.Recipient != fakeRecipient {
		t.Fatalf("key should be generated on use: recipient=%q err=%v", got.Recipient, err)
	}

	// The auto-generation is audited by key NAME, and no private material leaks.
	entries, _ := svc.audit.Recent(100)
	sawGen := false
	for _, e := range entries {
		blob := strings.Join([]string{e.Actor, e.Action, e.Target, e.Detail}, " ")
		if strings.Contains(blob, fakePrivate) {
			t.Fatalf("audit leaked private material: %+v", e)
		}
		if e.Action == "key_generate" && e.Target == "billing" {
			sawGen = true
		}
	}
	if !sawGen {
		t.Fatal("expected a key_generate audit entry naming the key")
	}
}

// TestEnsureGeneratedIdempotent confirms EnsureGenerated mints a keypair once and
// then leaves an already-generated key exactly as it is (no new keypair, no data
// loss) - the additive guarantee the assign/global paths rely on.
func TestEnsureGeneratedIdempotent(t *testing.T) {
	svc, st, _ := build(t)
	calls := 0
	svc.SetGenerator(func() (keys.Keypair, error) {
		calls++
		return keys.Keypair{Recipient: "age1once", Private: "AGE-SECRET-KEY-1ONCE"}, nil
	})
	k := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "k", Type: model.KeyShared, Status: model.KeyActive}
	if err := st.Keys.Put(k); err != nil {
		t.Fatalf("put key: %v", err)
	}
	if err := svc.EnsureGenerated(k.M.UUID, "tester"); err != nil {
		t.Fatalf("first EnsureGenerated: %v", err)
	}
	if err := svc.EnsureGenerated(k.M.UUID, "tester"); err != nil {
		t.Fatalf("second EnsureGenerated: %v", err)
	}
	if calls != 1 {
		t.Fatalf("generator called %d times, want exactly 1 (idempotent)", calls)
	}
	got, _ := st.Keys.Get(k.M.UUID)
	if got.Recipient != "age1once" {
		t.Fatalf("recipient = %q, want the first keypair unchanged", got.Recipient)
	}
}
