package keysvc

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sopshq/internal/keys"
	"sopshq/internal/model"
	"sopshq/internal/store"
)

// userWithKey creates a local OS user who OWNS a generated per_user key (sealed in the
// vault), the shape a key-based global set is built from. Returns the user, the owned
// key, its private key, and its recipient.
func userWithKey(t *testing.T, svc *Service, st *store.Store, localID, username, keyBase string) (*model.OSUser, *model.Key, string, string) {
	t.Helper()
	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate %s: %v", username, err)
	}
	sealed, err := svc.vault.Seal([]byte(kp.Private))
	if err != nil {
		t.Fatalf("seal %s: %v", username, err)
	}
	u := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: username, KeyBase: keyBase}
	if err := st.OSUsers.Put(u); err != nil {
		t.Fatalf("put user: %v", err)
	}
	k := &model.Key{
		M: model.Meta{UUID: store.NewID()}, Name: "k-" + username, Type: model.KeyPerUser,
		OwnerUserID: u.M.UUID,
		Recipient:   kp.Recipient, PrivSealed: sealed, Generation: 1, Status: model.KeyActive,
	}
	if err := st.Keys.Put(k); err != nil {
		t.Fatalf("put key: %v", err)
	}
	return u, k, kp.Private, kp.Recipient
}

// TestSharedGlobalSecretMultiRecipient creates a set encrypted to two users and
// confirms EACH user's own key decrypts their own copy - the core multi-recipient
// guarantee - and that no value leaks to disk plaintext or the audit log.
func TestSharedGlobalSecretMultiRecipient(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	svc, st, localID := build(t)

	devBase, ciBase := t.TempDir(), t.TempDir()
	dev, devKey, devPriv, _ := userWithKey(t, svc, st, localID, "dev", devBase)
	ci, ciKey, ciPriv, _ := userWithKey(t, svc, st, localID, "ci", ciBase)

	// Both owned per_user keys are global-set candidates, shown as key name + owner.
	cands := svc.GlobalKeyCandidates()
	if len(cands) != 2 {
		t.Fatalf("candidates = %d, want 2: %+v", len(cands), cands)
	}

	// Build the set by SELECTING the two owned keys.
	set, err := svc.CreateGlobalSet("apikeys", []string{devKey.M.UUID, ciKey.M.UUID}, "tester")
	if err != nil {
		t.Fatalf("CreateGlobalSet: %v", err)
	}
	// RecipientUserIDs derive from the selected keys' owners.
	gotOwners := map[string]bool{}
	for _, id := range set.RecipientUserIDs {
		gotOwners[id] = true
	}
	if len(set.RecipientUserIDs) != 2 || !gotOwners[dev.M.UUID] || !gotOwners[ci.M.UUID] {
		t.Fatalf("readers = %v, want dev+ci owners", set.RecipientUserIDs)
	}

	const val = "sk-shared-xyz"
	if err := svc.SetGlobalSecret(set.M.UUID, "OPENROUTER_API_KEY", val, "tester"); err != nil {
		t.Fatalf("SetGlobalSecret: %v", err)
	}

	devDir := filepath.Join(devBase, "global", "apikeys")
	ciDir := filepath.Join(ciBase, "global", "apikeys")

	// Both recipients have a copy, and EACH decrypts with their OWN key.
	for _, c := range []struct {
		dir, priv, who string
	}{{devDir, devPriv, "dev"}, {ciDir, ciPriv, "ci"}} {
		if _, err := os.Stat(filepath.Join(c.dir, "secrets.yaml")); err != nil {
			t.Fatalf("%s copy missing: %v", c.who, err)
		}
		got, err := keys.GetSecretValue(c.dir, "OPENROUTER_API_KEY", c.priv)
		if err != nil || got != val {
			t.Fatalf("%s decrypt with own key = %q err=%v, want %q", c.who, got, err, val)
		}
		raw, _ := os.ReadFile(filepath.Join(c.dir, "secrets.yaml"))
		if strings.Contains(string(raw), val) {
			t.Fatalf("%s copy has plaintext value at rest", c.who)
		}
	}

	// Service-level list/reveal/delete round-trip.
	if names, err := svc.ListGlobalSecrets(set.M.UUID); err != nil || len(names) != 1 || names[0] != "OPENROUTER_API_KEY" {
		t.Fatalf("list = %v err=%v", names, err)
	}
	if v, err := svc.RevealGlobalSecret(set.M.UUID, "OPENROUTER_API_KEY", "tester"); err != nil || v != val {
		t.Fatalf("reveal = %q err=%v", v, err)
	}
	if err := svc.DeleteGlobalSecret(set.M.UUID, "OPENROUTER_API_KEY", "tester"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if names, _ := svc.ListGlobalSecrets(set.M.UUID); len(names) != 0 {
		t.Fatalf("after delete: %v", names)
	}
	// The delete synced to the ci copy too (now empty).
	if n, _ := keys.ListSecretNames(ciDir, ciPriv); len(n) != 0 {
		t.Fatalf("ci copy not synced after delete: %v", n)
	}

	// Validation + audit hygiene.
	if _, err := svc.CreateGlobalSet("apikeys", []string{devKey.M.UUID}, "tester"); err != ErrSetExists {
		t.Fatalf("expected ErrSetExists, got %v", err)
	}
	if _, err := svc.CreateGlobalSet("bad name!", []string{devKey.M.UUID}, "tester"); err != ErrBadSetName {
		t.Fatalf("expected ErrBadSetName, got %v", err)
	}
	if _, err := svc.CreateGlobalSet("empty", nil, "tester"); err != ErrNoRecipients {
		t.Fatalf("expected ErrNoRecipients, got %v", err)
	}
	// A shared key cannot build a set (it has no single owner reader).
	shared := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "shared-x", Type: model.KeyShared, Status: model.KeyActive}
	if err := st.Keys.Put(shared); err != nil {
		t.Fatalf("put shared key: %v", err)
	}
	if _, err := svc.CreateGlobalSet("sharedset", []string{shared.M.UUID}, "tester"); !errors.Is(err, ErrKeyNotPerUser) {
		t.Fatalf("expected ErrKeyNotPerUser, got %v", err)
	}
	entries, _ := svc.audit.Recent(100)
	for _, e := range entries {
		if strings.Contains(strings.Join([]string{e.Actor, e.Action, e.Target, e.Detail}, " "), val) {
			t.Fatalf("audit leaked a value: %+v", e)
		}
	}
}
