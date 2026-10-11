package main

import (
	"path/filepath"
	"testing"

	"sopshq/internal/auth"
	"sopshq/internal/model"
	"sopshq/internal/store"
	"sopshq/internal/vault"
)

// newAdminTestEnv builds a hermetic vault + plaintext store under a temp dir, so the
// recovery path can be exercised without touching any host file, env var, or registry.
func newAdminTestEnv(t *testing.T) (*vault.Vault, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	v, err := vault.Init(filepath.Join(dir, "vault"), "test-pass")
	if err != nil {
		t.Fatalf("vault init: %v", err)
	}
	st, err := store.Open(filepath.Join(dir, "data"), "test-node", nil)
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	return v, st
}

// assertRecovered checks the invariants reset-admin must always establish: the account
// is live and enabled, signs in with the new password, and has NO two-factor pending
// (enrolled flag cleared, no recovery codes, but a valid sealed secret so the fresh
// enrollment page can open it).
func assertRecovered(t *testing.T, v *vault.Vault, st *store.Store, wantUUID, wantName, newPass string) {
	t.Helper()
	got, err := st.PanelUsers.Get(wantUUID)
	if err != nil {
		t.Fatalf("account not live after recovery: %v", err)
	}
	if got.Username != wantName {
		t.Fatalf("username = %q, want exact %q (login is an exact match)", got.Username, wantName)
	}
	if !got.Enabled {
		t.Fatalf("account must be enabled")
	}
	if got.TOTPEnabled {
		t.Fatalf("two-factor must be cleared so the next sign-in is password-only")
	}
	if len(got.RecoveryCodes) != 0 {
		t.Fatalf("recovery codes must be cleared, got %d", len(got.RecoveryCodes))
	}
	if _, err := v.Open(got.TOTPSealed); err != nil {
		t.Fatalf("sealed two-factor secret must be a fresh valid seal: %v", err)
	}
	ok, err := auth.VerifyPassword(got.PassHash, newPass)
	if err != nil || !ok {
		t.Fatalf("new password must verify: ok=%v err=%v", ok, err)
	}
}

// TestResetPanelAdminRestoresTombstone is the lockout case: the operator's own login
// was soft-deleted. reset-admin must restore
// THAT record (same UUID), not create a new one.
func TestResetPanelAdminRestoresTombstone(t *testing.T) {
	v, st := newAdminTestEnv(t)

	orig := &model.PanelUser{M: model.Meta{UUID: "u-orig"}, Username: "Alice", PassHash: "old", Role: model.RoleAdmin, Enabled: true}
	if err := st.PanelUsers.Put(orig); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.PanelUsers.Delete("u-orig"); err != nil { // simulate the dedup tombstone
		t.Fatalf("tombstone: %v", err)
	}

	restored, err := resetPanelAdmin(v, st, "alice", "newpass12")
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if !restored {
		t.Fatalf("must report it restored a tombstoned account")
	}
	assertRecovered(t, v, st, "u-orig", "alice", "newpass12")
}

// TestResetPanelAdminResetsLive resets an existing live account in place (same UUID)
// and does not report a restore.
func TestResetPanelAdminResetsLive(t *testing.T) {
	v, st := newAdminTestEnv(t)

	live := &model.PanelUser{M: model.Meta{UUID: "u-live"}, Username: "admin", PassHash: "old", Role: model.RoleAdmin, Enabled: true}
	if err := st.PanelUsers.Put(live); err != nil {
		t.Fatalf("seed: %v", err)
	}

	restored, err := resetPanelAdmin(v, st, "admin", "newpass12")
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if restored {
		t.Fatalf("a live account is reset, not restored")
	}
	assertRecovered(t, v, st, "u-live", "admin", "newpass12")
}

// TestResetPanelAdminPrefersLiveOverTombstone confirms that when both a live and a
// tombstoned account share the username, reset-admin acts on the LIVE one - the record
// login resolves to - so the operator is guaranteed to get in.
func TestResetPanelAdminPrefersLiveOverTombstone(t *testing.T) {
	v, st := newAdminTestEnv(t)

	dead := &model.PanelUser{M: model.Meta{UUID: "u-dead"}, Username: "alice", PassHash: "old", Role: model.RoleAdmin, Enabled: true}
	if err := st.PanelUsers.Put(dead); err != nil {
		t.Fatalf("seed dead: %v", err)
	}
	if err := st.PanelUsers.Delete("u-dead"); err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	live := &model.PanelUser{M: model.Meta{UUID: "u-live"}, Username: "alice", PassHash: "old", Role: model.RoleAdmin, Enabled: true}
	if err := st.PanelUsers.Put(live); err != nil {
		t.Fatalf("seed live: %v", err)
	}

	restored, err := resetPanelAdmin(v, st, "alice", "newpass12")
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if restored {
		t.Fatalf("must reset the live record, not restore the tombstone")
	}
	assertRecovered(t, v, st, "u-live", "alice", "newpass12")
}

// TestResetPanelAdminCreatesWhenAbsent creates a fresh admin login when the username
// has no record at all.
func TestResetPanelAdminCreatesWhenAbsent(t *testing.T) {
	v, st := newAdminTestEnv(t)

	restored, err := resetPanelAdmin(v, st, "newguy", "newpass12")
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if restored {
		t.Fatalf("no prior record: this is a create, not a restore")
	}
	u, ok := userFind(st, "newguy")
	if !ok {
		t.Fatalf("account was not created")
	}
	if u.Role != model.RoleAdmin {
		t.Fatalf("a created recovery account must be admin, got %q", u.Role)
	}
	assertRecovered(t, v, st, u.M.UUID, "newguy", "newpass12")
}

// userFind returns the live panel account with an exact username, mirroring how the
// login handler resolves a user.
func userFind(st *store.Store, name string) (*model.PanelUser, bool) {
	u, err := st.PanelUsers.Find(func(pu *model.PanelUser) bool { return pu.Username == name })
	if err != nil {
		return nil, false
	}
	return u, true
}

// TestReadNewPanelPassword exercises the masked prompt through the promptSecret seam:
// it accepts a matching pair, and rejects a mismatch and a too-short entry.
func TestReadNewPanelPassword(t *testing.T) {
	orig := promptSecret
	defer func() { promptSecret = orig }()

	script := func(answers ...string) {
		i := 0
		promptSecret = func(string) (string, error) {
			a := answers[i]
			i++
			return a, nil
		}
	}

	script("goodpass1", "goodpass1")
	got, err := readNewPanelPassword()
	if err != nil || got != "goodpass1" {
		t.Fatalf("matching pair: got %q err %v", got, err)
	}

	script("goodpass1", "different")
	if _, err := readNewPanelPassword(); err == nil {
		t.Fatalf("mismatched confirmation must error")
	}

	script("short", "short")
	if _, err := readNewPanelPassword(); err == nil {
		t.Fatalf("too-short password must error")
	}
}
