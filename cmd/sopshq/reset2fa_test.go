package main

import (
	"path/filepath"
	"testing"

	"sopshq/internal/auth"
	"sopshq/internal/model"
	"sopshq/internal/store"
	"sopshq/internal/vault"
)

// TestResetPanel2FAClears verifies the CLI escape hatch's core: it clears the
// target user's TOTPEnabled flag and recovery codes and rotates the sealed secret,
// so the panel routes them to fresh enrollment at next login.
func TestResetPanel2FAClears(t *testing.T) {
	dir := t.TempDir()
	v, err := vault.Init(filepath.Join(dir, "vault"), "test-pass")
	if err != nil {
		t.Fatalf("vault init: %v", err)
	}
	st, err := store.Open(filepath.Join(dir, "data"), "test-node", nil)
	if err != nil {
		t.Fatalf("store open: %v", err)
	}

	_, hashes, err := auth.GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("gen codes: %v", err)
	}
	sealed, err := v.Seal([]byte("OLDSECRET"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	u := &model.PanelUser{
		M:             model.Meta{UUID: store.NewID()},
		Username:      "alice",
		PassHash:      "x",
		TOTPSealed:    sealed,
		TOTPEnabled:   true,
		RecoveryCodes: hashes,
		Role:          model.RoleAdmin,
		Enabled:       true,
	}
	if err := st.PanelUsers.Put(u); err != nil {
		t.Fatalf("put: %v", err)
	}

	if err := resetPanel2FA(v, st, "alice"); err != nil {
		t.Fatalf("reset: %v", err)
	}

	got, err := st.PanelUsers.Get(u.M.UUID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.TOTPEnabled {
		t.Fatalf("TOTPEnabled not cleared")
	}
	if len(got.RecoveryCodes) != 0 {
		t.Fatalf("recovery codes not cleared: %d left", len(got.RecoveryCodes))
	}
	if got.TOTPSealed == sealed {
		t.Fatalf("TOTP secret was not rotated")
	}
	// The rotated secret must still open under the vault (i.e. it is a valid seal).
	if _, err := v.Open(got.TOTPSealed); err != nil {
		t.Fatalf("rotated secret does not open: %v", err)
	}

	// Unknown user is an error.
	if err := resetPanel2FA(v, st, "nobody"); err == nil {
		t.Fatalf("expected error for unknown user")
	}
}
