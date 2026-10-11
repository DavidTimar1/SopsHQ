package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultGeneratesIdentityAndRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.jsonc")
	c := Default(path, dir, "win-dev")
	if c.NodeID == "" {
		t.Fatal("Default must generate a node id")
	}
	if c.NodeName != "win-dev" {
		t.Fatalf("node name = %q, want win-dev", c.NodeName)
	}
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.NodeID != c.NodeID {
		t.Fatalf("node id not stable across save/load: %q vs %q", got.NodeID, c.NodeID)
	}
	if got.DataDir != c.DataDir {
		t.Fatalf("data dir mismatch: %q vs %q", got.DataDir, c.DataDir)
	}
}

func TestLoadStripsJSONCComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.jsonc")
	doc := `{
  // this is the stable machine id
  "node_id": "abc-123",
  "node_name": "linux-server", /* inline block */
  "data_dir": "/var/lib/sopshq/data",
  "vault_dir": "/var/lib/sopshq/data",
  "panel_listen": "127.0.0.1:8080",
  // a comment containing a // and a "quote" and /* not really a block */
  "agent_listen": "100.64.0.2:8443"
}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.NodeID != "abc-123" || c.NodeName != "linux-server" {
		t.Fatalf("parsed fields wrong: %+v", c)
	}
	if c.AgentListen != "100.64.0.2:8443" {
		t.Fatalf("agent_listen parse wrong: %+v", c)
	}
}

func TestStripJSONCKeepsCommentMarkersInsideStrings(t *testing.T) {
	in := []byte(`{"url": "https://example.com/path", "note": "a /* b */ // c"}`)
	out := stripJSONC(in)
	if string(out) != string(in) {
		t.Fatalf("string contents altered: %q", out)
	}
}

func TestLoadMissingReturnsErrNotFound(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.jsonc")); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// TestAuditRetentionDefaultAndRoundTrip confirms Default seeds the safer policy
// (keep forever, export-then-purge) and that an explicit policy survives Save/Load.
func TestAuditRetentionDefaultAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.jsonc")
	c := Default(path, dir, "win-dev")
	if c.AuditRetention.DaysToKeep != 0 || c.AuditRetention.Action != AuditActionExportThenPurge {
		t.Fatalf("default retention = %+v, want days=0 action=%q", c.AuditRetention, AuditActionExportThenPurge)
	}
	c.AuditRetention.DaysToKeep = 30
	c.AuditRetention.Action = AuditActionPurge
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.AuditRetention.DaysToKeep != 30 || got.AuditRetention.Action != AuditActionPurge {
		t.Fatalf("retention did not round-trip: %+v", got.AuditRetention)
	}
}

// TestAuditRetentionValidateRejectsBadValues confirms a negative day count and an
// unknown action are rejected at Load, while an empty action (treated as the
// default) is accepted.
func TestAuditRetentionValidateRejectsBadValues(t *testing.T) {
	base := `{
  "node_id": "abc-123",
  "node_name": "n",
  "data_dir": "/d",
  "vault_dir": "/d",
  "panel_listen": "127.0.0.1:8770",
  "agent_listen": "127.0.0.1:8443",
  "audit_retention": { "days_to_keep": %d, "action": %q }
}`
	write := func(t *testing.T, days int, action string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.jsonc")
		doc := []byte(fmt.Sprintf(base, days, action))
		if err := os.WriteFile(path, doc, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		return path
	}

	if _, err := Load(write(t, -1, AuditActionPurge)); err == nil {
		t.Fatal("a negative days_to_keep should be rejected")
	}
	if _, err := Load(write(t, 5, "shred")); err == nil {
		t.Fatal("an unknown action should be rejected")
	}
	if _, err := Load(write(t, 5, "")); err != nil {
		t.Fatalf("an empty action should be accepted (default): %v", err)
	}
}

// TestKeybaseRootValidation confirms keybase_root round-trips when set to an
// absolute path distinct from data_dir, is rejected when relative, and is rejected
// when it equals data_dir (the two must be separate folders).
func TestKeybaseRootValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.jsonc")
	c := Default(path, dir, "dev")
	c.KeybaseRoot = filepath.Join(dir, "keys")
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.KeybaseRoot != c.KeybaseRoot {
		t.Fatalf("keybase_root did not round-trip: %q vs %q", got.KeybaseRoot, c.KeybaseRoot)
	}

	relPath := filepath.Join(t.TempDir(), "config.jsonc")
	rel := Default(relPath, dir, "dev")
	rel.KeybaseRoot = "relative/keys"
	if err := rel.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := Load(relPath); err == nil {
		t.Fatal("a relative keybase_root should be rejected")
	}

	samePath := filepath.Join(t.TempDir(), "config.jsonc")
	same := Default(samePath, dir, "dev")
	same.KeybaseRoot = same.DataDir
	if err := same.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := Load(samePath); err == nil {
		t.Fatal("keybase_root equal to data_dir should be rejected")
	}
}
