package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sopshq/internal/audit"
	"sopshq/internal/config"
)

// seedAudit appends raw entries (with caller-chosen timestamps) to the audit file.
func seedAudit(t *testing.T, path string, entries ...audit.Entry) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	defer f.Close()
	for _, e := range entries {
		line, _ := json.Marshal(e)
		if _, err := f.Write(append(line, '\n')); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
}

// retentionFixture writes a config with the given policy and seeds the audit log
// with one entry 20 days old and one 1 day old, returning the data dir and log.
func retentionFixture(t *testing.T, days int, action string) (string, *audit.Log) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default(filepath.Join(dir, "config.jsonc"), dir, "node")
	cfg.AuditRetention = config.AuditRetention{DaysToKeep: days, Action: action}
	if err := cfg.Save(); err != nil {
		t.Fatalf("config save: %v", err)
	}
	now := time.Now()
	logPath := filepath.Join(dir, "audit.jsonl")
	seedAudit(t, logPath,
		audit.Entry{Time: now.AddDate(0, 0, -20).Unix(), Actor: "x", Action: "ancient", Outcome: audit.OK},
		audit.Entry{Time: now.AddDate(0, 0, -1).Unix(), Actor: "x", Action: "fresh", Outcome: audit.OK},
	)
	return dir, audit.Open(logPath, "node", nil)
}

func auditHas(t *testing.T, log *audit.Log) map[string]bool {
	t.Helper()
	entries, err := log.Recent(1000)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	out := map[string]bool{}
	for _, e := range entries {
		out[e.Action] = true
	}
	return out
}

// TestEnforceAuditRetentionExportThenPurge confirms the default action archives the
// entries it removes (to <dataDir>/audit-archive) and then deletes only the entries
// on or before the cutoff.
func TestEnforceAuditRetentionExportThenPurge(t *testing.T) {
	dir, log := retentionFixture(t, 10, config.AuditActionExportThenPurge)

	removed, err := enforceAuditRetention(filepath.Join(dir, "config.jsonc"), dir, log, time.Now())
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if removed != 1 {
		t.Fatalf("expected 1 entry removed (the 20-day-old one), got %d", removed)
	}

	has := auditHas(t, log)
	if has["ancient"] {
		t.Fatal("the old entry should have been purged")
	}
	if !has["fresh"] {
		t.Fatal("the 1-day-old entry should have been kept")
	}
	if !has["audit_retention"] {
		t.Fatal("the retention purge should have been recorded")
	}

	archives, _ := filepath.Glob(filepath.Join(dir, "audit-archive", "audit-*.jsonl"))
	if len(archives) != 1 {
		t.Fatalf("expected one archive file, got %d", len(archives))
	}
	body, err := os.ReadFile(archives[0])
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	if !strings.Contains(string(body), "ancient") || strings.Contains(string(body), "fresh") {
		t.Fatalf("archive should hold only the removed (old) entry: %s", body)
	}
}

// TestEnforceAuditRetentionPurgeOnly confirms the purge action deletes without
// writing any archive.
func TestEnforceAuditRetentionPurgeOnly(t *testing.T) {
	dir, log := retentionFixture(t, 10, config.AuditActionPurge)

	removed, err := enforceAuditRetention(filepath.Join(dir, "config.jsonc"), dir, log, time.Now())
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if removed != 1 {
		t.Fatalf("expected 1 entry removed, got %d", removed)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit-archive")); !os.IsNotExist(err) {
		t.Fatal("purge-only must not create an archive directory")
	}
}

// TestEnforceAuditRetentionDisabled confirms a zero day limit is a no-op (nothing
// removed, no archive written).
func TestEnforceAuditRetentionDisabled(t *testing.T) {
	dir, log := retentionFixture(t, 0, config.AuditActionExportThenPurge)

	removed, err := enforceAuditRetention(filepath.Join(dir, "config.jsonc"), dir, log, time.Now())
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if removed != 0 {
		t.Fatalf("a zero day limit should remove nothing, got %d", removed)
	}
	if has := auditHas(t, log); !has["ancient"] || !has["fresh"] {
		t.Fatal("disabled retention must keep every entry")
	}
	if _, err := os.Stat(filepath.Join(dir, "audit-archive")); !os.IsNotExist(err) {
		t.Fatal("disabled retention must not create an archive directory")
	}
}
