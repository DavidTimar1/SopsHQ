package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"sopshq/internal/audit"
	"sopshq/internal/config"
	"sopshq/internal/totp"
)

// appendAuditEntries appends raw entries (with caller-chosen timestamps) directly to
// the audit JSONL file, so a test can seed history that predates "now".
func appendAuditEntries(t *testing.T, path string, entries ...audit.Entry) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open audit file: %v", err)
	}
	defer f.Close()
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal entry: %v", err)
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	}
}

// auditActions returns the set of entry actions currently in the log.
func auditActions(t *testing.T, srv *Server) map[string]bool {
	t.Helper()
	entries, err := srv.audit.Recent(10000)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	out := make(map[string]bool, len(entries))
	for _, e := range entries {
		out[e.Action] = true
	}
	return out
}

// TestPurgeAllAuditEmptiesLog confirms /audit/purge-all clears prior history; the
// only entry left is the purge record PurgeAllBy writes for the trail.
func TestPurgeAllAuditEmptiesLog(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	if err := srv.audit.Record("admin", "seed_marker", "x", audit.OK, ""); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if n, _ := srv.audit.Count(); n == 0 {
		t.Fatal("expected a non-empty audit log before purge")
	}

	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/audit"), "csrf")
	resp, err := c.PostForm(ts.URL+"/audit/purge-all", url.Values{"csrf": {csrf}})
	if err != nil {
		t.Fatalf("purge-all: %v", err)
	}
	resp.Body.Close()

	n, err := srv.audit.Count()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("after purge-all expected only the purge record (count 1), got %d", n)
	}
	if acts := auditActions(t, srv); acts["seed_marker"] || !acts["audit_purge_all"] {
		t.Fatalf("purge-all did not clear prior history / record itself: %v", acts)
	}
}

// TestPurgeAuditBeforeRemovesOnlyOnOrBeforeCutoff confirms /audit/purge-before
// removes entries on or before the chosen day and keeps newer ones.
func TestPurgeAuditBeforeRemovesOnlyOnOrBeforeCutoff(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	old := audit.Entry{Time: time.Date(2020, 1, 1, 12, 0, 0, 0, time.Local).Unix(), Actor: "x", Action: "ancient", Outcome: audit.OK}
	recent := audit.Entry{Time: time.Now().Unix(), Actor: "x", Action: "fresh", Outcome: audit.OK}
	appendAuditEntries(t, srv.audit.Path(), old, recent)

	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/audit"), "csrf")
	resp, err := c.PostForm(ts.URL+"/audit/purge-before", url.Values{
		"csrf": {csrf}, "date": {"2020-06-30"},
	})
	if err != nil {
		t.Fatalf("purge-before: %v", err)
	}
	resp.Body.Close()

	acts := auditActions(t, srv)
	if acts["ancient"] {
		t.Fatal("an entry on or before the cutoff should have been removed")
	}
	if !acts["fresh"] {
		t.Fatal("an entry after the cutoff should have been kept")
	}
	if !acts["audit_purge_before"] {
		t.Fatal("the purge should have been recorded")
	}
}

// TestSaveRetentionPersists confirms /settings/retention writes the policy to
// config.jsonc (in memory and on disk) and that an unknown action falls back to the
// safer export-then-purge default.
func TestSaveRetentionPersists(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")
	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/settings"), "csrf")

	resp, err := c.PostForm(ts.URL+"/settings/retention", url.Values{
		"csrf": {csrf}, "days_to_keep": {"30"}, "action": {"purge"},
	})
	if err != nil {
		t.Fatalf("save retention: %v", err)
	}
	resp.Body.Close()

	if srv.cfg.AuditRetention.DaysToKeep != 30 || srv.cfg.AuditRetention.Action != config.AuditActionPurge {
		t.Fatalf("in-memory retention not updated: %+v", srv.cfg.AuditRetention)
	}
	got, err := config.Load(srv.cfg.Path())
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if got.AuditRetention.DaysToKeep != 30 || got.AuditRetention.Action != config.AuditActionPurge {
		t.Fatalf("on-disk retention not persisted: %+v", got.AuditRetention)
	}

	// An unknown action is coerced to the safer default.
	resp, err = c.PostForm(ts.URL+"/settings/retention", url.Values{
		"csrf": {csrf}, "days_to_keep": {"7"}, "action": {"shred"},
	})
	if err != nil {
		t.Fatalf("save retention 2: %v", err)
	}
	resp.Body.Close()
	if srv.cfg.AuditRetention.Action != config.AuditActionExportThenPurge {
		t.Fatalf("unknown action should fall back to export_then_purge, got %q", srv.cfg.AuditRetention.Action)
	}
}

// TestRetentionRejectsBadDays confirms a negative day count is rejected and leaves
// the stored policy untouched.
func TestRetentionRejectsBadDays(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")
	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/settings"), "csrf")

	resp, err := c.PostForm(ts.URL+"/settings/retention", url.Values{
		"csrf": {csrf}, "days_to_keep": {"-5"}, "action": {"purge"},
	})
	if err != nil {
		t.Fatalf("save retention: %v", err)
	}
	resp.Body.Close()
	if srv.cfg.AuditRetention.DaysToKeep != 0 {
		t.Fatalf("a negative day count should have been rejected, got %d", srv.cfg.AuditRetention.DaysToKeep)
	}
}

// TestAuditAndRetentionRoutesRequireCSRF confirms a missing or forged token leaves
// the mutating routes inert.
func TestAuditAndRetentionRoutesRequireCSRF(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")
	if err := srv.audit.Record("admin", "seed_marker", "x", audit.OK, ""); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cases := []struct {
		path string
		form url.Values
	}{
		{"/audit/purge-all", url.Values{}},
		{"/audit/purge-before", url.Values{"date": {"2030-01-01"}}},
		{"/settings/retention", url.Values{"days_to_keep": {"99"}, "action": {"purge"}}},
	}
	for _, tc := range cases {
		resp, err := c.PostForm(ts.URL+tc.path, tc.form) // missing token
		if err != nil {
			t.Fatalf("post %s (no csrf): %v", tc.path, err)
		}
		resp.Body.Close()
		forged := url.Values{"csrf": {"bogus"}}
		for k, v := range tc.form {
			forged[k] = v
		}
		resp, err = c.PostForm(ts.URL+tc.path, forged)
		if err != nil {
			t.Fatalf("post %s (forged csrf): %v", tc.path, err)
		}
		resp.Body.Close()
	}

	// The seed entry survives (no purge ran); the rejected POSTs are themselves
	// audited as csrf_reject, so the raw count is expected to grow.
	if !auditActions(t, srv)["seed_marker"] {
		t.Fatal("a CSRF-less or forged POST purged the audit log")
	}
	if srv.cfg.AuditRetention.DaysToKeep != 0 {
		t.Fatalf("a CSRF-less or forged POST changed retention: %+v", srv.cfg.AuditRetention)
	}
}

// TestAuditAndRetentionControlsAdminOnly confirms a developer cannot reach the
// purge or retention routes (each returns 403).
func TestAuditAndRetentionControlsAdminOnly(t *testing.T) {
	ts, _, _ := backupTestServer(t)
	admin := newClient(t)
	onboard(t, ts, admin, "admin", "supersecret")

	csrf := extract(t, reCSRF, getBody(t, admin, ts.URL+"/users"), "csrf")
	resp, err := admin.PostForm(ts.URL+"/users", url.Values{
		"csrf": {csrf}, "new_user_name": {"dev"}, "new_user_secret": {"devpassword"}, "role": {"developer"},
	})
	if err != nil {
		t.Fatalf("create dev: %v", err)
	}
	resp.Body.Close()

	dev := newClient(t)
	if _, err := dev.PostForm(ts.URL+"/login", url.Values{
		"username": {"dev"}, "password": {"devpassword"},
	}); err != nil {
		t.Fatalf("dev login: %v", err)
	}
	secret := extract(t, reSecret, getBody(t, dev, ts.URL+"/setup/totp"), "dev secret")
	code, _ := totp.Code(secret)
	resp, err = dev.PostForm(ts.URL+"/setup/totp", url.Values{"code": {code}, "saved": {"yes"}})
	if err != nil {
		t.Fatalf("dev enroll: %v", err)
	}
	resp.Body.Close()

	dev.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, path := range []string{"/audit/purge-all", "/audit/purge-before", "/settings/retention"} {
		resp, err := dev.PostForm(ts.URL+path, url.Values{"date": {"2030-01-01"}})
		if err != nil {
			t.Fatalf("dev POST %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("developer POST %s: expected 403, got %d", path, resp.StatusCode)
		}
	}
}
