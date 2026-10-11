package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sopshq/internal/audit"
	"sopshq/internal/config"
	"sopshq/internal/keysvc"
	"sopshq/internal/place"
	"sopshq/internal/store"
	"sopshq/internal/totp"
	"sopshq/internal/usage"
	"sopshq/internal/vault"
)

// backupTestServer is like testServer but also returns the *Server and *config so
// a test can wire a fake backup runner and inspect the sealed password. The store
// and vault live in a sandbox temp dir; no real state is touched.
func backupTestServer(t *testing.T) (*httptest.Server, *Server, *config.Config) {
	t.Helper()
	t.Setenv("SOPS_AGE_KEY_FILE", "")
	dir := t.TempDir()
	v, err := vault.Init(filepath.Join(dir, "vault"), "test-pass")
	if err != nil {
		t.Fatalf("vault init: %v", err)
	}
	st, err := store.Open(filepath.Join(dir, "data"), "test-node", nil)
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	a := audit.Open(filepath.Join(dir, "audit.jsonl"), "test-node", nil)
	cfg := config.Default(filepath.Join(dir, "config.jsonc"), dir, "test-node")
	if err := cfg.Save(); err != nil {
		t.Fatalf("config save: %v", err)
	}
	ks := keysvc.New(st, v, a, cfg.LocalMachineID)
	ks.SetPlacer(place.WriteKeyStore)
	ks.SetDiscoverer(hermeticDiscoverer)
	place.DisableEffectsForTest(t)
	ks.SetUsage(usage.Open(filepath.Join(dir, "usage.jsonl")))
	srv, err := NewServer(st, v, a, ks, cfg, "test", time.Hour)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.SetIngestToken(testIngestToken)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, srv, cfg
}

// TestBackupPasswordSealsAndPersists verifies that setting the backup password
// stores a vault-sealed ciphertext (never the plaintext) and that the plaintext
// never appears on the dashboard.
func TestBackupPasswordSealsAndPersists(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	const plain = "backup-pass-123"
	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/"), "csrf")
	resp, err := c.PostForm(ts.URL+"/backup/password", url.Values{"csrf": {csrf}, "backup_secret": {plain}})
	if err != nil {
		t.Fatalf("post password: %v", err)
	}
	resp.Body.Close()

	b := srv.store.BackupSettingsFor(srv.keys.LocalMachine())
	if b.PasswordSealed == "" {
		t.Fatal("PasswordSealed is empty after setting the backup password")
	}
	if b.PasswordSealed == plain {
		t.Fatal("PasswordSealed equals the plaintext password (not sealed)")
	}
	// The sealed blob must open back to the plaintext via the vault.
	got, err := srv.vault.Open(b.PasswordSealed)
	if err != nil {
		t.Fatalf("vault open sealed backup password: %v", err)
	}
	if string(got) != plain {
		t.Fatal("sealed backup password did not round-trip")
	}

	body := getBody(t, c, ts.URL+"/settings")
	if strings.Contains(body, plain) {
		t.Fatal("settings leaked the plaintext backup password")
	}
	if !strings.Contains(body, "Set") {
		t.Fatal("settings does not show the backup password as Set")
	}
}

// TestBackupPasswordRejectsShort confirms an under-length password is rejected and
// nothing is sealed.
func TestBackupPasswordRejectsShort(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")
	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/"), "csrf")
	resp, err := c.PostForm(ts.URL+"/backup/password", url.Values{"csrf": {csrf}, "backup_secret": {"short"}})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if srv.store.BackupSettingsFor(srv.keys.LocalMachine()).PasswordSealed != "" {
		t.Fatal("a too-short password should not be sealed")
	}
}

// TestBackupNowRequiresCSRF confirms /backup/now runs only with a valid CSRF token,
// stores the summary, and surfaces it on the dashboard.
func TestBackupNowRequiresCSRF(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
	var calls atomic.Int32
	srv.SetBackupRunner(func() (string, error) {
		calls.Add(1)
		return "sopshq-backup-test (42 bytes); local: /tmp/x [ok]", nil
	})
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	// Missing CSRF -> rejected, runner not called.
	resp, err := c.PostForm(ts.URL+"/backup/now", url.Values{})
	if err != nil {
		t.Fatalf("post no-csrf: %v", err)
	}
	resp.Body.Close()
	if calls.Load() != 0 {
		t.Fatal("backup runner was called without a CSRF token")
	}

	// Forged CSRF -> rejected too.
	resp, err = c.PostForm(ts.URL+"/backup/now", url.Values{"csrf": {"bogus"}})
	if err != nil {
		t.Fatalf("post bad-csrf: %v", err)
	}
	resp.Body.Close()
	if calls.Load() != 0 {
		t.Fatal("backup runner was called with a forged CSRF token")
	}

	// Valid CSRF -> runner called, summary stored and rendered.
	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/"), "csrf")
	resp, err = c.PostForm(ts.URL+"/backup/now", url.Values{"csrf": {csrf}})
	if err != nil {
		t.Fatalf("post csrf: %v", err)
	}
	resp.Body.Close()
	if calls.Load() != 1 {
		t.Fatalf("expected backup runner to be called once, got %d", calls.Load())
	}
	if body := getBody(t, c, ts.URL+"/settings"); !strings.Contains(body, "sopshq-backup-test (42 bytes)") {
		t.Fatalf("settings did not render the last-backup summary")
	}
}

// TestBackupControlsAdminOnly confirms a developer cannot reach the backup routes.
func TestBackupControlsAdminOnly(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
	srv.SetBackupRunner(func() (string, error) { return "should-not-run", nil })
	admin := newClient(t)
	onboard(t, ts, admin, "admin", "supersecret")

	// Admin creates a developer.
	csrf := extract(t, reCSRF, getBody(t, admin, ts.URL+"/users"), "csrf")
	resp, err := admin.PostForm(ts.URL+"/users", url.Values{
		"csrf": {csrf}, "new_user_name": {"dev"}, "new_user_secret": {"devpassword"}, "role": {"developer"},
	})
	if err != nil {
		t.Fatalf("create dev: %v", err)
	}
	resp.Body.Close()

	// Developer logs in and enrolls TOTP.
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
	for _, path := range []string{
		"/backup/now", "/backup/password",
		"/backup/config", "/backup/destinations/add", "/backup/destinations/remove",
	} {
		resp, err := dev.PostForm(ts.URL+path, url.Values{"backup_secret": {"whatever123"}})
		if err != nil {
			t.Fatalf("dev POST %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("developer POST %s: expected 403, got %d", path, resp.StatusCode)
		}
	}
}
