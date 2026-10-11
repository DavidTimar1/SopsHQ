package web

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"sopshq/internal/audit"
	"sopshq/internal/config"
	"sopshq/internal/keysvc"
	"sopshq/internal/place"
	"sopshq/internal/stamps"
	"sopshq/internal/store"
	"sopshq/internal/totp"
	"sopshq/internal/usage"
	"sopshq/internal/vault"
)

const testIngestToken = "test-ingest-token"

// hermeticDiscoverer is the keysvc discovery seam used in tests: it repairs
// nothing and touches nothing (no setx/mklink/bashrc), returning an empty report.
func hermeticDiscoverer(place.Opts) place.DiscoveryReport { return place.DiscoveryReport{} }

// testServer spins up a panel backed by a temp store + unlocked vault.
func testServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	// Hermetic: clear any SOPS_AGE_KEY_FILE leaking from the parent shell so the
	// safe-wiring inspector does not see host state during HTTP tests.
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
	ks := keysvc.New(st, v, a, cfg.LocalMachineID)
	ks.SetPlacer(place.WriteKeyStore)    // never touch the host environment in tests
	ks.SetDiscoverer(hermeticDiscoverer) // never run setx/mklink during discovery
	place.DisableEffectsForTest(t)       // backstop: no host effects from any path
	ks.SetUsage(usage.Open(filepath.Join(dir, "usage.jsonl")))
	// Wire the machine-local external-change guard so the panel's reconcile flow is
	// exercised exactly as in production. Baseline-on-first-sight keeps the existing
	// flows green: a first write to an unstamped file proceeds and records a stamp.
	stmp, err := stamps.Open(filepath.Join(dir, "stamps.json"))
	if err != nil {
		t.Fatalf("stamps open: %v", err)
	}
	ks.SetStamps(stmp)
	srv, err := NewServer(st, v, a, ks, cfg, "test", time.Hour)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.SetIngestToken(testIngestToken)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, st
}

func newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

var (
	reCSRF   = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	reSecret = regexp.MustCompile(`id="totp-secret"[^>]*>([^<]+)<`)
)

func getBody(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body %s: %v", url, err)
	}
	return string(b)
}

func extract(t *testing.T, re *regexp.Regexp, body, what string) string {
	t.Helper()
	m := re.FindStringSubmatch(body)
	if len(m) < 2 {
		t.Fatalf("could not find %s in body", what)
	}
	return m[1]
}

// onboard runs setup -> TOTP enrollment and returns the enrolled secret, leaving
// the client logged in as the first admin.
func onboard(t *testing.T, ts *httptest.Server, c *http.Client, username, password string) string {
	t.Helper()
	// Setup form (creating the first admin).
	if _, err := c.PostForm(ts.URL+"/setup", url.Values{
		"username": {username}, "password": {password},
	}); err != nil {
		t.Fatalf("post setup: %v", err)
	}
	body := getBody(t, c, ts.URL+"/setup/totp")
	secret := extract(t, reSecret, body, "totp secret")
	code, err := totp.Code(secret)
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	resp, err := c.PostForm(ts.URL+"/setup/totp", url.Values{"code": {code}, "saved": {"yes"}})
	if err != nil {
		t.Fatalf("post setup totp: %v", err)
	}
	resp.Body.Close()
	return secret
}

func TestSetupLoginAndDashboard(t *testing.T) {
	ts, _ := testServer(t)
	c := newClient(t)

	// Fresh install redirects to setup.
	if body := getBody(t, c, ts.URL+"/"); !strings.Contains(body, "Create the first administrator") &&
		!strings.Contains(body, "Welcome to SopsHQ") {
		t.Fatalf("expected setup page, got: %.120s", body)
	}
	onboard(t, ts, c, "admin", "supersecret")

	body := getBody(t, c, ts.URL+"/")
	if !strings.Contains(body, "Dashboard") {
		t.Fatalf("expected dashboard after onboarding, got: %.150s", body)
	}
}

func TestCreateMachineWithAndWithoutCSRF(t *testing.T) {
	ts, st := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	// Valid CSRF -> machine created.
	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/machines"), "csrf token")
	resp, err := c.PostForm(ts.URL+"/machines", url.Values{
		"csrf": {csrf}, "name": {"linux-server"}, "os": {"linux"},
	})
	if err != nil {
		t.Fatalf("post machine: %v", err)
	}
	resp.Body.Close()
	if n := len(st.Machines.List()); n != 1 {
		t.Fatalf("expected 1 machine, got %d", n)
	}

	// Missing CSRF -> rejected, no second machine.
	resp, err = c.PostForm(ts.URL+"/machines", url.Values{
		"name": {"evil"}, "os": {"linux"},
	})
	if err != nil {
		t.Fatalf("post machine 2: %v", err)
	}
	resp.Body.Close()
	if n := len(st.Machines.List()); n != 1 {
		t.Fatalf("CSRF-less POST should be rejected; machines = %d", n)
	}
}

func TestProtectedRoutesRequireLogin(t *testing.T) {
	ts, _ := testServer(t)
	c := newClient(t)
	// Do not follow redirects so we can see the 303 to /login.
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, path := range []string{"/machines", "/keys", "/users", "/audit"} {
		resp, err := c.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("%s: expected redirect to login, got %d", path, resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); loc != "/login" {
			t.Errorf("%s: expected Location /login, got %q", path, loc)
		}
	}
}

var (
	reMachineLocal = regexp.MustCompile(`/machines/([0-9a-f-]+)/local`)
	reOSUserDel    = regexp.MustCompile(`/osusers/([0-9a-f-]+)/delete`)
	reProjLink     = regexp.MustCompile(`/projects/([0-9a-f-]+)"`)
	reKeyGen       = regexp.MustCompile(`/keys/([0-9a-f-]+)/generate`)
)

// TestKeyFlowOverHTTP drives the whole key flow through the real HTTP
// handlers: designate the local machine, register an OS user and project with a
// local path, define + generate a key, assign it, then Apply - and confirm the
// private key was placed and .sops.yaml written.
func TestKeyFlowOverHTTP(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	ts, _ := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	post := func(path string, vals url.Values) {
		t.Helper()
		csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/machines"), "csrf")
		vals.Set("csrf", csrf)
		resp, err := c.PostForm(ts.URL+path, vals)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		resp.Body.Close()
	}

	keyBase := t.TempDir()
	projDir := t.TempDir()

	post("/machines", url.Values{"name": {"local"}, "os": {"windows"}})
	machineID := extract(t, reMachineLocal, getBody(t, c, ts.URL+"/machines"), "machine id")
	post("/machines/"+machineID+"/local", url.Values{})

	post("/osusers", url.Values{"machine_id": {machineID}, "os_username": {"dev"}, "key_base": {keyBase}})
	osUserID := extract(t, reOSUserDel, getBody(t, c, ts.URL+"/osusers"), "os user id")

	post("/projects", url.Values{"name": {"app"}})
	projID := extract(t, reProjLink, getBody(t, c, ts.URL+"/projects"), "project id")
	post("/projects/"+projID+"/paths", url.Values{"machine_id": {machineID}, "path": {projDir}})

	post("/keys", url.Values{"name": {"appkey"}, "type": {"shared"}})
	keyID := extract(t, reKeyGen, getBody(t, c, ts.URL+"/keys"), "key id")
	post("/keys/"+keyID+"/generate", url.Values{})

	post("/assignments", url.Values{
		"project_id": {projID}, "key_id": {keyID}, "machine_id": {machineID}, "os_user_id": {osUserID},
	})

	post("/apply", url.Values{})

	if b, err := os.ReadFile(filepath.Join(keyBase, "keys.txt")); err != nil ||
		!strings.HasPrefix(strings.TrimSpace(string(b)), "AGE-SECRET-KEY-1") {
		t.Fatalf("Apply did not place the private key: err=%v", err)
	}
	sy, err := os.ReadFile(filepath.Join(projDir, ".sops.yaml"))
	if err != nil || !strings.Contains(string(sy), "age1") {
		t.Fatalf("Apply did not write .sops.yaml with a recipient: err=%v", err)
	}
}

func TestDeveloperCannotReachAdminPages(t *testing.T) {
	ts, _ := testServer(t)
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

	// Developer logs in (password -> forced TOTP enrollment -> dashboard).
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

	// Developer can see dashboard but NOT the admin-only users page.
	if body := getBody(t, dev, ts.URL+"/"); !strings.Contains(body, "Dashboard") {
		t.Fatalf("developer should see dashboard")
	}
	dev.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err = dev.Get(ts.URL + "/users")
	if err != nil {
		t.Fatalf("dev GET /users: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("developer reaching /users: expected 403, got %d", resp.StatusCode)
	}
}
