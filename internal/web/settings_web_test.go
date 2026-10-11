package web

import (
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sopshq/internal/totp"
)

// TestSettingsRequiresLogin confirms the Settings page is login-gated.
func TestSettingsRequiresLogin(t *testing.T) {
	ts, _ := testServer(t)
	c := newClient(t)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Get(ts.URL + "/settings")
	if err != nil {
		t.Fatalf("GET /settings: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected redirect to login, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Fatalf("expected Location /login, got %q", loc)
	}
}

// TestSettingsRendersPathsAndBackups confirms the Paths table and Backups panel
// render on Settings (and not on the dashboard).
func TestSettingsRendersPathsAndBackups(t *testing.T) {
	ts, _ := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	settings := getBody(t, c, ts.URL+"/settings")
	for _, want := range []string{"Paths this machine uses", "Location pointer", "Backups", "Set backup password"} {
		if !strings.Contains(settings, want) {
			t.Fatalf("settings page missing %q", want)
		}
	}

	dash := getBody(t, c, ts.URL+"/")
	for _, gone := range []string{"Paths this machine uses", "Set backup password"} {
		if strings.Contains(dash, gone) {
			t.Fatalf("dashboard still shows moved markup %q", gone)
		}
	}
}

// TestSettingsBackupControlsAdminOnly confirms a developer sees the admin-only
// note instead of the backup controls on Settings (the POST gate is covered by
// TestBackupControlsAdminOnly).
func TestSettingsBackupControlsAdminOnly(t *testing.T) {
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

	body := getBody(t, dev, ts.URL+"/settings")
	if strings.Contains(body, "Set backup password") {
		t.Fatal("developer should not see the backup password control on Settings")
	}
	if !strings.Contains(body, "available to administrators") {
		t.Fatal("developer should see the admin-only backup note on Settings")
	}
}

// TestDashboardApplyButtonsDisabledWhenNoPending confirms Apply + Push render with
// the real disabled attribute when nothing is pending, while Dry run, Force
// re-apply, and Sync stay enabled.
func TestDashboardApplyButtonsDisabledWhenNoPending(t *testing.T) {
	ts, _ := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	body := getBody(t, c, ts.URL+"/")
	for _, want := range []string{"disabled>Apply to this machine", "disabled>Push to all machines"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected disabled control %q on a no-pending dashboard", want)
		}
	}
	for _, bad := range []string{"disabled>Dry run", "disabled>Force re-apply", "disabled>Sync now"} {
		if strings.Contains(body, bad) {
			t.Fatalf("control should not be disabled: %q", bad)
		}
	}
}

// TestDashboardResultsPanelAfterApply drives a full apply through the HTTP handlers
// and confirms the dashboard then renders the detailed per-item results panel
// reflecting ApplyReport.Actions (a placed key, marked "done").
func TestDashboardResultsPanelAfterApply(t *testing.T) {
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

	// Sanity: the apply really placed the key on disk.
	if _, err := os.Stat(filepath.Join(keyBase, "keys.txt")); err != nil {
		t.Fatalf("apply did not place the key: %v", err)
	}

	body := getBody(t, c, ts.URL+"/")
	for _, want := range []string{"Last action this session", "key-placed", "done"} {
		if !strings.Contains(body, want) {
			t.Fatalf("results panel missing %q after apply; body:\n%s", want, body)
		}
	}
}
