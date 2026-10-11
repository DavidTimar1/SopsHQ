package web

import (
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"

	"sopshq/internal/totp"
)

// dbAdminTabLabels are the tab buttons an admin must see on the DB page.
var dbAdminTabLabels = []string{
	">Keys<", ">Projects<", ">Machines<", ">OS users<", ">Assignments<", ">Users<", ">Secrets<",
}

// TestDBPageAdminSeesAllTabs logs in as the first admin and asserts the DB page
// renders every tab, including the admin-only Users and Secrets tabs.
func TestDBPageAdminSeesAllTabs(t *testing.T) {
	ts, _ := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	body := getBody(t, c, ts.URL+"/db")
	if !strings.Contains(body, `id="db-tabs"`) {
		t.Fatalf("DB page did not render the tab strip")
	}
	for _, label := range dbAdminTabLabels {
		if !strings.Contains(body, label) {
			t.Errorf("admin DB page missing tab %q", label)
		}
	}
}

// TestDBPageDeveloperHidesAdminTabs confirms a developer can browse the DB page
// but never receives the admin-only Users or Secrets tabs (neither the tab nor
// any of their data).
func TestDBPageDeveloperHidesAdminTabs(t *testing.T) {
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

	body := getBody(t, dev, ts.URL+"/db")
	for _, label := range []string{">Keys<", ">Projects<", ">Machines<", ">OS users<", ">Assignments<"} {
		if !strings.Contains(body, label) {
			t.Errorf("developer DB page missing operational tab %q", label)
		}
	}
	for _, hidden := range []string{`id="db-users-tab"`, `id="db-secrets-tab"`} {
		if strings.Contains(body, hidden) {
			t.Errorf("developer DB page leaked admin-only tab %q", hidden)
		}
	}
}

// TestDBPageSecretsTabNeverLeaksValue seeds a project with a real secret (via the
// same HTTP flow the panel uses), then loads the DB page as admin and asserts the
// Secrets tab shows the secret's NAME but never its plaintext VALUE.
func TestDBPageSecretsTabNeverLeaksValue(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
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

	post("/projects", url.Values{"name": {"app"}})
	projID := extract(t, reProjLink, getBody(t, c, ts.URL+"/projects"), "project id")
	post("/projects/"+projID+"/paths", url.Values{"machine_id": {machineID}, "path": {projDir}})

	post("/keys", url.Values{"name": {"appkey"}, "type": {"shared"}})
	keyID := extract(t, reKeyGen, getBody(t, c, ts.URL+"/keys"), "key id")
	post("/keys/"+keyID+"/generate", url.Values{})

	osUserID := extract(t, reOSUserDel, getBody(t, c, ts.URL+"/osusers"), "os user id")
	post("/assignments", url.Values{
		"project_id": {projID}, "key_id": {keyID}, "machine_id": {machineID}, "os_user_id": {osUserID},
	})
	post("/apply", url.Values{})

	const secretName = "APP_TOKEN"
	const secretValue = "sentinel-zzz-9f3a-never-render"
	post("/projects/"+projID+"/secrets", url.Values{"name": {secretName}, "value": {secretValue}})

	body := getBody(t, c, ts.URL+"/db")
	if !strings.Contains(body, secretName) {
		t.Fatalf("Secrets tab did not show the secret name %q", secretName)
	}
	if strings.Contains(body, secretValue) {
		t.Fatalf("DB page LEAKED the secret value %q", secretValue)
	}
}

// TestDBPageRequiresLogin confirms the DB route is login-gated.
func TestDBPageRequiresLogin(t *testing.T) {
	ts, _ := testServer(t)
	c := newClient(t)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Get(ts.URL + "/db")
	if err != nil {
		t.Fatalf("GET /db: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("GET /db unauthenticated: expected redirect to /login, got %d %q",
			resp.StatusCode, resp.Header.Get("Location"))
	}
}
