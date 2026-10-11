package web

import (
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"

	"sopshq/internal/model"
	"sopshq/internal/store"
	"sopshq/internal/totp"
)

// mapDefaultViewIDs are the built-in views every Map page must list as pills.
var mapDefaultViewIDs = []string{
	"default-projects", "default-machines", "default-users", "default-keys", "default-secrets",
}

// seedMapRecords inserts a machine, OS user, project, and assignment directly into
// the store (no age-keygen/sops needed) so the tree builder has relations to group.
func seedMapRecords(t *testing.T, st *store.Store) (machine, user, project string) {
	t.Helper()
	m := &model.Machine{M: model.Meta{UUID: store.NewID()}, Name: "linuxbox", OS: model.OSLinux}
	if err := st.Machines.Put(m); err != nil {
		t.Fatalf("put machine: %v", err)
	}
	u := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: m.M.UUID, Username: "alice"}
	if err := st.OSUsers.Put(u); err != nil {
		t.Fatalf("put os user: %v", err)
	}
	p := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "billing",
		Paths: []model.ProjectPath{{MachineID: m.M.UUID, Path: "/srv/billing"}}}
	if err := st.Projects.Put(p); err != nil {
		t.Fatalf("put project: %v", err)
	}
	a := &model.Assignment{M: model.Meta{UUID: store.NewID()},
		ProjectID: p.M.UUID, MachineID: m.M.UUID, OSUserID: u.M.UUID}
	if err := st.Assignments.Put(a); err != nil {
		t.Fatalf("put assignment: %v", err)
	}
	return m.Name, u.Username, p.Name
}

// TestMapPageShowsDefaultViews confirms the Map page renders the built-in view
// pills and the two-pane shell.
func TestMapPageShowsDefaultViews(t *testing.T) {
	ts, _ := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	body := getBody(t, c, ts.URL+"/map")
	if !strings.Contains(body, `id="map-page"`) || !strings.Contains(body, `id="map-tree"`) {
		t.Fatalf("Map page missing the two-pane shell")
	}
	for _, id := range mapDefaultViewIDs {
		if !strings.Contains(body, `data-view="`+id+`"`) {
			t.Errorf("Map page missing default view pill %q", id)
		}
	}
}

// TestMapTreeBuildsFromRecords checks /map/tree returns a JSON tree grouping the
// seeded records by the Machines view (Machine -> OS user -> Project).
func TestMapTreeBuildsFromRecords(t *testing.T) {
	ts, st := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")
	machine, user, project := seedMapRecords(t, st)

	body := getBody(t, c, ts.URL+"/map/tree?view=default-machines")
	for _, want := range []string{machine, user, project, `"kind":"leaf"`, `"kind":"grouping"`} {
		if !strings.Contains(body, want) {
			t.Errorf("/map/tree missing %q in %s", want, body)
		}
	}
}

// TestMapTreeUnknownView returns 404 for an unknown view id.
func TestMapTreeUnknownView(t *testing.T) {
	ts, _ := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Get(ts.URL + "/map/tree?view=does-not-exist")
	if err != nil {
		t.Fatalf("GET /map/tree: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown view: expected 404, got %d", resp.StatusCode)
	}
}

// TestMapEditorCreatesView posts the editor form and confirms a custom MapView
// record is stored, then that it appears as a pill.
func TestMapEditorCreatesView(t *testing.T) {
	ts, st := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/map"), "csrf")
	resp, err := c.PostForm(ts.URL+"/map/views", url.Values{
		"csrf":   {csrf},
		"name":   {"By machine"},
		"levels": {"Machine,OSUser"},
		"leaf":   {"Project"},
	})
	if err != nil {
		t.Fatalf("create view: %v", err)
	}
	resp.Body.Close()

	views := st.MapViews.List()
	if len(views) != 1 {
		t.Fatalf("expected 1 stored view, got %d", len(views))
	}
	v := views[0]
	if v.Name != "By machine" || v.Leaf != "Project" ||
		len(v.GroupBy) != 2 || v.GroupBy[0] != "Machine" || v.GroupBy[1] != "OSUser" {
		t.Fatalf("stored view wrong: %+v", v)
	}
	if body := getBody(t, c, ts.URL+"/map"); !strings.Contains(body, `data-view="`+v.M.UUID+`"`) {
		t.Fatalf("custom view pill not rendered")
	}
}

// TestMapEditorRequiresCSRF confirms the create-view POST is rejected without a
// valid CSRF token.
func TestMapEditorRequiresCSRF(t *testing.T) {
	ts, st := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	resp, err := c.PostForm(ts.URL+"/map/views", url.Values{
		"name": {"evil"}, "levels": {"Machine"}, "leaf": {"Project"},
	})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if n := len(st.MapViews.List()); n != 0 {
		t.Fatalf("CSRF-less view POST should be rejected; views = %d", n)
	}
}

// TestMapEditorDeveloperForbidden confirms a developer can browse the Map page and
// its tree but cannot create a custom view (the editor POST is admin-only).
func TestMapEditorDeveloperForbidden(t *testing.T) {
	ts, _ := testServer(t)
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

	// Developer can read the Map page and its tree.
	if body := getBody(t, dev, ts.URL+"/map"); !strings.Contains(body, `id="map-page"`) {
		t.Fatalf("developer should see the Map page")
	}
	if body := getBody(t, dev, ts.URL+"/map/tree?view=default-projects"); !strings.Contains(body, `"nodes"`) {
		t.Fatalf("developer should get the Map tree JSON")
	}
	// Developer cannot create a custom view (admin-only editor POST).
	devCSRF := extract(t, reCSRF, getBody(t, dev, ts.URL+"/map"), "dev csrf")
	dev.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err = dev.PostForm(ts.URL+"/map/views", url.Values{
		"csrf": {devCSRF}, "name": {"sneaky"}, "levels": {"Machine"}, "leaf": {"Project"},
	})
	if err != nil {
		t.Fatalf("dev create view: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("developer creating a view: expected 403, got %d", resp.StatusCode)
	}
}

// TestMapTreeNeverLeaksSecretValue seeds a real secret through the panel flow, then
// asserts the Projects view tree shows the secret NAME but never its plaintext.
func TestMapTreeNeverLeaksSecretValue(t *testing.T) {
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
	const secretValue = "sentinel-map-7c1a-never-render"
	post("/projects/"+projID+"/secrets", url.Values{"name": {secretName}, "value": {secretValue}})

	body := getBody(t, c, ts.URL+"/map/tree?view=default-projects")
	if !strings.Contains(body, secretName) {
		t.Fatalf("Projects tree did not show the secret name %q", secretName)
	}
	if strings.Contains(body, secretValue) {
		t.Fatalf("/map/tree LEAKED the secret value %q", secretValue)
	}
}

// TestMapPageRequiresLogin confirms the Map route is login-gated.
func TestMapPageRequiresLogin(t *testing.T) {
	ts, _ := testServer(t)
	c := newClient(t)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, path := range []string{"/map", "/map/tree?view=default-projects"} {
		resp, err := c.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
			t.Fatalf("GET %s unauthenticated: expected redirect to /login, got %d %q",
				path, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}
