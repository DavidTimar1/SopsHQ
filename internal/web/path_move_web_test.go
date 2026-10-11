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

// TestFolderMoveOverHTTP drives a project-folder change through the real handlers:
// a first POST to change an already-set local folder shows the confirm screen; a
// second POST with confirm_move=1 moves the managed .sops.yaml to the new folder and
// leaves the old folder clean.
func TestFolderMoveOverHTTP(t *testing.T) {
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
	postBody := func(path string, vals url.Values) (int, string) {
		t.Helper()
		csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/machines"), "csrf")
		vals.Set("csrf", csrf)
		resp, err := c.PostForm(ts.URL+path, vals)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		return resp.StatusCode, readAll(t, resp)
	}

	oldDir := t.TempDir()
	post("/machines", url.Values{"name": {"local"}, "os": {"windows"}})
	machineID := extract(t, reMachineLocal, getBody(t, c, ts.URL+"/machines"), "machine id")
	post("/machines/"+machineID+"/local", url.Values{})
	post("/osusers", url.Values{"machine_id": {machineID}, "os_username": {"dev"}, "key_base": {t.TempDir()}})
	post("/projects", url.Values{"name": {"app"}})
	projID := extract(t, reProjLink, getBody(t, c, ts.URL+"/projects"), "project id")
	post("/projects/"+projID+"/paths", url.Values{"machine_id": {machineID}, "path": {oldDir}})
	post("/projects/"+projID+"/wire", url.Values{})

	oldSops := filepath.Join(oldDir, ".sops.yaml")
	orig, err := os.ReadFile(oldSops)
	if err != nil || !strings.Contains(string(orig), "age1") {
		t.Fatalf("wiring did not write .sops.yaml: err=%v", err)
	}

	// Change the folder: the first POST must show the confirm screen, not move yet.
	newDir := t.TempDir()
	_, body := postBody("/projects/"+projID+"/paths", url.Values{"machine_id": {machineID}, "path": {newDir}})
	if !strings.Contains(body, "Move project folder") || !strings.Contains(body, "Move and update the folder") {
		t.Fatalf("expected the move confirm screen; got: %.400s", body)
	}
	if _, err := os.Stat(oldSops); err != nil {
		t.Fatalf("nothing should have moved before confirm; old .sops.yaml missing: %v", err)
	}

	// Confirm: the managed .sops.yaml moves and the old folder is cleaned.
	post("/projects/"+projID+"/paths", url.Values{"machine_id": {machineID}, "path": {newDir}, "confirm_move": {"1"}})
	if _, err := os.Stat(oldSops); !os.IsNotExist(err) {
		t.Fatalf("old .sops.yaml should be gone after the move; stat err=%v", err)
	}
	moved, err := os.ReadFile(filepath.Join(newDir, ".sops.yaml"))
	if err != nil {
		t.Fatalf("new .sops.yaml missing after move: %v", err)
	}
	if string(moved) != string(orig) {
		t.Fatal("moved .sops.yaml was regenerated, not byte-preserved")
	}
}

// TestDriftResolveButtonsRender wires a project, plants an extra public key on disk,
// and checks the Drift page renders the specific message plus the per-row resolve
// actions (proving the new template executes with the enriched DriftItem).
func TestDriftResolveButtonsRender(t *testing.T) {
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

	projDir := t.TempDir()
	post("/machines", url.Values{"name": {"local"}, "os": {"windows"}})
	machineID := extract(t, reMachineLocal, getBody(t, c, ts.URL+"/machines"), "machine id")
	post("/machines/"+machineID+"/local", url.Values{})
	post("/osusers", url.Values{"machine_id": {machineID}, "os_username": {"dev"}, "key_base": {t.TempDir()}})
	post("/projects", url.Values{"name": {"app"}})
	projID := extract(t, reProjLink, getBody(t, c, ts.URL+"/projects"), "project id")
	post("/projects/"+projID+"/paths", url.Values{"machine_id": {machineID}, "path": {projDir}})
	post("/projects/"+projID+"/wire", url.Values{})

	// Plant an extra public key on disk so the project drifts.
	sopsPath := filepath.Join(projDir, ".sops.yaml")
	b, _ := os.ReadFile(sopsPath)
	edited := strings.Replace(string(b), "age: ", "age: "+fakeRecipient+",", 1)
	os.WriteFile(sopsPath, []byte(edited), 0o644)

	body := getBody(t, c, ts.URL+"/drift")
	if !strings.Contains(body, "does not include") || !strings.Contains(body, "public key") {
		t.Fatalf("drift page missing the specific message; got: %.500s", body)
	}
	if !strings.Contains(body, "Adopt readers") || !strings.Contains(body, "Re-key to desired") {
		t.Fatalf("drift page missing the resolve actions; got: %.500s", body)
	}
	if !strings.Contains(body, `value="adopt-readers"`) || !strings.Contains(body, `value="rekey-desired"`) {
		t.Fatalf("drift page missing the resolve action values; got: %.500s", body)
	}
}

// TestAdoptReadersAdminOnly confirms the adopt-readers resolve action (which imports
// an unknown on-disk PRIVATE key into the vault) is refused for a developer but the
// admin passes the gate.
func TestAdoptReadersAdminOnly(t *testing.T) {
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

	// Admin makes a project (so a real project_id exists to POST).
	admin.PostForm(ts.URL+"/projects", url.Values{
		"csrf": {extract(t, reCSRF, getBody(t, admin, ts.URL+"/projects"), "csrf")}, "name": {"app"},
	})
	projID := extract(t, reProjLink, getBody(t, admin, ts.URL+"/projects"), "project id")

	// Developer logs in and enrolls TOTP.
	dev := newClient(t)
	if _, err := dev.PostForm(ts.URL+"/login", url.Values{"username": {"dev"}, "password": {"devpassword"}}); err != nil {
		t.Fatalf("dev login: %v", err)
	}
	secret := extract(t, reSecret, getBody(t, dev, ts.URL+"/setup/totp"), "dev secret")
	code, _ := totp.Code(secret)
	if resp, err := dev.PostForm(ts.URL+"/setup/totp", url.Values{"code": {code}, "saved": {"yes"}}); err == nil {
		resp.Body.Close()
	}

	adopt := func(c *http.Client) string {
		t.Helper()
		csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/machines"), "csrf")
		resp, err := c.PostForm(ts.URL+"/drift/resolve", url.Values{
			"csrf": {csrf}, "project_id": {projID}, "action": {"adopt-readers"},
		})
		if err != nil {
			t.Fatalf("adopt POST: %v", err)
		}
		return readAll(t, resp)
	}

	if body := adopt(dev); !strings.Contains(body, "admin-only") {
		t.Fatalf("developer adopt-readers should be refused as admin-only; got: %.400s", body)
	}
	if body := adopt(admin); strings.Contains(body, "admin-only") {
		t.Fatalf("admin adopt-readers should pass the gate, not be blocked; got: %.400s", body)
	}
}

// TestPeerPathChangeRecordsOnly confirms changing a PEER machine's project folder only
// updates the record (SopsHQ cannot touch a peer's filesystem) and touches nothing on
// the local disk.
func TestPeerPathChangeRecordsOnly(t *testing.T) {
	ts, st := testServer(t)
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
	postBody := func(path string, vals url.Values) string {
		t.Helper()
		csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/machines"), "csrf")
		vals.Set("csrf", csrf)
		resp, err := c.PostForm(ts.URL+path, vals)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		return readAll(t, resp)
	}

	// One local machine (designated) and one peer machine.
	post("/machines", url.Values{"name": {"local"}, "os": {"windows"}})
	localID := extract(t, reMachineLocal, getBody(t, c, ts.URL+"/machines"), "machine id")
	post("/machines/"+localID+"/local", url.Values{})
	post("/machines", url.Values{"name": {"peer"}, "os": {"linux"}})
	var peerID string
	for _, m := range st.Machines.List() {
		if m.M.UUID != localID {
			peerID = m.M.UUID
		}
	}
	if peerID == "" {
		t.Fatal("could not find the peer machine")
	}

	post("/projects", url.Values{"name": {"app"}})
	projID := extract(t, reProjLink, getBody(t, c, ts.URL+"/projects"), "project id")

	// Set then CHANGE the peer's path.
	post("/projects/"+projID+"/paths", url.Values{"machine_id": {peerID}, "path": {"/srv/old"}})
	body := postBody("/projects/"+projID+"/paths", url.Values{"machine_id": {peerID}, "path": {"/srv/new"}})
	if strings.Contains(body, "Move project folder") {
		t.Fatal("a peer path change must not show the local move confirm screen")
	}
	if !strings.Contains(body, "next apply or reconcile") {
		t.Fatalf("peer path change should note the peer reconciles itself; got: %.300s", body)
	}
	p, _ := st.Projects.Get(projID)
	for _, pp := range p.Paths {
		if pp.MachineID == peerID && pp.Path != "/srv/new" {
			t.Fatalf("peer path not updated; got %q", pp.Path)
		}
	}
}
