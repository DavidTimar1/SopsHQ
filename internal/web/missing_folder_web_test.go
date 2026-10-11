package web

import (
	"net/url"
	"os"
	"strings"
	"testing"
)

// TestMissingLocalFolderAlert drives the proactive "folder no longer exists" alert
// through the real handlers: a project gets a local-machine folder that exists, the
// folder is then deleted, and the dashboard, projects list, and project detail must
// all surface the alert without changing anything.
func TestMissingLocalFolderAlert(t *testing.T) {
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
	post("/projects", url.Values{"name": {"app"}})
	projID := extract(t, reProjLink, getBody(t, c, ts.URL+"/projects"), "project id")
	post("/projects/"+projID+"/paths", url.Values{"machine_id": {machineID}, "path": {projDir}})

	// While the folder exists, none of the surfaces should warn.
	if body := getBody(t, c, ts.URL+"/"); strings.Contains(body, "no longer exist") {
		t.Fatalf("dashboard warned about a folder that still exists; got: %.400s", body)
	}

	// Delete the folder to simulate a moved/deleted project.
	if err := os.RemoveAll(projDir); err != nil {
		t.Fatalf("remove project dir: %v", err)
	}

	if body := getBody(t, c, ts.URL+"/"); !strings.Contains(body, "no longer exist") || !strings.Contains(body, "/projects/"+projID) {
		t.Fatalf("dashboard missing the folder-gone alert; got: %.500s", body)
	}
	if body := getBody(t, c, ts.URL+"/projects"); !strings.Contains(body, "folder missing") {
		t.Fatalf("projects list missing the folder-gone badge; got: %.500s", body)
	}
	if body := getBody(t, c, ts.URL+"/projects/"+projID); !strings.Contains(body, "no longer exists on this machine") {
		t.Fatalf("project detail missing the folder-gone alert; got: %.500s", body)
	}
}
