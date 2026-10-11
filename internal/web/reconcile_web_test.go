package web

import (
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRecipient is a distinctive (non-real) age recipient hand-added to a project
// .sops.yaml to stand in for an operator's manual edit.
const fakeRecipient = "age1faketestrecipientzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"

// TestExternalChangeReconcileOverHTTP drives the write-time guard + reconcile
// through the real HTTP handlers: wire a project (stamping its .sops.yaml), edit
// .sops.yaml OUTSIDE SopsHQ, then Apply - which must pause with a non-secret diff -
// and exercise overwrite, cancel, and adopt.
func TestExternalChangeReconcileOverHTTP(t *testing.T) {
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
	// postBody posts and returns the final status + body (following redirects).
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

	projDir := t.TempDir()
	post("/machines", url.Values{"name": {"local"}, "os": {"windows"}})
	machineID := extract(t, reMachineLocal, getBody(t, c, ts.URL+"/machines"), "machine id")
	post("/machines/"+machineID+"/local", url.Values{})
	post("/osusers", url.Values{"machine_id": {machineID}, "os_username": {"dev"}, "key_base": {t.TempDir()}})
	post("/projects", url.Values{"name": {"app"}})
	projID := extract(t, reProjLink, getBody(t, c, ts.URL+"/projects"), "project id")
	post("/projects/"+projID+"/paths", url.Values{"machine_id": {machineID}, "path": {projDir}})
	post("/projects/"+projID+"/wire", url.Values{})

	sopsPath := filepath.Join(projDir, ".sops.yaml")
	orig, err := os.ReadFile(sopsPath)
	if err != nil || !strings.Contains(string(orig), "age1") {
		t.Fatalf("wiring did not write .sops.yaml: err=%v", err)
	}

	// Hand-edit .sops.yaml: prepend a fake recipient to the age line.
	editSops := func() {
		t.Helper()
		b, err := os.ReadFile(sopsPath)
		if err != nil {
			t.Fatalf("read sops: %v", err)
		}
		edited := strings.Replace(string(b), "age: ", "age: "+fakeRecipient+",", 1)
		if edited == string(b) {
			t.Fatal("could not edit the age line")
		}
		if err := os.WriteFile(sopsPath, []byte(edited), 0o644); err != nil {
			t.Fatalf("write sops: %v", err)
		}
	}
	hasFake := func() bool {
		b, _ := os.ReadFile(sopsPath)
		return strings.Contains(string(b), fakeRecipient)
	}

	// 1) External edit -> Apply must pause with the reconcile screen naming the
	//    added recipient, and never show a secret value.
	editSops()
	status, body := postBody("/apply", url.Values{})
	if status != 409 {
		t.Fatalf("Apply over an external change: want 409, got %d", status)
	}
	if !strings.Contains(body, "External change detected") || !strings.Contains(body, fakeRecipient) {
		t.Fatalf("reconcile screen missing the added recipient; got: %.500s", body)
	}
	if !strings.Contains(body, "Adopt") || !strings.Contains(body, "Overwrite") {
		t.Fatalf("reconcile screen missing the choices; got: %.500s", body)
	}

	// 2) Overwrite -> SopsHQ's desired recipients are written, dropping the fake.
	post("/reconcile", url.Values{"kind": {"sops.yaml"}, "project_id": {projID}, "action": {"overwrite"}})
	if hasFake() {
		t.Fatal("overwrite should have dropped the hand-added recipient")
	}

	// 3) External edit again -> Cancel changes nothing on disk.
	editSops()
	if s, _ := postBody("/apply", url.Values{}); s != 409 {
		t.Fatalf("second external change should block; got %d", s)
	}
	post("/reconcile", url.Values{"kind": {"sops.yaml"}, "project_id": {projID}, "action": {"cancel"}})
	if !hasFake() {
		t.Fatal("cancel must not change the file")
	}

	// 4) Adopt -> re-stamp the on-disk version (kept), so the next Apply proceeds
	//    instead of blocking.
	post("/reconcile", url.Values{"kind": {"sops.yaml"}, "project_id": {projID}, "action": {"adopt"}})
	if !hasFake() {
		t.Fatal("adopt must not change the file")
	}
	if s, b := postBody("/apply", url.Values{}); s == 409 {
		t.Fatalf("after adopt, Apply should proceed, not block; got 409: %.300s", b)
	}
}
