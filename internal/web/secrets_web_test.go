package web

import (
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

var reMachineLocalSec = regexp.MustCompile(`/machines/([0-9a-f-]+)/local`)
var reGlobalSetDel = regexp.MustCompile(`/global/([0-9a-f-]+)/delete`)

// TestSecretsCatalogShowsGlobalSet onboards, creates a per-user key owned by an OS
// user, builds a global shared set by selecting that key, adds one secret, then loads
// the admin Secrets catalog and confirms the global secret renders in the Global Set
// column with a global reveal endpoint - and that its VALUE never appears.
func TestSecretsCatalogShowsGlobalSet(t *testing.T) {
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

	post("/machines", url.Values{"name": {"local"}, "os": {"windows"}})
	machineID := extract(t, reMachineLocalSec, getBody(t, c, ts.URL+"/machines"), "machine id")
	post("/machines/"+machineID+"/local", url.Values{})
	post("/osusers", url.Values{"machine_id": {machineID}, "os_username": {"dev"}, "key_base": {t.TempDir()}})
	osUserID := extract(t, reOSUserDel, getBody(t, c, ts.URL+"/osusers"), "os user id")

	// Create a per-user key OWNED by the OS user; its keypair is minted when the set
	// is built. Selecting it makes its owner the set's reader.
	post("/keys", url.Values{"name": {"devkey"}, "type": {"per_user"}, "owner_user_id": {osUserID}})
	keyID := extract(t, reKeyGen, getBody(t, c, ts.URL+"/keys"), "key id")

	// Build a global set by SELECTING that owned key, then add one secret to it.
	post("/global", url.Values{"name": {"teamkeys"}, "key": {keyID}})
	setID := extract(t, reGlobalSetDel, getBody(t, c, ts.URL+"/global"), "global set id")
	const globVal = "glob-token-secret-xyz"
	post("/global/"+setID+"/secrets", url.Values{"name": {"GLOBAL_TOKEN"}, "value": {globVal}})

	body := getBody(t, c, ts.URL+"/secrets")
	if !strings.Contains(body, "Global Set") {
		t.Fatalf("catalog missing the Global Set column header; got: %.400s", body)
	}
	if !strings.Contains(body, "GLOBAL_TOKEN") || !strings.Contains(body, "teamkeys") {
		t.Fatalf("catalog missing the global secret name/set; got: %.600s", body)
	}
	if !strings.Contains(body, `data-reveal-url="/global/`+setID+`/secrets/reveal"`) {
		t.Fatalf("global row should reveal via the global endpoint; got: %.600s", body)
	}
	if strings.Contains(body, globVal) {
		t.Fatal("the global secret VALUE must never appear in the catalog page")
	}
}

// TestSecretsEditorOverHTTP drives the secrets editor through the real HTTP
// handlers and the real sops binary: onboard, designate the local machine, set a
// project's local path, wire it (onboarding glue), then add / edit / delete a
// secret and confirm the name list reflects each change. It also checks that a
// mutating POST without a CSRF token is rejected.
func TestSecretsEditorOverHTTP(t *testing.T) {
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

	projDir := t.TempDir()
	post("/machines", url.Values{"name": {"local"}, "os": {"windows"}})
	machineID := extract(t, reMachineLocalSec, getBody(t, c, ts.URL+"/machines"), "machine id")
	post("/machines/"+machineID+"/local", url.Values{})

	// Register an OS user with an ISOLATED key base so wiring places into a temp
	// dir, never the real $HOME/.sops on the test host (which would also trip the
	// safe-wiring conflict guard).
	post("/osusers", url.Values{"machine_id": {machineID}, "os_username": {"dev"}, "key_base": {t.TempDir()}})

	post("/projects", url.Values{"name": {"app"}})
	projID := extract(t, reProjLink, getBody(t, c, ts.URL+"/projects"), "project id")
	post("/projects/"+projID+"/paths", url.Values{"machine_id": {machineID}, "path": {projDir}})

	// Before wiring, the detail page should offer to wire the project.
	if body := getBody(t, c, ts.URL+"/projects/"+projID); !strings.Contains(body, "Wire this project") {
		t.Fatalf("expected a wire prompt before wiring; got: %.300s", body)
	}

	// Wire it (onboarding glue), then the editor should be available.
	post("/projects/"+projID+"/wire", url.Values{})
	if body := getBody(t, c, ts.URL+"/projects/"+projID); !strings.Contains(body, "No secrets yet") {
		t.Fatalf("expected an empty secrets editor after wiring; got: %.300s", body)
	}

	// Add a secret.
	post("/projects/"+projID+"/secrets", url.Values{"name": {"DB_PASSWORD"}, "value": {"hunter2"}})
	body := getBody(t, c, ts.URL+"/projects/"+projID)
	if !strings.Contains(body, "DB_PASSWORD") {
		t.Fatalf("secret name not listed after add; got: %.300s", body)
	}
	if strings.Contains(body, "hunter2") {
		t.Fatal("the secret VALUE must never appear in the project page")
	}

	// Edit prefill: the value comes back in the response BODY (POST), not a URL.
	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/machines"), "csrf")
	resp, err := c.PostForm(ts.URL+"/projects/"+projID+"/secrets/edit",
		url.Values{"csrf": {csrf}, "name": {"DB_PASSWORD"}})
	if err != nil {
		t.Fatalf("POST edit: %v", err)
	}
	editBody := readAll(t, resp)
	if !strings.Contains(editBody, "hunter2") {
		t.Fatalf("edit prefill should show the decrypted value in the form; got: %.400s", editBody)
	}

	// Reveal returns the value as JSON (the UI keeps it masked until clicked). The
	// value rides the POST response body, never a URL.
	resp, err = c.PostForm(ts.URL+"/projects/"+projID+"/secrets/reveal",
		url.Values{"csrf": {csrf}, "name": {"DB_PASSWORD"}})
	if err != nil {
		t.Fatalf("POST reveal: %v", err)
	}
	if revealBody := readAll(t, resp); !strings.Contains(revealBody, "hunter2") {
		t.Fatalf("reveal should return the decrypted value as JSON; got: %.200s", revealBody)
	}

	// A reveal without a CSRF token must be refused (no value returned).
	resp, err = c.PostForm(ts.URL+"/projects/"+projID+"/secrets/reveal",
		url.Values{"name": {"DB_PASSWORD"}})
	if err != nil {
		t.Fatalf("POST reveal without csrf: %v", err)
	}
	if noCSRF := readAll(t, resp); strings.Contains(noCSRF, "hunter2") {
		t.Fatal("reveal without a CSRF token must not return the value")
	}

	// Overwrite the value.
	post("/projects/"+projID+"/secrets", url.Values{"name": {"DB_PASSWORD"}, "value": {"newpass"}})

	// Add a second secret, then delete the first.
	post("/projects/"+projID+"/secrets", url.Values{"name": {"API_KEY"}, "value": {"abc"}})
	post("/projects/"+projID+"/secrets/delete", url.Values{"name": {"DB_PASSWORD"}})
	body = getBody(t, c, ts.URL+"/projects/"+projID)
	if strings.Contains(body, "DB_PASSWORD") {
		t.Fatalf("DB_PASSWORD should be gone after delete; got: %.300s", body)
	}
	if !strings.Contains(body, "API_KEY") {
		t.Fatalf("API_KEY should remain; got: %.300s", body)
	}

	// CSRF rejection: a secrets POST with no token must not change anything.
	resp, err = c.PostForm(ts.URL+"/projects/"+projID+"/secrets",
		url.Values{"name": {"INJECTED"}, "value": {"x"}})
	if err != nil {
		t.Fatalf("POST without csrf: %v", err)
	}
	resp.Body.Close()
	if body := getBody(t, c, ts.URL+"/projects/"+projID); strings.Contains(body, "INJECTED") {
		t.Fatal("CSRF-less secret POST should be rejected")
	}
}

// readAll reads a response body fully and closes it.
func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 1<<16)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}
