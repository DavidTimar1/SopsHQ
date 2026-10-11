package web

import (
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sopshq/internal/keys"
	"sopshq/internal/place"
)

// TestImportAlertAndImportOverHTTP drives bug 2 through the real handlers: a key that
// appears on disk in a registered OS user's keystore AFTER the user was added is
// surfaced as importable on both the Keys and OS users pages, and one click imports
// it (exactly one Key + assignment, deduped) so the alert clears.
func TestImportAlertAndImportOverHTTP(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
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

	keyBase := t.TempDir() // empty at OS-user add time, so nothing is adopted then
	post("/machines", url.Values{"name": {"local"}, "os": {"windows"}})
	machineID := extract(t, reMachineLocal, getBody(t, c, ts.URL+"/machines"), "machine id")
	post("/machines/"+machineID+"/local", url.Values{})
	post("/osusers", url.Values{"machine_id": {machineID}, "os_username": {"dev"}, "key_base": {keyBase}})
	osUserID := extract(t, reOSUserDel, getBody(t, c, ts.URL+"/osusers"), "os user id")

	// A key appears on disk later (added outside SopsHQ).
	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := os.WriteFile(place.KeyFile(keyBase), []byte(kp.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant key: %v", err)
	}

	// The alert now shows on Keys and OS users, with an Import form for this user.
	wantForm := "/osusers/" + osUserID + "/import-keys"
	for _, page := range []string{"/keys", "/osusers"} {
		body := getBody(t, c, ts.URL+page)
		if !strings.Contains(body, "Found 1 key(s) on disk not in your database.") {
			t.Fatalf("%s: expected import alert, not found", page)
		}
		if !strings.Contains(body, wantForm) {
			t.Fatalf("%s: expected Import form %q", page, wantForm)
		}
	}

	// One click imports it.
	post("/osusers/"+osUserID+"/import-keys", url.Values{"back": {"/keys"}})
	if len(st.Keys.List()) != 1 || len(st.Assignments.List()) != 1 {
		t.Fatalf("import must create exactly one key + assignment; keys=%d asg=%d", len(st.Keys.List()), len(st.Assignments.List()))
	}
	if st.Keys.List()[0].Recipient != kp.Recipient {
		t.Fatalf("imported key public-key mismatch")
	}
	// The alert is gone now that the key is tracked.
	if body := getBody(t, c, ts.URL+"/keys"); strings.Contains(body, "not in your database") {
		t.Fatal("import alert should be gone after importing")
	}
	// The on-disk file was never modified by the scan or the import.
	if b, _ := os.ReadFile(filepath.Join(keyBase, "keys.txt")); strings.TrimSpace(string(b)) != strings.TrimSpace(kp.Private) {
		t.Fatal("import/scan modified the on-disk keys.txt")
	}
}
