package web

import (
	"net/url"
	"os/exec"
	"strings"
	"testing"
)

// TestKeyLifecycleOverHTTP drives the key-lifecycle changes through the real HTTP
// handlers: a freshly defined key is called out as unused in the Keys table; assigning
// it to a project mints its keypair on first use (no manual Generate step); the table
// then shows it as placed; and the Global page offers set creation once a per-user key
// is owned by a local OS user.
func TestKeyLifecycleOverHTTP(t *testing.T) {
	ts, st := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	post := func(path string, vals url.Values) {
		t.Helper()
		csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/keys"), "csrf")
		vals.Set("csrf", csrf)
		resp, err := c.PostForm(ts.URL+path, vals)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		resp.Body.Close()
	}

	// Define a key with no keypair. The Keys table must loudly call it out as unused.
	post("/keys", url.Values{"name": {"billing"}, "type": {"shared"}})
	keyID := extract(t, reKeyGen, getBody(t, c, ts.URL+"/keys"), "key id")
	if body := getBody(t, c, ts.URL+"/keys"); !strings.Contains(body, "Unused - no keypair or key files yet") {
		t.Fatalf("Keys table should call out the unused, ungenerated key")
	}

	// The rest exercises auto-generation on assignment, which mints a real age keypair.
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH (assignment auto-generation needs it)")
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

	// Assign the still-ungenerated key: the handler must generate the keypair first.
	post("/assignments", url.Values{
		"project_id": {projID}, "key_id": {keyID}, "machine_id": {machineID}, "os_user_id": {osUserID},
	})
	k, err := st.Keys.Get(keyID)
	if err != nil || k.Recipient == "" {
		t.Fatalf("assigning an ungenerated key should auto-generate its keypair: recipient=%q err=%v", k.Recipient, err)
	}

	// The Keys table now shows the key as placed (its public key + a placement row),
	// not the unused badge.
	body := getBody(t, c, ts.URL+"/keys")
	if strings.Contains(body, "Unused - no keypair or key files yet") {
		t.Fatal("an assigned key must no longer read as unused")
	}
	if !strings.Contains(body, k.Recipient) {
		t.Fatalf("Keys table should show the generated public key %q", k.Recipient)
	}

	// The Global page offers set creation once a per-user key is OWNED by a local OS
	// user (an owned key builds a set directly, no project-wiring detour).
	post("/keys", url.Values{"name": {"devowned"}, "type": {"per_user"}, "owner_user_id": {osUserID}})
	if gbody := getBody(t, c, ts.URL+"/global"); !strings.Contains(gbody, "Create set") {
		t.Fatalf("Global page should offer set creation once a per-user key is owned by a local OS user")
	}
}

// TestGeneratedNotPlacedStatus confirms the middle lifecycle state: a key that has a
// keypair but is not assigned anywhere reads as "Keypair created; not placed ...".
func TestGeneratedNotPlacedStatus(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	ts, _ := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	post := func(path string, vals url.Values) {
		t.Helper()
		csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/keys"), "csrf")
		vals.Set("csrf", csrf)
		resp, err := c.PostForm(ts.URL+path, vals)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		resp.Body.Close()
	}

	post("/keys", url.Values{"name": {"solo"}, "type": {"shared"}})
	keyID := extract(t, reKeyGen, getBody(t, c, ts.URL+"/keys"), "key id")
	// Manually generate (the additive button), without assigning it anywhere.
	post("/keys/"+keyID+"/generate", url.Values{})

	body := getBody(t, c, ts.URL+"/keys")
	if !strings.Contains(body, "Keypair created; not placed on any machine yet") {
		t.Fatalf("a generated-but-unassigned key should read as created-not-placed")
	}
	if strings.Contains(body, "Unused - no keypair or key files yet") {
		t.Fatalf("a generated key must not read as unused")
	}
}
