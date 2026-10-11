package web

import (
	"net/url"
	"strings"
	"testing"
)

// TestRenameKeyOverHTTP drives the rename through the real handler: define a key,
// rename it, and confirm the Keys page shows the new label. It also confirms the
// route is gated by CSRF and by login.
func TestRenameKeyOverHTTP(t *testing.T) {
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

	// Define a key (metadata only, no keypair needed to rename its label).
	post("/keys", url.Values{"name": {"adopted-alice"}, "type": {"shared"}})
	keyID := extract(t, reKeyGen, getBody(t, c, ts.URL+"/keys"), "key id")

	// Rename it and confirm the Keys page shows the new name.
	post("/keys/"+keyID+"/rename", url.Values{"name": {"billing"}})
	body := getBody(t, c, ts.URL+"/keys")
	if !strings.Contains(body, `value="billing"`) {
		t.Fatal("Keys page should show the renamed label")
	}
	if k, err := st.Keys.Get(keyID); err != nil || k.Name != "billing" {
		t.Fatalf("store name = %v (err %v), want billing", k, err)
	}

	// CSRF: a POST with a forged token must not rename.
	resp, err := c.PostForm(ts.URL+"/keys/"+keyID+"/rename", url.Values{"csrf": {"bogus"}, "name": {"hacked"}})
	if err != nil {
		t.Fatalf("POST forged csrf: %v", err)
	}
	resp.Body.Close()
	if k, _ := st.Keys.Get(keyID); k.Name != "billing" {
		t.Fatalf("forged CSRF renamed the key to %q", k.Name)
	}

	// Auth: an unauthenticated client is bounced to /login, not renamed.
	anon := newClient(t)
	resp, err = anon.PostForm(ts.URL+"/keys/"+keyID+"/rename", url.Values{"name": {"anon"}})
	if err != nil {
		t.Fatalf("anon POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.Request.URL.Path != "/login" {
		t.Fatalf("unauthenticated rename should redirect to /login, landed on %q", resp.Request.URL.Path)
	}
	if k, _ := st.Keys.Get(keyID); k.Name != "billing" {
		t.Fatalf("unauthenticated request renamed the key to %q", k.Name)
	}
}
