package web

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sopshq/internal/config"
	"sopshq/internal/totp"
)

// TestSettingsShowsKeybaseRoot confirms the Settings page shows the current
// keys root folder, and says keys stay under each user's home when it is unset.
func TestSettingsShowsKeybaseRoot(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	body := getBody(t, c, ts.URL+"/settings")
	if !strings.Contains(body, "Keys root folder") {
		t.Fatal("settings page missing the keys root folder panel")
	}
	if !strings.Contains(body, "not set - keys stay under each user's home") {
		t.Fatalf("settings page did not describe an unset root as keys under each user's home:\n%s", body)
	}

	root := t.TempDir()
	srv.keys.SetKeybaseRoot(root)
	body = getBody(t, c, ts.URL+"/settings")
	if !strings.Contains(body, root) {
		t.Fatalf("settings page did not show the configured root %q", root)
	}
}

// TestSaveKeybaseRootPersists confirms a valid save writes config.jsonc and
// updates the live key service, and that it never moves any key (there is
// nothing here for it to move, so this only proves no placement call happens).
func TestSaveKeybaseRootPersists(t *testing.T) {
	ts, srv, cfg := backupTestServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")
	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/settings"), "csrf")

	root := t.TempDir()
	resp, err := c.PostForm(ts.URL+"/settings/keybase-root", url.Values{
		"csrf": {csrf}, "keybase_root": {root},
	})
	if err != nil {
		t.Fatalf("save keybase root: %v", err)
	}
	resp.Body.Close()

	if srv.cfg.KeybaseRoot != root {
		t.Fatalf("in-memory config not updated: got %q, want %q", srv.cfg.KeybaseRoot, root)
	}
	if srv.keys.KeybaseRoot() != root {
		t.Fatalf("live key service not updated: got %q, want %q", srv.keys.KeybaseRoot(), root)
	}
	got, err := config.Load(cfg.Path())
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if got.KeybaseRoot != root {
		t.Fatalf("on-disk config not persisted: got %q, want %q", got.KeybaseRoot, root)
	}

	// Setting it back to empty is accepted and means no root.
	resp, err = c.PostForm(ts.URL+"/settings/keybase-root", url.Values{
		"csrf": {csrf}, "keybase_root": {""},
	})
	if err != nil {
		t.Fatalf("clear keybase root: %v", err)
	}
	resp.Body.Close()
	if srv.cfg.KeybaseRoot != "" || srv.keys.KeybaseRoot() != "" {
		t.Fatalf("clearing the root did not take: cfg=%q live=%q", srv.cfg.KeybaseRoot, srv.keys.KeybaseRoot())
	}
}

// TestSaveKeybaseRootRejectsInvalid confirms each invalid value is refused with a
// plain-sentence flash and leaves the stored config untouched.
func TestSaveKeybaseRootRejectsInvalid(t *testing.T) {
	ts, srv, cfg := backupTestServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")
	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/settings"), "csrf")

	notADir := filepath.Join(t.TempDir(), "not-a-folder.txt")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	cases := []struct {
		name string
		root string
		want string
	}{
		{"relative", "relative/keys", "must be an absolute path"},
		{"same as data dir", cfg.DataDir, "different from the data directory"},
		{"missing", missing, "does not exist"},
		{"not a folder", notADir, "not a folder"},
	}
	for _, tc := range cases {
		resp, err := c.PostForm(ts.URL+"/settings/keybase-root", url.Values{
			"csrf": {csrf}, "keybase_root": {tc.root},
		})
		if err != nil {
			t.Fatalf("%s: post: %v", tc.name, err)
		}
		loc := resp.Request.URL.String()
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("%s: read body: %v", tc.name, err)
		}
		if !strings.Contains(loc, "err=1") {
			t.Fatalf("%s: expected an error flash, landed at %s", tc.name, loc)
		}
		if !strings.Contains(string(body), tc.want) {
			t.Fatalf("%s: expected the flash to say %q, got:\n%s", tc.name, tc.want, body)
		}
		if srv.cfg.KeybaseRoot != "" {
			t.Fatalf("%s: rejected save changed the in-memory config: %q", tc.name, srv.cfg.KeybaseRoot)
		}
	}

	got, err := config.Load(cfg.Path())
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if got.KeybaseRoot != "" {
		t.Fatalf("a rejected save wrote config.jsonc: %q", got.KeybaseRoot)
	}
}

// TestSaveKeybaseRootRequiresCSRF confirms a missing or forged token changes
// nothing.
func TestSaveKeybaseRootRequiresCSRF(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	root := t.TempDir()
	for _, form := range []url.Values{
		{"keybase_root": {root}},
		{"csrf": {"bogus"}, "keybase_root": {root}},
	} {
		resp, err := c.PostForm(ts.URL+"/settings/keybase-root", form)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
	}
	if srv.cfg.KeybaseRoot != "" || srv.keys.KeybaseRoot() != "" {
		t.Fatal("a CSRF-less or forged POST changed the keys root folder")
	}
}

// TestSaveKeybaseRootAdminOnly confirms a developer cannot reach the route (403)
// and does not see the change form on Settings.
func TestSaveKeybaseRootAdminOnly(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
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

	body := getBody(t, dev, ts.URL+"/settings")
	if strings.Contains(body, "Change the keys root folder") {
		t.Fatal("developer should not see the keys root folder form on Settings")
	}
	if !strings.Contains(body, "Keys root folder controls are available to administrators") {
		t.Fatal("developer should see the admin-only keys root folder note on Settings")
	}

	dev.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	root := t.TempDir()
	resp, err = dev.PostForm(ts.URL+"/settings/keybase-root", url.Values{"keybase_root": {root}})
	if err != nil {
		t.Fatalf("dev POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("developer POST /settings/keybase-root: expected 403, got %d", resp.StatusCode)
	}
	if srv.cfg.KeybaseRoot != "" {
		t.Fatalf("developer's forbidden POST somehow changed the root: %q", srv.cfg.KeybaseRoot)
	}
}
