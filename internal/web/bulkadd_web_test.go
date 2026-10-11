package web

import (
	"net/http"
	"net/url"
	"testing"

	"sopshq/internal/totp"
)

// TestBulkAddSecretsIsAdminOnly: the reuse picker is shown to admins only, so the
// server must refuse a developer's POST (403) while an admin's POST reaches the handler.
func TestBulkAddSecretsIsAdminOnly(t *testing.T) {
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
	if _, err := dev.PostForm(ts.URL+"/login", url.Values{"username": {"dev"}, "password": {"devpassword"}}); err != nil {
		t.Fatalf("dev login: %v", err)
	}
	secret := extract(t, reSecret, getBody(t, dev, ts.URL+"/setup/totp"), "dev secret")
	code, _ := totp.Code(secret)
	resp, err = dev.PostForm(ts.URL+"/setup/totp", url.Values{"code": {code}, "saved": {"yes"}})
	if err != nil {
		t.Fatalf("dev enroll: %v", err)
	}
	resp.Body.Close()
	devCSRF := extract(t, reCSRF, getBody(t, dev, ts.URL+"/conflicts"), "dev csrf")

	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	dev.CheckRedirect = noRedirect
	admin.CheckRedirect = noRedirect
	const route = "/projects/p1/secrets/bulk-add"

	resp, err = dev.PostForm(ts.URL+route, url.Values{"csrf": {devCSRF}, "pick": {"p2|API_KEY"}})
	if err != nil {
		t.Fatalf("dev POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("developer on bulk-add: expected 403, got %d", resp.StatusCode)
	}

	// No picks: the admin passes the role gate and the handler redirects back with a flash.
	resp, err = admin.PostForm(ts.URL+route, url.Values{"csrf": {csrf}})
	if err != nil {
		t.Fatalf("admin POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("admin on bulk-add: expected 303 redirect, got %d", resp.StatusCode)
	}
}
