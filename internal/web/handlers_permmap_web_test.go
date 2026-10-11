package web

import (
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"testing"

	"sopshq/internal/totp"
)

// TestPermmapRequiresLogin confirms the auditor route is login-gated.
func TestPermmapRequiresLogin(t *testing.T) {
	ts, _ := testServer(t)
	c := newClient(t)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Get(ts.URL + "/permmap")
	if err != nil {
		t.Fatalf("GET /permmap: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("GET /permmap unauthenticated: expected redirect to /login, got %d %q",
			resp.StatusCode, resp.Header.Get("Location"))
	}
}

// TestPermmapAdminOnly confirms a developer is refused the auditor page.
func TestPermmapAdminOnly(t *testing.T) {
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

	body := getBody(t, dev, ts.URL+"/permmap")
	if !strings.Contains(body, "Admins only.") {
		t.Errorf("developer reached the permission auditor page; want admin-only refusal")
	}
}

// TestPermmapPageRendersForAdmin confirms the page renders for an admin. Off Linux
// it shows the "Linux only" notice; the heading is always present.
func TestPermmapPageRendersForAdmin(t *testing.T) {
	ts, _ := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	body := getBody(t, c, ts.URL+"/permmap")
	if !strings.Contains(body, "Permissions") {
		t.Fatalf("permmap page missing heading")
	}
	if runtime.GOOS != "linux" && !strings.Contains(body, "Linux only") {
		t.Errorf("off Linux the page should show the Linux-only notice")
	}
}

// TestPermmapDataEmptyWithoutScan confirms the data feed returns an empty, total-0
// result when no scan has been stored (the test server wires no permmap store).
func TestPermmapDataEmptyWithoutScan(t *testing.T) {
	ts, _ := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	body := getBody(t, c, ts.URL+"/permmap/data?filter=dangerous")
	if !strings.Contains(body, `"total":0`) {
		t.Errorf("permmap data without a scan: want total 0, got %s", body)
	}
}
