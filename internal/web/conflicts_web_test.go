package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"sopshq/internal/model"
	"sopshq/internal/totp"
)

// TestConflictMergeTwoStepGuard drives the conflict UI over real HTTP: a differing-field
// duplicate is listed on /conflicts, the execute endpoint REFUSES to delete without the
// step-2 confirmation checkbox, and only a confirmed request merges the records.
func TestConflictMergeTwoStepGuard(t *testing.T) {
	ts, st := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	// Two keys share a public key but hold different sealed private halves.
	for _, k := range []*model.Key{
		{M: model.Meta{UUID: "k1"}, Name: "one", Type: model.KeyShared, Recipient: "age1same", PrivSealed: "A", Status: model.KeyActive},
		{M: model.Meta{UUID: "k2"}, Name: "two", Type: model.KeyShared, Recipient: "age1same", PrivSealed: "B", Status: model.KeyActive},
	} {
		if err := st.Keys.Put(k); err != nil {
			t.Fatalf("put key: %v", err)
		}
	}

	body := getBody(t, c, ts.URL+"/conflicts")
	if !strings.Contains(body, "Conflicts to resolve") || !strings.Contains(body, "Merge into one") {
		t.Fatalf("conflicts page should list the group; got: %.200s", body)
	}
	csrf := extract(t, reCSRF, body, "csrf")

	// Step-2 endpoint WITHOUT the confirmation token: nothing is deleted.
	resp, err := c.PostForm(ts.URL+"/conflicts/merge/execute", url.Values{
		"csrf": {csrf}, "entity": {"key"}, "ids": {"k1,k2"}, "pick_priv": {"k2"},
	})
	if err != nil {
		t.Fatalf("execute without confirm: %v", err)
	}
	resp.Body.Close()
	if n := len(st.Keys.List()); n != 2 {
		t.Fatalf("execute without the confirm token must delete nothing; keys=%d", n)
	}

	// With the explicit confirmation, the merge proceeds.
	resp, err = c.PostForm(ts.URL+"/conflicts/merge/execute", url.Values{
		"csrf": {csrf}, "entity": {"key"}, "ids": {"k1,k2"}, "pick_priv": {"k2"}, "confirm_delete": {"yes"},
	})
	if err != nil {
		t.Fatalf("execute with confirm: %v", err)
	}
	resp.Body.Close()
	if n := len(st.Keys.List()); n != 1 {
		t.Fatalf("confirmed merge should leave one key; keys=%d", n)
	}
	sv, err := st.Keys.Get("k1")
	if err != nil {
		t.Fatalf("survivor must remain: %v", err)
	}
	if sv.PrivSealed != "B" {
		t.Fatalf("picked private half must win; got %q", sv.PrivSealed)
	}
}

// TestConflictResolutionIsAdminOnly is Medium-2: a developer may VIEW /conflicts but the
// destructive resolution routes reject them, while an admin is allowed.
func TestConflictResolutionIsAdminOnly(t *testing.T) {
	ts, st := testServer(t)
	admin := newClient(t)
	onboard(t, ts, admin, "admin", "supersecret")

	// Two conflicting keys to resolve.
	for _, k := range []*model.Key{
		{M: model.Meta{UUID: "k1"}, Name: "one", Type: model.KeyShared, Recipient: "age1same", PrivSealed: "A", Status: model.KeyActive},
		{M: model.Meta{UUID: "k2"}, Name: "two", Type: model.KeyShared, Recipient: "age1same", PrivSealed: "B", Status: model.KeyActive},
	} {
		if err := st.Keys.Put(k); err != nil {
			t.Fatalf("put key: %v", err)
		}
	}

	// Admin creates a developer.
	csrf := extract(t, reCSRF, getBody(t, admin, ts.URL+"/users"), "csrf")
	resp, err := admin.PostForm(ts.URL+"/users", url.Values{
		"csrf": {csrf}, "new_user_name": {"dev"}, "new_user_secret": {"devpassword"}, "role": {"developer"},
	})
	if err != nil {
		t.Fatalf("create dev: %v", err)
	}
	resp.Body.Close()

	// Developer logs in and enrolls TOTP.
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

	// Developer CAN view the read-only list.
	if body := getBody(t, dev, ts.URL+"/conflicts"); !strings.Contains(body, "Conflicts to resolve") {
		t.Fatalf("developer should see the conflicts list")
	}
	devCSRF := extract(t, reCSRF, getBody(t, dev, ts.URL+"/conflicts"), "dev csrf")

	// Developer is REFUSED on every destructive route (403).
	dev.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, route := range []string{"/conflicts/merge/confirm", "/conflicts/merge/execute", "/conflicts/keep-both"} {
		resp, err := dev.PostForm(ts.URL+route, url.Values{
			"csrf": {devCSRF}, "entity": {"key"}, "ids": {"k1,k2"}, "confirm_delete": {"yes"}, "pick_priv": {"k2"},
		})
		if err != nil {
			t.Fatalf("dev POST %s: %v", route, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("developer on %s: expected 403, got %d", route, resp.StatusCode)
		}
	}
	// Nothing was deleted by the refused developer requests.
	if n := len(st.Keys.List()); n != 2 {
		t.Fatalf("refused developer requests must delete nothing; keys=%d", n)
	}
}
