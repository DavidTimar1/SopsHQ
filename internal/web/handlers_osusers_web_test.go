package web

import (
	"net/url"
	"testing"
)

// TestOSUserInputRejectedOverHTTP proves the /osusers boundary rejects a username or
// keystore path that could carry a shell payload into the printed Mode-A sudo block.
// A rejected request must persist NOTHING (nothing to render, nothing to replicate);
// a benign request is stored. It asserts against the store directly, so it does not
// depend on HTML rendering.
func TestOSUserInputRejectedOverHTTP(t *testing.T) {
	ts, st := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	post := func(vals url.Values) {
		t.Helper()
		csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/machines"), "csrf")
		vals.Set("csrf", csrf)
		resp, err := c.PostForm(ts.URL+"/osusers", vals)
		if err != nil {
			t.Fatalf("POST /osusers: %v", err)
		}
		resp.Body.Close()
	}

	// Register a machine (not designated local, so resolveKeyBase does no getent
	// lookup - the test stays hermetic and deterministic).
	{
		csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/machines"), "csrf")
		resp, err := c.PostForm(ts.URL+"/machines", url.Values{"name": {"local"}, "os": {"linux"}, "csrf": {csrf}})
		if err != nil {
			t.Fatalf("POST /machines: %v", err)
		}
		resp.Body.Close()
	}
	machineID := extract(t, reMachineLocal, getBody(t, c, ts.URL+"/machines"), "machine id")

	// Every one of these must be refused: metacharacter usernames, a leading dash, and
	// metacharacter / leading-dash keystore paths.
	bad := []url.Values{
		{"machine_id": {machineID}, "os_username": {"svc$(reboot)"}, "key_base": {"/etc/svc/keys"}},
		{"machine_id": {machineID}, "os_username": {"a;b"}, "key_base": {"/etc/svc/keys"}},
		{"machine_id": {machineID}, "os_username": {"-x"}, "key_base": {"/etc/svc/keys"}},
		{"machine_id": {machineID}, "os_username": {"svc"}, "key_base": {"/mnt/x; rm -rf /"}},
		{"machine_id": {machineID}, "os_username": {"svc"}, "key_base": {"-rf"}},
		{"machine_id": {machineID}, "os_username": {"svc"}, "use_secure": {"1"}, "secure_dir": {"/a$(reboot)"}},
	}
	for _, v := range bad {
		post(v)
	}
	if n := len(st.OSUsers.List()); n != 0 {
		t.Fatalf("expected no OS users stored after rejected posts, got %d", n)
	}

	// A benign account with a valid explicit keystore is accepted.
	post(url.Values{"machine_id": {machineID}, "os_username": {"mailsvc"}, "key_base": {"/etc/mailsvc/keys"}})
	users := st.OSUsers.List()
	if len(users) != 1 {
		t.Fatalf("expected 1 OS user after a valid add, got %d", len(users))
	}
	if users[0].Username != "mailsvc" || users[0].KeyBase != "/etc/mailsvc/keys" {
		t.Fatalf("stored user = %q keybase %q, want mailsvc /etc/mailsvc/keys", users[0].Username, users[0].KeyBase)
	}
}
