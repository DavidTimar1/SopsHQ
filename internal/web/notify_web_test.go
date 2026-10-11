package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"sopshq/internal/notify"
	"sopshq/internal/totp"
)

// TestSaveNotificationConfigPersists confirms /notifications/config writes the
// master switch, the per-channel enables, the chat id, and the per-event toggles
// onto this machine's record, and that an unchecked default-on event becomes false.
func TestSaveNotificationConfigPersists(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")
	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/settings"), "csrf")

	// Enable everything, set a chat id, turn ON apply + lockout, and OMIT drift
	// (a default-on event) so it must persist as false.
	resp, err := c.PostForm(ts.URL+"/notifications/config", url.Values{
		"csrf": {csrf}, "enabled": {"1"},
		"telegram_enabled": {"1"}, "slack_enabled": {"1"},
		"chat_id":     {"@my-channel"},
		"event_apply": {"1"}, "event_lockout": {"1"},
	})
	if err != nil {
		t.Fatalf("post config: %v", err)
	}
	resp.Body.Close()

	n := srv.store.NotificationSettingsFor(srv.keys.LocalMachine())
	if !n.Enabled || !n.TelegramEnabled || !n.SlackEnabled {
		t.Fatalf("master/channel switches not persisted: %+v", n)
	}
	if n.TelegramChatID != "@my-channel" {
		t.Fatalf("chat id not persisted: %q", n.TelegramChatID)
	}
	if !n.Events["apply"] || !n.Events["lockout"] {
		t.Fatalf("checked events not persisted: %+v", n.Events)
	}
	if n.Events["drift"] {
		t.Fatalf("an unchecked default-on event should be false, got %+v", n.Events)
	}
}

// TestSetNotificationCredentialsSeal confirms setting the Telegram token and the
// Slack webhook seals each (never the plaintext) and that neither plaintext reaches
// the rendered Settings page, which instead reports the credential as set.
func TestSetNotificationCredentialsSeal(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")
	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/settings"), "csrf")

	const token = "telegram-bot-token-xyz"
	resp, err := c.PostForm(ts.URL+"/notifications/telegram", url.Values{
		"csrf": {csrf}, "token": {token},
	})
	if err != nil {
		t.Fatalf("post telegram: %v", err)
	}
	resp.Body.Close()

	const webhook = "https://hooks.slack.example/T000/B000/secretpath"
	resp, err = c.PostForm(ts.URL+"/notifications/slack", url.Values{
		"csrf": {csrf}, "webhook": {webhook},
	})
	if err != nil {
		t.Fatalf("post slack: %v", err)
	}
	resp.Body.Close()

	n := srv.store.NotificationSettingsFor(srv.keys.LocalMachine())
	if n.TelegramTokenSealed == "" || n.TelegramTokenSealed == token {
		t.Fatal("telegram token was not sealed")
	}
	if got, err := srv.vault.Open(n.TelegramTokenSealed); err != nil || string(got) != token {
		t.Fatalf("sealed telegram token did not round-trip: %v", err)
	}
	if n.SlackWebhookSealed == "" || n.SlackWebhookSealed == webhook {
		t.Fatal("slack webhook was not sealed")
	}
	if got, err := srv.vault.Open(n.SlackWebhookSealed); err != nil || string(got) != webhook {
		t.Fatalf("sealed slack webhook did not round-trip: %v", err)
	}

	body := getBody(t, c, ts.URL+"/settings")
	if strings.Contains(body, token) || strings.Contains(body, webhook) {
		t.Fatal("the Settings page leaked a notification credential")
	}
	if !strings.Contains(body, "Set") {
		t.Fatal("the Settings page does not report a credential as Set")
	}
}

// TestNotificationTestRouteCallsNotifier confirms /notifications/test reaches the
// wired notifier, which performs a real Slack send to the configured webhook. The
// webhook points at a local test server so no external call is made.
func TestNotificationTestRouteCallsNotifier(t *testing.T) {
	ts, srv, _ := backupTestServer(t)

	var calls atomic.Int32
	slackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(slackSrv.Close)

	srv.SetNotifier(notify.New(srv.store, srv.vault, srv.audit, srv.keys.LocalMachine))

	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")
	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/settings"), "csrf")

	// Point the Slack webhook at the local test server and enable the channel.
	resp, err := c.PostForm(ts.URL+"/notifications/slack", url.Values{
		"csrf": {csrf}, "webhook": {slackSrv.URL},
	})
	if err != nil {
		t.Fatalf("set slack webhook: %v", err)
	}
	resp.Body.Close()
	resp, err = c.PostForm(ts.URL+"/notifications/config", url.Values{
		"csrf": {csrf}, "enabled": {"1"}, "slack_enabled": {"1"},
	})
	if err != nil {
		t.Fatalf("enable slack: %v", err)
	}
	resp.Body.Close()

	resp, err = c.PostForm(ts.URL+"/notifications/test", url.Values{
		"csrf": {csrf}, "channel": {"slack"},
	})
	if err != nil {
		t.Fatalf("post test: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if calls.Load() != 1 {
		t.Fatalf("expected the notifier to make 1 Slack send, got %d", calls.Load())
	}
	if !strings.Contains(string(body), "Test message sent to slack") {
		t.Fatalf("expected a success flash on the settings page after the test send")
	}
}

// TestNotificationRoutesRequireCSRF confirms a missing or forged CSRF token leaves
// the mutating notification routes inert.
func TestNotificationRoutesRequireCSRF(t *testing.T) {
	ts, srv, _ := backupTestServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	cases := []struct {
		path string
		form url.Values
	}{
		{"/notifications/config", url.Values{"enabled": {"1"}, "telegram_enabled": {"1"}}},
		{"/notifications/telegram", url.Values{"token": {"should-not-seal"}}},
		{"/notifications/slack", url.Values{"webhook": {"https://should-not-seal"}}},
	}
	for _, tc := range cases {
		resp, err := c.PostForm(ts.URL+tc.path, tc.form) // missing token
		if err != nil {
			t.Fatalf("post %s (no csrf): %v", tc.path, err)
		}
		resp.Body.Close()
		forged := url.Values{}
		for k, v := range tc.form {
			forged[k] = v
		}
		forged.Set("csrf", "bogus")
		resp, err = c.PostForm(ts.URL+tc.path, forged) // forged token
		if err != nil {
			t.Fatalf("post %s (forged csrf): %v", tc.path, err)
		}
		resp.Body.Close()
	}

	n := srv.store.NotificationSettingsFor(srv.keys.LocalMachine())
	if n.Enabled || n.TelegramEnabled || n.TelegramTokenSealed != "" || n.SlackWebhookSealed != "" {
		t.Fatalf("a CSRF-less or forged POST mutated the notification settings: %+v", n)
	}
}

// TestNotificationControlsAdminOnly confirms a developer cannot reach the
// notification routes (each returns 403).
func TestNotificationControlsAdminOnly(t *testing.T) {
	ts, _, _ := backupTestServer(t)
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

	dev.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, path := range []string{
		"/notifications/config", "/notifications/telegram",
		"/notifications/slack", "/notifications/test",
	} {
		resp, err := dev.PostForm(ts.URL+path, url.Values{"channel": {"slack"}})
		if err != nil {
			t.Fatalf("dev POST %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("developer POST %s: expected 403, got %d", path, resp.StatusCode)
		}
	}
}
