package notify

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sopshq/internal/audit"
	"sopshq/internal/model"
	"sopshq/internal/store"
	"sopshq/internal/vault"
)

const testMachine = "machine-1"

// harness builds a notifier over a sandboxed store + vault and replaces the
// channel send funcs with fakes that report each send onto a channel. Nothing
// touches a real endpoint or real state.
type harness struct {
	n     *Notifier
	store *store.Store
	vault *vault.Vault
	sent  chan string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	v, err := vault.Init(filepath.Join(dir, "vault"), "test-pass")
	if err != nil {
		t.Fatalf("vault init: %v", err)
	}
	st, err := store.Open(filepath.Join(dir, "data"), "test-node", nil)
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	a := audit.Open(filepath.Join(dir, "audit.jsonl"), "test-node", nil)
	n := New(st, v, a, func() string { return testMachine })
	h := &harness{n: n, store: st, vault: v, sent: make(chan string, 8)}
	n.sendTelegram = func(token, chatID, text string) error {
		h.sent <- "telegram|" + token + "|" + chatID + "|" + text
		return nil
	}
	n.sendSlack = func(webhookURL, text string) error {
		h.sent <- "slack|" + webhookURL + "|" + text
		return nil
	}
	return h
}

// configure builds and persists the machine's NotificationSettings, sealing any
// non-empty credential through the real vault.
func (h *harness) configure(t *testing.T, master, telOn, slackOn bool, token, chatID, webhook string) *model.NotificationSettings {
	t.Helper()
	rec := h.store.NotificationSettingsFor(testMachine)
	rec.Enabled = master
	rec.TelegramEnabled = telOn
	rec.TelegramChatID = chatID
	if token != "" {
		sealed, err := h.vault.Seal([]byte(token))
		if err != nil {
			t.Fatalf("seal token: %v", err)
		}
		rec.TelegramTokenSealed = sealed
	}
	rec.SlackEnabled = slackOn
	if webhook != "" {
		sealed, err := h.vault.Seal([]byte(webhook))
		if err != nil {
			t.Fatalf("seal webhook: %v", err)
		}
		rec.SlackWebhookSealed = sealed
	}
	if err := h.store.NotificationSettingsColl.Put(rec); err != nil {
		t.Fatalf("put settings: %v", err)
	}
	return rec
}

// waitFor collects exactly n sends or fails on timeout.
func (h *harness) waitFor(t *testing.T, n int) []string {
	t.Helper()
	var got []string
	deadline := time.After(2 * time.Second)
	for len(got) < n {
		select {
		case s := <-h.sent:
			got = append(got, s)
		case <-deadline:
			t.Fatalf("timed out waiting for %d send(s), got %d: %v", n, len(got), got)
		}
	}
	return got
}

// expectNone asserts no send happens within a short window.
func (h *harness) expectNone(t *testing.T) {
	t.Helper()
	select {
	case s := <-h.sent:
		t.Fatalf("expected no send, got %q", s)
	case <-time.After(150 * time.Millisecond):
	}
}

// TestNotifyFansOutToEnabledChannels confirms an enabled event reaches both
// channels, that the formatted message carries the summary but never a sealed
// credential's plaintext, and that the right chat id / token is used.
func TestNotifyFansOutToEnabledChannels(t *testing.T) {
	h := newHarness(t)
	const (
		token   = "super-secret-token"
		chatID  = "chat-7"
		webhook = "https://hooks.example/secret-webhook"
	)
	h.configure(t, true, true, true, token, chatID, webhook)

	h.n.Notify(model.EventApply, "Local apply: 1 keys placed")
	got := h.waitFor(t, 2)

	var sawTelegram, sawSlack bool
	for _, s := range got {
		switch {
		case strings.HasPrefix(s, "telegram|"):
			sawTelegram = true
			if !strings.Contains(s, "|"+token+"|"+chatID+"|") {
				t.Errorf("telegram send missing token/chat: %q", s)
			}
		case strings.HasPrefix(s, "slack|"):
			sawSlack = true
			if !strings.Contains(s, "|"+webhook+"|") {
				t.Errorf("slack send missing webhook: %q", s)
			}
		}
		// The MESSAGE TEXT is the last field; it must never carry a secret.
		text := s[strings.LastIndex(s, "|")+1:]
		if strings.Contains(text, token) || strings.Contains(text, webhook) {
			t.Errorf("message text leaked a credential: %q", text)
		}
		if !strings.Contains(text, "Local apply: 1 keys placed") {
			t.Errorf("message text missing summary: %q", text)
		}
	}
	if !sawTelegram || !sawSlack {
		t.Fatalf("expected both channels, telegram=%v slack=%v", sawTelegram, sawSlack)
	}
}

// TestNotifyRespectsMasterSwitch confirms nothing sends when the master switch is
// off even though both channels are enabled and the event is on.
func TestNotifyRespectsMasterSwitch(t *testing.T) {
	h := newHarness(t)
	h.configure(t, false, true, true, "tok", "chat", "https://hooks.example/x")
	h.n.Notify(model.EventApply, "anything")
	h.expectNone(t)
}

// TestNotifyRespectsEventToggle confirms an event whose toggle is off (default for
// EventSecretReveal) sends nothing, while a default-on event does send.
func TestNotifyRespectsEventToggle(t *testing.T) {
	h := newHarness(t)
	h.configure(t, true, true, false, "tok", "chat", "")

	h.n.Notify(model.EventSecretReveal, "reveal X")
	h.expectNone(t)

	h.n.Notify(model.EventApply, "apply ran")
	got := h.waitFor(t, 1)
	if !strings.HasPrefix(got[0], "telegram|") {
		t.Fatalf("expected a telegram send, got %q", got[0])
	}
}

// TestNotifyRespectsPerChannelEnable confirms a disabled channel is skipped: with
// Telegram off and Slack on, only Slack receives the event.
func TestNotifyRespectsPerChannelEnable(t *testing.T) {
	h := newHarness(t)
	h.configure(t, true, false, true, "tok", "chat", "https://hooks.example/only-slack")

	h.n.Notify(model.EventApply, "apply ran")
	got := h.waitFor(t, 1)
	if !strings.HasPrefix(got[0], "slack|") {
		t.Fatalf("expected only a slack send, got %q", got[0])
	}
	h.expectNone(t) // no second (telegram) send
}

// TestSealingRoundTrips confirms the get-or-make persists a record whose
// credential fields are sealed ciphertext (not the plaintext), and that the vault
// opens them back to the originals.
func TestSealingRoundTrips(t *testing.T) {
	h := newHarness(t)
	const (
		token   = "round-trip-token"
		webhook = "https://hooks.example/round-trip"
	)
	h.configure(t, true, true, true, token, "chat", webhook)

	rec := h.store.NotificationSettingsFor(testMachine)
	if rec.TelegramTokenSealed == "" || rec.TelegramTokenSealed == token {
		t.Fatalf("telegram token not sealed: %q", rec.TelegramTokenSealed)
	}
	if rec.SlackWebhookSealed == "" || rec.SlackWebhookSealed == webhook {
		t.Fatalf("slack webhook not sealed: %q", rec.SlackWebhookSealed)
	}
	openTok, err := h.vault.Open(rec.TelegramTokenSealed)
	if err != nil || string(openTok) != token {
		t.Fatalf("token did not round-trip: %v / %q", err, openTok)
	}
	openHook, err := h.vault.Open(rec.SlackWebhookSealed)
	if err != nil || string(openHook) != webhook {
		t.Fatalf("webhook did not round-trip: %v / %q", err, openHook)
	}
}

// TestGetOrMakeDefaults confirms a fresh machine yields a disabled record with the
// curated default-on event set, and that two get-or-make calls return the same id.
func TestGetOrMakeDefaults(t *testing.T) {
	h := newHarness(t)
	rec := h.store.NotificationSettingsFor(testMachine)
	if rec.Enabled {
		t.Error("a fresh record should be disabled")
	}
	for _, on := range []string{model.EventApply, model.EventDrift, model.EventBackup, model.EventFailedLogin} {
		if !rec.Events[on] {
			t.Errorf("event %q should default ON", on)
		}
	}
	for _, off := range []string{model.EventSecretReveal, model.EventRotation, model.EventLockout} {
		if rec.Events[off] {
			t.Errorf("event %q should default OFF", off)
		}
	}
	// Persist, then the get-or-make must return the SAME record (same id).
	if err := h.store.NotificationSettingsColl.Put(rec); err != nil {
		t.Fatalf("put: %v", err)
	}
	again := h.store.NotificationSettingsFor(testMachine)
	if again.M.UUID != rec.M.UUID {
		t.Fatalf("get-or-make minted a new id: %q != %q", again.M.UUID, rec.M.UUID)
	}
}

// TestTestHelper confirms Test sends to a configured channel and errors clearly on
// an unconfigured one.
func TestTestHelper(t *testing.T) {
	h := newHarness(t)
	h.configure(t, true, false, true, "", "", "https://hooks.example/test")

	if err := h.n.Test("slack"); err != nil {
		t.Fatalf("Test(slack): %v", err)
	}
	got := h.waitFor(t, 1)
	if !strings.HasPrefix(got[0], "slack|") || !strings.Contains(got[0], "test notification") {
		t.Fatalf("unexpected slack test send: %q", got[0])
	}
	if err := h.n.Test("telegram"); err == nil {
		t.Fatal("Test(telegram) should error when telegram is not configured")
	}
	if err := h.n.Test("email"); err == nil {
		t.Fatal("Test(unknown channel) should error")
	}
}

// TestNilNotifierIsNoOp confirms a nil notifier's Notify is safe and Test errors.
func TestNilNotifierIsNoOp(t *testing.T) {
	var n *Notifier
	n.Notify(model.EventApply, "x") // must not panic
	if err := n.Test("slack"); err == nil {
		t.Fatal("nil notifier Test should return an error")
	}
}
