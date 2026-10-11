package web

import (
	"fmt"
	"net/http"
	"strings"

	"sopshq/internal/audit"
	"sopshq/internal/auth"
	"sopshq/internal/model"
)

// eventToggle is one notification event as shown in the UI: its stable Key (the
// model.Event* constant used in form names and the Events map), a human Label, and
// whether it is currently On.
type eventToggle struct {
	Key   string
	Label string
	On    bool
}

// notificationView is the Settings page "Notifications" panel data. It exposes the
// configuration by status only - never a credential. TelegramTokenSet and
// SlackWebhookSet report whether a sealed credential exists; the sealed blobs and
// the plaintext token/webhook are never copied here or rendered.
type notificationView struct {
	Available        bool   // a notifier is wired (serve, not a bare test server)
	Enabled          bool   // master on/off switch
	TelegramEnabled  bool   // the Telegram channel is on
	TelegramChatID   string // the Telegram chat/channel id (not secret)
	TelegramTokenSet bool   // a Telegram bot token has been sealed (never the value)
	SlackEnabled     bool   // the Slack channel is on
	SlackWebhookSet  bool   // a Slack webhook URL has been sealed (never the value)
	Events           []eventToggle
}

// notifyEvent pairs an event key with its human label. notifyEventOrder is the
// canonical render order AND the known vocabulary: saveNotificationConfig rebuilds
// the Events map from exactly these keys, defaulting any unchecked one to false.
type notifyEvent struct {
	key   string
	label string
}

var notifyEventOrder = []notifyEvent{
	{model.EventApply, "Apply ran"},
	{model.EventDrift, "Drift detected"},
	{model.EventBackup, "Backup result"},
	{model.EventFailedLogin, "Failed login"},
	{model.EventProjectWired, "Project wired"},
	{model.EventKeyGenerated, "Key generated"},
	{model.EventRotation, "Key rotation"},
	{model.EventSecretReveal, "Secret revealed"},
	{model.EventReplicationError, "Replication error"},
	{model.EventNewSession, "New session"},
	{model.EventLockout, "Account lockout"},
	{model.EventPermDrift, "Permission map drift"},
}

// notificationViewData assembles the notifications panel from this machine's stored
// settings. It exposes only non-secret fields; the sealed Telegram token and Slack
// webhook stay in the record and are reported as set/not-set only.
func (s *Server) notificationViewData() notificationView {
	n := s.store.NotificationSettingsFor(s.keys.LocalMachine())
	v := notificationView{
		Available:        s.notifier != nil,
		Enabled:          n.Enabled,
		TelegramEnabled:  n.TelegramEnabled,
		TelegramChatID:   n.TelegramChatID,
		TelegramTokenSet: n.TelegramTokenSealed != "",
		SlackEnabled:     n.SlackEnabled,
		SlackWebhookSet:  n.SlackWebhookSealed != "",
	}
	for _, e := range notifyEventOrder {
		v.Events = append(v.Events, eventToggle{
			Key:   e.key,
			Label: e.label,
			On:    n.Events[e.key],
		})
	}
	return v
}

// saveNotificationConfig stores the master switch, per-channel enables, the Telegram
// chat id, and the per-event toggles for this machine. Admin-only and CSRF-checked.
// The Events map is rebuilt from the known event vocabulary so an unchecked box
// becomes false and an unknown posted key is ignored. The audit row records a
// non-secret summary only.
func (s *Server) saveNotificationConfig(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/settings") {
		return
	}
	n := s.store.NotificationSettingsFor(s.keys.LocalMachine())
	n.Enabled = r.FormValue("enabled") != ""
	n.TelegramEnabled = r.FormValue("telegram_enabled") != ""
	n.SlackEnabled = r.FormValue("slack_enabled") != ""
	n.TelegramChatID = strings.TrimSpace(r.FormValue("chat_id"))

	events := make(map[string]bool, len(notifyEventOrder))
	on := 0
	for _, e := range notifyEventOrder {
		if r.FormValue("event_"+e.key) != "" {
			events[e.key] = true
			on++
		} else {
			events[e.key] = false
		}
	}
	n.Events = events

	if err := s.store.NotificationSettingsColl.Put(n); err != nil {
		s.renderError(w, r, sess, "Could not save the notification settings.", http.StatusInternalServerError)
		return
	}
	summary := fmt.Sprintf("enabled=%t telegram=%t slack=%t events_on=%d",
		n.Enabled, n.TelegramEnabled, n.SlackEnabled, on)
	s.audit.Record(sess.Username, "notify_config", "notification_settings", audit.OK, summary)
	redirect(w, r, "/settings", "Notification settings saved.", false)
}

// setNotificationTelegram seals the operator-supplied Telegram bot token into this
// machine's notification record. Admin-only and CSRF-checked. The plaintext token is
// sealed with the vault and only the sealed blob is persisted; the token is never
// logged, echoed, returned, or rendered. An empty token is rejected (nothing to set).
func (s *Server) setNotificationTelegram(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/settings") {
		return
	}
	token := strings.TrimSpace(r.FormValue("token"))
	if token == "" {
		redirect(w, r, "/settings", "Enter a Telegram bot token to set.", true)
		return
	}
	sealed, err := s.vault.Seal([]byte(token))
	if err != nil {
		s.renderError(w, r, sess, "Vault is locked; cannot seal the Telegram bot token.", http.StatusInternalServerError)
		return
	}
	n := s.store.NotificationSettingsFor(s.keys.LocalMachine())
	n.TelegramTokenSealed = sealed
	if chat := strings.TrimSpace(r.FormValue("chat_id")); chat != "" {
		n.TelegramChatID = chat
	}
	if err := s.store.NotificationSettingsColl.Put(n); err != nil {
		s.renderError(w, r, sess, "Could not save the notification settings.", http.StatusInternalServerError)
		return
	}
	s.audit.Record(sess.Username, "notify_telegram_set", "notification_settings", audit.OK, "")
	redirect(w, r, "/settings", "Telegram bot token set.", false)
}

// setNotificationSlack seals the operator-supplied Slack incoming-webhook URL into
// this machine's notification record. Admin-only and CSRF-checked. The webhook URL is
// a secret (it grants posting to the channel), so it is sealed with the vault and
// only the sealed blob is persisted; it is never logged, echoed, returned, or
// rendered. An empty webhook is rejected (nothing to set).
func (s *Server) setNotificationSlack(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/settings") {
		return
	}
	webhook := strings.TrimSpace(r.FormValue("webhook"))
	if webhook == "" {
		redirect(w, r, "/settings", "Enter a Slack webhook URL to set.", true)
		return
	}
	sealed, err := s.vault.Seal([]byte(webhook))
	if err != nil {
		s.renderError(w, r, sess, "Vault is locked; cannot seal the Slack webhook.", http.StatusInternalServerError)
		return
	}
	n := s.store.NotificationSettingsFor(s.keys.LocalMachine())
	n.SlackWebhookSealed = sealed
	if err := s.store.NotificationSettingsColl.Put(n); err != nil {
		s.renderError(w, r, sess, "Could not save the notification settings.", http.StatusInternalServerError)
		return
	}
	s.audit.Record(sess.Username, "notify_slack_set", "notification_settings", audit.OK, "")
	redirect(w, r, "/settings", "Slack webhook set.", false)
}

// testNotification sends one test message to the named channel (telegram|slack) and
// flashes the outcome. Admin-only and CSRF-checked. The notifier unseals the
// credential internally; any returned error is credential-free, so it is safe to
// flash.
func (s *Server) testNotification(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/settings") {
		return
	}
	channel := strings.TrimSpace(r.FormValue("channel"))
	if s.notifier == nil {
		redirect(w, r, "/settings", "Notifications are not available in this process.", true)
		return
	}
	if err := s.notifier.Test(channel); err != nil {
		s.audit.Record(sess.Username, "notify_test", channel, audit.Failed, "")
		redirect(w, r, "/settings", "Test failed: "+err.Error(), true)
		return
	}
	s.audit.Record(sess.Username, "notify_test", channel, audit.OK, "")
	redirect(w, r, "/settings", "Test message sent to "+channel+".", false)
}
