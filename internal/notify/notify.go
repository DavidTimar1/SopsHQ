// Package notify is SopsHQ's event-notification seam: a single Notifier the event
// sources call when something worth alerting on happens. It reads this machine's
// NotificationSettings record, formats a one-line ASCII message from
// names/UUIDs/outcomes ONLY, and fans the message out to every enabled channel
// (Telegram, Slack).
//
// SECURITY: a message NEVER carries a secret value (an age key, a passphrase, a
// TOTP secret, the bot token, or the webhook URL) - only names, UUIDs, counts,
// and outcomes. The channel credentials are vault-sealed in the record and
// unsealed in-process only at send time; a per-channel failure is logged by
// event + channel NAME, never the credential.
//
// A send NEVER blocks or fails the action that triggered it: Notify decides
// cheaply whether to send and, if so, performs the network fan-out on a
// background goroutine (each channel client carries its own timeout).
package notify

import (
	"errors"
	"fmt"
	"strings"

	"sopshq/internal/audit"
	"sopshq/internal/model"
	"sopshq/internal/slack"
	"sopshq/internal/store"
	"sopshq/internal/telegram"
	"sopshq/internal/vault"
)

// opener is the subset of *vault.Vault the notifier needs: turn a sealed
// credential back into its plaintext. It is an interface so tests can substitute
// a fake without a real vault.
type opener interface {
	Open(sealed string) ([]byte, error)
}

// Notifier reads the local machine's NotificationSettings and sends event
// messages to the enabled channels. The zero value is unusable; build one with
// New. A nil *Notifier is safe to call: every method is a no-op (or a clear
// error), so call sites need no nil guard.
type Notifier struct {
	store *store.Store
	vault opener
	audit *audit.Log
	local func() string // current local machine id (read live, like the backup runner)

	// Channel send funcs, overridable in tests. Production wires the real clients.
	sendTelegram func(token, chatID, text string) error
	sendSlack    func(webhookURL, text string) error
}

// New builds a Notifier. local returns the CURRENT local machine id each call, so
// re-designating the local machine at runtime takes effect without rebuilding the
// notifier (mirrors how the backup runner re-reads cfg.LocalMachineID).
func New(st *store.Store, v *vault.Vault, a *audit.Log, local func() string) *Notifier {
	return &Notifier{
		store:        st,
		vault:        v,
		audit:        a,
		local:        local,
		sendTelegram: telegram.SendMessage,
		sendSlack:    slack.SendWebhook,
	}
}

// settings returns the local machine's NotificationSettings (get-or-make, never
// nil). It reflects the latest stored record.
func (n *Notifier) settings() *model.NotificationSettings {
	return n.store.NotificationSettingsFor(n.local())
}

// target is one resolved, ready-to-send channel: a name for logging and a closure
// that performs the network send of a given message.
type target struct {
	channel string
	send    func(text string) error
}

// Notify alerts the enabled channels about eventType, using summary as the human
// description (names/UUIDs/outcome only - never a secret). It does nothing when
// the notifier is nil, the master switch is off, or eventType's toggle is off.
// The credential unsealing happens synchronously (cheap, in-process); only the
// network fan-out runs on a background goroutine, so the caller is never blocked.
func (n *Notifier) Notify(eventType, summary string) {
	if n == nil {
		return
	}
	rec := n.settings()
	if !rec.Enabled || !rec.Events[eventType] {
		return
	}
	targets := n.resolveTargets(rec)
	if len(targets) == 0 {
		return
	}
	text := formatMessage(summary)
	go func() {
		for _, t := range targets {
			if err := t.send(text); err != nil {
				n.logFailure(eventType, t.channel)
			}
		}
	}()
}

// resolveTargets unseals the credentials of every enabled, configured channel and
// returns a send closure per channel. A channel whose credential cannot be
// unsealed (vault locked) is skipped. The plaintext credentials live only inside
// the returned closures and are never logged.
func (n *Notifier) resolveTargets(rec *model.NotificationSettings) []target {
	var targets []target
	if rec.TelegramEnabled && rec.TelegramTokenSealed != "" && rec.TelegramChatID != "" {
		if tok, err := n.vault.Open(rec.TelegramTokenSealed); err == nil {
			token, chatID := string(tok), rec.TelegramChatID
			targets = append(targets, target{
				channel: "telegram",
				send:    func(text string) error { return n.sendTelegram(token, chatID, text) },
			})
		}
	}
	if rec.SlackEnabled && rec.SlackWebhookSealed != "" {
		if hook, err := n.vault.Open(rec.SlackWebhookSealed); err == nil {
			webhookURL := string(hook)
			targets = append(targets, target{
				channel: "slack",
				send:    func(text string) error { return n.sendSlack(webhookURL, text) },
			})
		}
	}
	return targets
}

// Test sends a fixed test line to ONE channel synchronously and returns the
// outcome, so an operator-facing "send test message" button can report success or
// failure. It does not consult the per-event toggles, but it does require the
// channel to be enabled and configured.
func (n *Notifier) Test(channel string) error {
	if n == nil {
		return errors.New("notify: notifier not available")
	}
	rec := n.settings()
	const text = "SopsHQ: test notification"
	switch channel {
	case "telegram":
		if !rec.TelegramEnabled || rec.TelegramTokenSealed == "" || rec.TelegramChatID == "" {
			return errors.New("telegram is not configured")
		}
		tok, err := n.vault.Open(rec.TelegramTokenSealed)
		if err != nil {
			return errors.New("could not open the telegram token (is the vault unlocked?)")
		}
		return n.sendTelegram(string(tok), rec.TelegramChatID, text)
	case "slack":
		if !rec.SlackEnabled || rec.SlackWebhookSealed == "" {
			return errors.New("slack is not configured")
		}
		hook, err := n.vault.Open(rec.SlackWebhookSealed)
		if err != nil {
			return errors.New("could not open the slack webhook (is the vault unlocked?)")
		}
		return n.sendSlack(string(hook), text)
	default:
		return fmt.Errorf("unknown channel %q", channel)
	}
}

// logFailure records a per-channel send failure by event + channel NAME only,
// never a credential. It is best-effort (auditing must not block the action).
func (n *Notifier) logFailure(eventType, channel string) {
	if n.audit == nil {
		return
	}
	_ = n.audit.Record("system", "notify", channel, audit.Failed, eventType)
}

// formatMessage builds the one-line ASCII message body from a summary. It
// collapses any newlines so the alert is a single line on every channel.
func formatMessage(summary string) string {
	one := strings.ReplaceAll(summary, "\r", " ")
	one = strings.ReplaceAll(one, "\n", " ")
	return "SopsHQ: " + one
}
