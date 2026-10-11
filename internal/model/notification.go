package model

// Notification event types. Each constant is the stable string key used in a
// NotificationSettings.Events map and on the wire to the notifier. They name an
// auditable SopsHQ action the operator can choose to be alerted about.
const (
	// Default-ON events (alerted unless the operator turns them off).
	EventApply       = "apply"        // an apply/reconcile finished (counts + outcome)
	EventDrift       = "drift"        // desired state and on-disk reality diverged
	EventBackup      = "backup"       // a self-backup run finished (per-destination outcome)
	EventFailedLogin = "failed_login" // a panel login attempt was rejected

	// Available-but-off events (defined and selectable; off by default).
	EventProjectWired     = "project_wired"     // a project's .sops.yaml was wired
	EventKeyGenerated     = "key_generated"     // a new keypair was generated
	EventRotation         = "rotation"          // a key rotation ran
	EventSecretReveal     = "secret_reveal"     // an operator decrypted/revealed a secret
	EventReplicationError = "replication_error" // a peer pull failed
	EventNewSession       = "new_session"       // a panel session was started
	EventLockout          = "lockout"           // an account was locked out
	EventPermDrift        = "perm_drift"        // the filesystem permission map changed vs its baseline
)

// DefaultNotificationEvents returns the per-event toggle map for a fresh
// NotificationSettings record: the curated default-ON set is true, every other
// known event is present but false. Every event key is listed so a settings UI
// can render a toggle for each without guessing the vocabulary.
func DefaultNotificationEvents() map[string]bool {
	return map[string]bool{
		EventApply:       true,
		EventDrift:       true,
		EventBackup:      true,
		EventFailedLogin: true,

		EventProjectWired:     false,
		EventKeyGenerated:     false,
		EventRotation:         false,
		EventSecretReveal:     false,
		EventReplicationError: false,
		EventNewSession:       false,
		EventLockout:          false,
		EventPermDrift:        false,
	}
}

// NotificationSettings is one machine's event-notification configuration. Like
// BackupSettings it is a normal replicated record (it embeds Meta and flows
// through the oplog) but is scoped to ONE machine via MachineID: each node reads
// and acts on only the record whose MachineID equals its own, because the chat
// destinations belong to that machine's operator.
//
// SECURITY: TelegramTokenSealed and SlackWebhookSealed hold VAULT-SEALED
// ciphertext, never a plaintext credential (the record replicates to the peer's
// store). The Slack incoming-webhook URL grants posting to the channel, so it is
// a secret and is sealed exactly like the Telegram bot token. Both are unsealed
// in-process only at send time and are never logged, echoed, or rendered.
type NotificationSettings struct {
	M Meta `json:"meta"`
	// MachineID is the Machine record this configuration belongs to. The owning
	// node is the only one that acts on it.
	MachineID string `json:"machine_id"`
	// Enabled is the master on/off switch. When false, no event notifies.
	Enabled bool `json:"enabled"`

	// TelegramEnabled turns the Telegram channel on or off.
	TelegramEnabled bool `json:"telegram_enabled"`
	// TelegramTokenSealed is the vault-sealed Telegram bot token (SECRET).
	TelegramTokenSealed string `json:"telegram_token_sealed"`
	// TelegramChatID is the Telegram chat/channel id to send to (not secret).
	TelegramChatID string `json:"telegram_chat_id"`

	// SlackEnabled turns the Slack channel on or off.
	SlackEnabled bool `json:"slack_enabled"`
	// SlackWebhookSealed is the vault-sealed Slack incoming-webhook URL (SECRET).
	SlackWebhookSealed string `json:"slack_webhook_sealed"`

	// Events maps an event-type constant to whether it notifies.
	Events map[string]bool `json:"events"`
}

func (n *NotificationSettings) Meta() *Meta { return &n.M }

// DefaultNotificationSettings builds a fresh, disabled NotificationSettings for
// machineID with the default per-event toggle set. The caller assigns the UUID
// (the store's get-or-make does this) before persisting.
func DefaultNotificationSettings(machineID string) *NotificationSettings {
	return &NotificationSettings{
		MachineID: machineID,
		Events:    DefaultNotificationEvents(),
	}
}
