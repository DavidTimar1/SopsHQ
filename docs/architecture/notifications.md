# Notifications

This part covers the short Telegram and Slack messages SopsHQ can push when chosen
events happen. For the overview, start at the [architecture index](README.md).

## 16. Notifications

SopsHQ can push a **short message** to a **Telegram** channel and/or a **Slack** channel
when chosen events happen, so the operator learns about important activity without watching
the panel. This is distinct from the backup feature's Telegram **file** upload - here it is
a one-line `sendMessage` / Slack webhook `POST`.

- **Config: a per-machine `NotificationSettings` database record** (managed in
  **Settings -> Notifications**, admin only - not in `config.jsonc`): a master enable, a
  per-channel enable, the Telegram **chat id**, the **vault-sealed** Telegram bot token and
  the **vault-sealed** Slack incoming-webhook URL (the webhook grants posting, so it is a
  secret), and a per-event-type on/off map. Default-ON events: apply result, drift detected,
  backup result, failed login; the rest (project wired, key generated, rotation, secret
  reveal, replication error, new session, lockout) are available but off.
- **Channels (stdlib, HTTPS):** `internal/telegram` `SendMessage` and `internal/slack`
  `SendWebhook`. As with backup, **no owner/app-identifying metadata** is sent - only the
  credential and the message.
- **The notifier seam** (`internal/notify`): the event sites call `Notify(eventType,
  summary)`. If the record is missing/disabled or the event toggle is off it is a no-op;
  otherwise it formats a **one-line ASCII** message (names / UUIDs / outcome only, **never a
  secret value, key, passphrase, TOTP secret, token, or webhook**), then fans out to every
  enabled channel on a goroutine so a send **never blocks or fails** the action that
  triggered it. A per-channel failure is logged by event + channel **name** only. Wired
  events: apply (`applyLocal`/`applyAll`), drift (on the no-drift -> drift transition in the
  pending refresh), backup result, and failed login. A **Send test** button drives a
  synchronous single-channel test send.
