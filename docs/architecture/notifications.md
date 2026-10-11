# Notifications

SopsHQ can push a **short message** to a Telegram channel, a Slack channel, or both when
chosen events happen, so the operator learns about important activity without watching
the panel. This is separate from the backup feature's Telegram **file** upload: here it
is a one-line Telegram `sendMessage` or a Slack webhook `POST`. For the overview, start
at the [architecture index](README.md).

## Contents

- [Settings](#settings)
- [Events](#events)
- [Channels](#channels)
- [How a message is sent](#how-a-message-is-sent)

## Settings

- Notifications are set in **Settings, then Notifications** (admin only), not in
  `config.jsonc`.
- They are stored as one `NotificationSettings` record per machine:
  - a master switch and a switch per channel;
  - the Telegram chat id;
  - the Telegram bot token and the Slack incoming-webhook URL, both **sealed with the
    vault** (the webhook URL grants posting, so it is a secret);
  - an on or off switch per event type.

## Events

- **On by default:** apply result, drift detected, backup result, failed login.
- **Available, off by default:** project wired, key generated, rotation, secret reveal,
  replication error, new session, lockout, permission drift.
- Every event in both lists is sent from the action it names.

## Channels

- Telegram and Slack are both sent with the standard library's `net/http`.
- As with backups, no owner- or app-identifying metadata is sent: only the credential
  and the message.

## How a message is sent

- If the settings record is missing or switched off, or the event's switch is off,
  nothing is sent.
- Otherwise SopsHQ builds a **one-line ASCII** message with names, UUIDs and the outcome
  only. It **never** carries a secret value, key, vault key, TOTP secret, token or
  webhook.
- The message goes to every enabled channel in the background, so sending never blocks
  or fails the action that caused it.
- A channel that fails is logged by event and channel **name** only.
- The **Send test** button sends a test message to one channel and waits for the result.
