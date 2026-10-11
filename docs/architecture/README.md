# SopsHQ Architecture

This is the architecture guide for SopsHQ. It explains how the system is built and
why. It is written so a non-technical reader can follow the shape of the system while
giving an engineer the detail needed to work on it. Every term is defined on first use.
To get started running SopsHQ, see the project [`README.md`](../../README.md).

These documents use the plain-language terms from
[`../terminology.md`](../terminology.md). In particular: where the sops tool's own
documentation says "recipient" for a public key listed in an encrypted file, these
documents say **public key**. That mapping is stated once here and not repeated.

The guide is split into the following parts. Start here, then follow whichever link
matches what you need.

## Contents

- [Decisions and dependencies](decisions.md) - the four foundational design decisions
  and the "standard library only" dependency policy.
- [System shape, packages, and data model](system-shape.md) - the cluster
  diagram, every Go package and what it does, and the records SopsHQ stores.
- [Security model](security.md) - encryption at rest, the transport posture, login and
  audit, and two-factor recovery (never a permanent sign-in block).
- [Key and secret scoping](scoping.md) - how to scope a secret from broadest (many
  readers) to tightest (one), framed as blast radius.
- [Keys: placement, rotation, everyday flow, usage](keys.md) - the key placement
  contract, safe wiring, the write-time change guard, rotation, the day-to-day flow,
  and best-effort usage tracking.
- [Drift, reconcile, and folder moves](reconcile-drift.md) - how SopsHQ spots when
  on-disk files drift from what it intends, the one-click resolve actions on the Drift
  page, and how changing a project's folder MOVES its managed files instead of
  stranding them.
- [Replication](replication.md) - how the peer machines converge (operation log +
  last-writer-wins).
- [Cluster peer identity](peer-identity.md) - the canonical machine id, Add peer, the
  new-vs-reinstall confirmation, and convergent cluster-wide de-duplication.
- [Conflict resolution](conflict-resolution.md) - when two records disagree on a value,
  why SopsHQ keeps both instead of merging, and the double-confirmed resolve flow.
- [Storage, backup, and recovery](storage-backup-recovery.md) - every file on disk,
  what is secret, what to back up, encryption at rest, recovery paths, and the
  scheduled self-backup.
- [Notifications](notifications.md) - short Telegram and Slack messages on chosen
  events.
- [Build, versioning, releases and updating](build-versioning.md) - how the version is injected at build
  time, how a release is signed, and how `sopshq update` installs one.
- [Deployment guide](../deployment.md) - the Linux install: the dedicated `sopshq`
  service account, the three-path encrypted layout, the systemd unit, and the
  everyday start/stop flow.

---

## 1. Purpose and boundaries

**SopsHQ** manages [SOPS](https://github.com/getsops/sops) +
[age](https://github.com/FiloSottile/age) encryption keys across a peer-to-peer
cluster of machines that share nearly the same set of projects. Any number of
peers is supported; the common deployment is two machines (a Windows dev box and a
Linux server).

It is a **control plane**: it decides *which key goes where* and makes it so. It is
deliberately **not** part of decryption. After SopsHQ places a key, `sops -d` works
locally with no help from SopsHQ. If SopsHQ is offline, decryption is unaffected.

**In scope:** generating age keypairs, storing private keys (encrypted),
distributing them to the right OS users, maintaining the public keys in each project's
`.sops.yaml`, rotating keys, keeping the cluster's machines in sync, and **editing a project's
secret values** from the panel under an *encrypt-and-forget* custody model (see below).

**Secret values - encrypt and forget:** the panel can add, edit, and
delete the name/value pairs in a project's `secrets.yaml`. The crucial property is
that SopsHQ keeps **no copy** of any value: each save runs `sops` to encrypt the
value straight into the project's `secrets.yaml` on the local machine, and nothing
of the value is retained. The encrypted file in the project is the only copy. To
read or write, SopsHQ unseals the project key's PRIVATE material from its own vault
(never requiring the key to be placed on disk first) and passes it to `sops` only
through the `SOPS_AGE_KEY` child-process environment variable. That child
environment is **scrubbed** of every ambient age-identity-discovery variable
(`SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE`, `SOPS_AGE_KEY_CMD`,
`SOPS_AGE_SSH_PRIVATE_KEY_FILE`, `SOPS_AGE_SSH_PRIVATE_KEY_CMD`) before the vault
key is added, so `sops` decrypts with ONLY the key SopsHQ supplies and can never
pick up an unintended identity from the operator's shell. The value itself is
passed to `sops set` on **stdin** (so it never appears in the process list). The
panel and the audit log show secret **NAMES only** - a value is never stored,
logged, audited, or written to any document. This preserves the original promise
below: SopsHQ still never *holds* a secret value, it only passes one through.

**Cross-project secrets catalog:** an admin-only **Secrets** page lists every
secret SopsHQ can read on this machine, across all projects, **grouped by identical
value** (so the operator can see where a value is reused and spot duplicates). Building
it is a deliberate, audited **bulk decrypt**: for each project with a local path and a
wired key, SopsHQ decrypts its `secrets.yaml` in memory (vault-unsealed key, exactly as
the editor does), groups the usages by plaintext value, then **discards the plaintext**.
The custody promise is unchanged - no value is stored, cached to disk, logged, or sent
to the browser until the operator clicks **Show** on a row, which calls the same audited
per-project reveal endpoint (audited by NAME only). The grouped table sent to the browser
carries no values, only masked counts and the names/locations. Projects this machine
cannot decrypt are not listed. The whole sweep is recorded as one `secrets_catalog`
audit entry (counts only).

**Secret reuse picker:** the project page's Secrets section has an admin-only,
collapsible **"Reuse an existing secret"** panel that loads that same catalog (lazily,
the first time it is opened) and shows each value with a checkbox and an editable target
name. The operator ticks values and clicks **Add selected**; for each pick, SopsHQ
decrypts the value from its source on demand and writes it into this project under the
chosen name (`POST /projects/{id}/secrets/bulk-add`). Names that already exist here are **skipped, never
overwritten**, and the result is reported by name. The picked value is never shown in the
picker or sent to the browser - it is read from the source and written to the target
entirely server-side (Path 1), audited by name like any other secret write.

**Global (shared) secrets:** a value can also be
defined in a **named set** that does **not** belong to any project folder - the classic
case is a shared `OPENROUTER_API_KEY`. A set names one **or more** OS accounts as its
readers; it is encrypted to **each** chosen account's existing key (the same key SopsHQ
already places for their projects), so every chosen account decrypts it with its **own**
key - no shared private key. Each set is written to `<key base>/global/<set>/secrets.yaml`
(with its own `.sops.yaml`) in **every** chosen account's keystore; the copies are
byte-identical (same public-key list), so there are no cross-account file permissions to
manage. The `GlobalSet` store record holds only the set name + the reader OS-account IDs
(it replicates like any record); the **values** live only in the encrypted files
(encrypt-and-forget - nothing stored/logged, reveal audited by set+NAME only). SopsHQ
manages a set by unsealing any one chosen account's key, re-encrypting in the "primary"
copy, then syncing the identical ciphertext to the other accounts' dirs. An app reads a
set the standard sops way, no SopsHQ in the loop: `sops exec-env <path> '<command>'` (the
panel shows each account's exact path). A chosen account's private key must be placed (any
`Apply` for one of their projects does this) before their apps can decrypt. Scope is the
local machine's OS accounts; the encrypted values are never replicated (only the small set
record is). A one-account set is just the "your own global secrets" case.

**Mass-update a secret:** a secret can be renamed or re-valued once and
propagated to **every place that holds the exact same `(name, value)`** - across project
`secrets.yaml` files **and** global sets on this machine. Identity is name+value, so a
same-named secret with a *different* value (a deliberately different key) and a same-valued
secret under a *different* name are both left alone. From the **Secrets catalog**, a row's
**Edit** opens a page that lists the affected places and updates them all on save. On a
**project page**, editing a secret shows (to admins) "this is also used in N other places -
update them too?"; ticking it propagates, otherwise only that project changes. The engine
(`keysvc.FindSecretOccurrences` + `MassUpdateSecret`) decrypts on demand only to match and
to write the new value, re-encrypts each place independently (one failure does not roll back
the rest), and audits by name only - values are never logged. It is a mass-decrypt+write
surface, so it is admin-only.

**Quick add - guided one-shot:** a **Quick add** page wraps the whole flow in
one guided form so a person does not have to understand the model first. You pick the
secret, choose **where it should live** - **Project** (one project; granted OS accounts all
get the project key) or **Global** (a shared set; chosen accounts each read with their own
key) - and pick the target(s). Before acting it runs **pre-flight checks** and shows
non-secret alerts: filesystem access (via `internal/access` - rigorous uid/gid/mode +
parent traversal on Unix, best-effort `icacls` on Windows), whether an account has a real
home directory, secret-name collisions, and a re-encryption notice. On **Set it up** it
runs the full automation: create the missing project + folder path, wire (generate/assign/
place the key), Apply, and encrypt the secret - reusing the existing audited operations
(`RunQuickAdd`), with a step-by-step result. (Creating new OS accounts inline is the one
piece left to the dedicated OS users page for now; the wizard works with the machine's
existing OS accounts.)

**Still out of scope:** storing or replicating secret *values* between machines
(only the local machine's `secrets.yaml` is edited; the value lives solely in that
encrypted file), and editing a remote machine's secrets from this panel.
