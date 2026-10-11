# SopsHQ Architecture

This is the architecture guide for SopsHQ: how the system is built, and why.

- It is written so a non-technical reader can follow the shape of the system, while an
  engineer gets the detail needed to work on it.
- Every term is defined on first use.
- To install and run SopsHQ, start at the project [`README.md`](../../README.md).

These documents use the plain-language terms from [`../terminology.md`](../terminology.md).
Where the sops tool's own documentation says "recipient" for a public key listed in an
encrypted file, these documents say **public key**. That mapping is stated here once.

## Contents

- [Purpose and boundaries](#purpose-and-boundaries)
- [The guide, part by part](#the-guide-part-by-part)

## Purpose and boundaries

**SopsHQ** manages [SOPS](https://github.com/getsops/sops) and
[age](https://github.com/FiloSottile/age) encryption keys across a peer-to-peer cluster
of machines that share nearly the same set of projects. Any number of peers is
supported; the common deployment is two machines, a Windows dev box and a Linux server.

It is a **control plane**: it decides *which key goes where* and makes it so. It is
deliberately **not** part of decryption.

- After SopsHQ places a key, `sops -d` works locally with no help from SopsHQ.
- If SopsHQ is offline, decryption is unaffected.

**In scope:**

- generating age key pairs;
- storing private keys, encrypted;
- placing them for the right OS accounts;
- maintaining the public keys in each project's `.sops.yaml`;
- rotating keys;
- keeping the cluster's machines in sync;
- editing a project's secret values from the panel, under an *encrypt and forget*
  custody model: SopsHQ keeps no copy of any value (see [secret values](secrets.md)).

**Out of scope:**

- storing or replicating secret *values* between machines (only the local machine's
  encrypted files are edited);
- editing a remote machine's secrets from this panel.

## The guide, part by part

Start here, then follow whichever link matches what you need.

**Design**

- [Decisions and dependencies](decisions.md): the foundational design decisions and the
  dependency policy (standard library first).
- [System shape, packages, and data model](system-shape.md): the cluster diagram, the
  setup and serve lifecycle, every Go package, and the records SopsHQ stores.
- [The admin panel](panel.md): the web interface, the DB and Map views, the permission
  auditor, Settings, and audit-log retention.
- [Security model](security.md): encryption at rest, the transport posture, login and
  audit, and two-factor recovery.

**Keys and secrets**

- [Key and secret scoping](scoping.md): how to scope a secret from broadest (many
  readers) to tightest (one), framed as blast radius.
- [Keys: the placement contract](keys.md): where a key goes, the shared keys root, ACLs,
  and discovery.
- [Keys: setting up an account's key store](keys-account-setup.md): the print-commands
  model for anything that needs root.
- [Keys: safe wiring](keys-safe-wiring.md): never clobber existing state, reuse versus
  re-create, and the key lifecycle.
- [Keys: continuous local reconcile](keys-reconcile.md): drift computed fresh, importing
  keys found on disk, and discovery repair.
- [Keys: the write-time change guard](keys-write-guard.md): how a file changed outside
  SopsHQ is caught before it is overwritten.
- [Keys: rotation and the everyday flow](keys-rotation-and-flow.md).
- [Keys: usage tracking](keys-usage-tracking.md): the optional, best-effort `sops` usage
  log.
- [Secret values](secrets.md): encrypt and forget, the cross-project catalog, the reuse
  picker, global sets, mass update, and Quick add.
- [Drift, reconcile, and folder moves](reconcile-drift.md): how SopsHQ spots on-disk
  drift, the one-click resolve actions, and how a project's folder change moves its
  managed files.

**The cluster**

- [Replication](replication.md): how the peer machines converge (operation log,
  last-writer-wins, per-field merge).
- [Cluster peer identity](peer-identity.md): the canonical machine id, Add peer, the
  new-versus-reinstall confirmation, and convergent de-duplication.
- [Conflict resolution](conflict-resolution.md): when two records disagree on a value,
  why SopsHQ keeps both, and the double-confirmed resolve flow.

**Operating it**

- [Storage, backup, and recovery](storage-backup-recovery.md): every file on disk, what
  is secret, what to back up, encryption at rest, recovery paths, and the scheduled
  self-backup.
- [Notifications](notifications.md): short Telegram and Slack messages on chosen events.
- [Build, versioning, releases and updating](build-versioning.md): how the version is
  injected, and how `sopshq update` verifies a signed release.
- [Deployment guide (Linux)](../deployment.md) and
  [deployment guide (Windows)](../deployment-windows.md): install, service account,
  start and stop.
