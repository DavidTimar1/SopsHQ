# Security Policy

**SopsHQ is not maintained.** Nobody reads security reports, issues or pull requests
for this repository, and no fixes will be released. If you find a problem, fix it in
your own fork. Read the code before you trust it with real keys.

## Contents

- [What SopsHQ is, for the threat model](#what-sopshq-is-for-the-threat-model)
- [Updates](#updates)

## What SopsHQ is, for the threat model

SopsHQ is a **management plane** for SOPS/age keys. It generates, places and rotates
keys, but it is **never in the decrypt path**: once a key is placed on a machine,
`sops -d` keeps working locally with SopsHQ turned off.

- It serves a plain-HTTP admin panel and a machine-to-machine agent. Both must be
  reached only over loopback (for example an SSH tunnel) or a Tailscale bind. Never put
  either on a public interface.
- The agent requires a shared transfer key on every request.
- Data is encrypted at rest with AES-256-GCM under a key derived from the vault key, and
  the vault never unlocks by itself at boot.

The design, its trust boundaries and its known limits are in
[architecture/security.md](architecture/security.md).

## Updates

`sopshq update` is switched off in this repository: no release signing key is embedded
and no releases are published. A fork that turns it on should read
[releasing.md](releasing.md) and the update section of
[architecture/security.md](architecture/security.md#updates-and-release-signing).
