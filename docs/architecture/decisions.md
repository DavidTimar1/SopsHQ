# Decisions and dependencies

This part covers the foundational design decisions behind SopsHQ and its dependency
policy: standard library first, with one small third-party module today. For the
overview and scope, start at the [architecture index](README.md).

## Contents

- [Foundational decisions](#foundational-decisions)
- [Dependency policy](#dependency-policy)
- [Common dependencies SopsHQ avoids](#common-dependencies-sopshq-avoids)

## Foundational decisions

1. **Multi-master topology.** The full panel and a local database run on **every**
   machine in the cluster, a peer-to-peer set of any number of machines. They converge
   by exchanging logical records (an operation log with last-writer-wins), never by
   copying the database file.
2. **Central custody.** SopsHQ generates keypairs, stores the **private** keys
   encrypted, and pushes them out.
3. **Both key models.** "One shared keypair per project" and "one keypair per user" are
   both supported; each key is tagged with its type.
4. **Strong auth.**
   - Login is a PBKDF2-hashed password **plus** a TOTP code, or a one-time recovery code
     if the authenticator is lost.
   - Roles are `admin` and `developer`, and every action is audited.
   - A lost authenticator never shuts the operator out for good; see
     [two-factor recovery](security.md#two-factor-recovery).

## Dependency policy

- **Standard library first.** SopsHQ builds from the Go standard library by default.
- **One third-party module today:** `rsc.io/qr`, a small pure-Go QR encoder with no
  dependencies of its own, used only to draw the TOTP enrollment QR code. QR encoding is
  spec-heavy and a hand-written encoder proved error-prone, so a small audited library
  was the better trade.
- **External programs:** only the installed `age-keygen` and `sops` binaries.
- **Why:** the supply chain stays easy to audit, and the cross-platform build needs no
  CGO.
- **When a module is allowed:** when it is clearly more correct, professional or
  future-proof than writing it by hand, for example post-quantum signatures or ACL
  system calls.
  - Prefer a small, audited, pure-Go module with few dependencies of its own.
  - Justify it in the commit message.
  - Heavy or supply-chain-risky dependencies are still avoided.

## Common dependencies SopsHQ avoids

| Need | Common dependency | SopsHQ choice (standard library) |
|---|---|---|
| age key generation | `filippo.io/age` | run the installed `age-keygen` |
| database | `modernc.org/sqlite` | JSON document store (`encoding/json`) |
| key derivation | `golang.org/x/crypto/argon2` | `crypto/pbkdf2` (PBKDF2-HMAC-SHA384) |
| `.sops.yaml` | `gopkg.in/yaml.v3` | a small internal writer (SopsHQ owns the file) |
| TOTP | `github.com/pquerna/otp` | a small RFC 6238 helper (`internal/totp`) |
