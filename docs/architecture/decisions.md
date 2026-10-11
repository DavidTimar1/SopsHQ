# Decisions and dependencies

This part covers the four foundational design decisions behind SopsHQ and the
"standard library only" dependency policy. For the overview and scope, start at the
[architecture index](README.md).

## 2. The four foundational decisions

1. **Multi-master topology.** The full panel + a local database run on **every**
   machine in the cluster (a peer-to-peer set of any number of machines). They
   converge by exchanging *logical records* (an operation log with last-writer-wins),
   never by copying the database file.
2. **Central custody.** SopsHQ generates keypairs and stores the **private** keys
   encrypted, then pushes them out.
3. **Both key models.** "One shared keypair per project" and "one keypair per user"
   are both supported; each key is tagged with its type.
4. **Strong auth.** Login = PBKDF2-hashed password **plus** a TOTP code (or a
   one-time **recovery code** if the authenticator is lost). Roles: `admin` and
   `developer`. Every action is audited. A lost authenticator never permanently shuts
   the operator out: recovery codes, self re-enrollment, an admin reset, and a CLI
   escape hatch each provide a way back in (see the
   [two-factor recovery section](security.md#71-2fa-recovery-no-permanent-sign-in-block)).

---

## 3. Dependency policy

SopsHQ builds from the **Go standard library** by default, with a **single, vetted
third-party dependency** today: `rsc.io/qr` (a small, pure-Go QR encoder with **zero
transitive dependencies**), used only to render the TOTP enrollment QR image.
Everything else is stdlib, so the supply chain stays trivial to audit and the
cross-platform build is free of CGO. The only external programs invoked are the
installed `age-keygen` and `sops` binaries.

The policy is **prefer stdlib, add a dependency when it is clearly better.** Reach for
the standard library first; but a third-party module is allowed when it is clearly more
correct, professional, or future-proof than hand-rolling (for example post-quantum
signatures or ACL syscalls). When one is added, it should be a small, audited, pure-Go
module with minimal transitive dependencies, justified in the commit message; heavy or supply-chain-risky dependencies are still avoided.

QR is the current example of a dependency adopted rather than hand-rolled: QR encoding
is spec-heavy and a from-scratch encoder proved error-prone, so a tiny audited library
was the better engineering trade-off. Where other common third-party choices were
avoided and why:

| Need | Common dep | SopsHQ choice (stdlib) |
|---|---|---|
| age key generation | `filippo.io/age` | exec the installed `age-keygen` |
| database | `modernc.org/sqlite` | JSON document store (`encoding/json`) |
| key derivation | `golang.org/x/crypto/argon2` | `crypto/pbkdf2` (PBKDF2-HMAC-SHA384) |
| `.sops.yaml` | `gopkg.in/yaml.v3` | a small internal writer (we own the file) |
| TOTP | `github.com/pquerna/otp` | a ~50-line RFC 6238 helper |
