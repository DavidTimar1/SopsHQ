# Contributing

SopsHQ is not maintained, so pull requests and issues are not reviewed. Fork it freely
and change it however you like under the licence.

If you work on a fork, these are the rules the code was written to:

- **Check every change:** `go build ./...`, `go vet ./...`, `go test ./...`, and
  `GOOS=windows go vet ./...` for the Windows build. `scripts/test_uninstall.sh` tests
  `uninstall.sh`.
- **Prefer the standard library.** A third-party module is added only when it is clearly
  better than writing it by hand: small, audited, pure Go, few dependencies of its own.
  Today the only one is `rsc.io/qr`, for the TOTP enrollment QR code.
- **Secrets never leak.** age private keys, the vault key and TOTP secrets are never
  logged, printed, rendered into a template, written to an audit row or put in a
  document. Audit and log by name or UUID only.
- **ASCII only in source.** Code, comments and any string that may be printed are ASCII
  (`->`, `[ok]`, `...`). Data the program reads may be UTF-8; decode it explicitly.
- **The crypto posture is fixed:** AES-256-GCM at rest and PBKDF2-HMAC-SHA384 (600,000
  iterations) for key derivation. Never downgrade it or hand-roll crypto.
- **No app-layer TLS.** The panel and the agent are plain HTTP on loopback or Tailscale,
  and the agent is gated by the transfer key.
- **The vault never auto-unlocks.** The vault key comes from the operator or
  `SOPSHQ_VAULT_KEY`, and stays in memory only.
- **Version every behaviour change.** Bump the root `VERSION` (semver) in the same
  commit, and put the reason in the commit message: git history is the changelog.
- **Build into `dist/`** with `./build.sh` or
  `go build -ldflags "-X main.version=$(cat VERSION)" -o dist/ ./cmd/sopshq`.

## License

GNU AGPL-3.0-or-later; see [LICENSE](LICENSE).
