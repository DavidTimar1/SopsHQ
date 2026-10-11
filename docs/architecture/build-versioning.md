# Build and versioning

This part explains how SopsHQ stamps its version into the binary at build time. For
the overview, start at the [architecture index](README.md).

## 11. Build and versioning

- Version lives in the root `VERSION` file (semver) and is injected into the binary
  at build time: `-ldflags "-X main.version=$(cat VERSION)"`. Plain `go run`/`go test`
  report `dev`.
- Every behavior change bumps `VERSION` in the same change, and its commit message
  carries the reason: git is the changelog. Structural changes update these
  architecture documents.

## 12. Releases and updating

- A release is four files: the Linux and Windows binaries, `SHA256SUMS` and
  `SHA256SUMS.sig`. CI builds a draft with the first three; the operator signs on their
  own machine with `releasesign publish`, which uploads the signature and publishes the
  draft, so the signing seed never reaches GitHub. `SHA256SUMS` names the release version inside the signed bytes, so
  an old signed release cannot be replayed as a new one.
- The signature is ML-DSA-65 (`crypto/mldsa`, Go 1.27). The private seed lives only on
  the operator's machine (a 0600 file outside the repository); the public key is embedded in the binary from
  `internal/update/release_pubkey.hex`. A build with no key embedded refuses every
  update. `cmd/releasesign` creates the key and writes and signs `SHA256SUMS`.
- `sopshq update` (Linux, root) is a management-plane command like `setup`: it replaces
  the binary only and never touches the vault, data or config. Its logic is in
  `internal/update` (verification, versions, backups, release source) and
  `cmd/sopshq/update_*_linux.go` (the swap sequence and the systemd and `gh` adapters).
  The operator-facing description is in [Updating](../deployment.md#updating-linux).
- The unlock status reply carries the running version so an update can prove the new
  build is the one that came up.
