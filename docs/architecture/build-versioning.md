# Build and versioning

This part explains how SopsHQ stamps its version into the binary and how releases are
built. For the overview, start at the [architecture index](README.md).

## Contents

- [Version and build](#version-and-build)
- [Releases and updating](#releases-and-updating)

## Version and build

- The version lives in the root `VERSION` file (semver).
- It is injected at build time: `-ldflags "-X main.version=$(cat VERSION)"`. A plain
  `go run` or `go test` reports `dev`.
- `./build.sh` builds the Linux and Windows (amd64) binaries into `dist/` with the
  version injected. `./build.sh --check` runs `go vet` and `go test` first.
- When to bump the version is in [contributing](../../CONTRIBUTING.md).

## Releases and updating

**This snapshot embeds no release signing key, so `sopshq update` refuses every update
until a fork embeds its own key.** The release process for a fork is in
[releasing](../releasing.md), and the trust model is in
[security](security.md#updates-and-release-signing).

- **A release** is four files: the Linux and Windows binaries, `SHA256SUMS` and
  `SHA256SUMS.sig`. The example workflow `docs/examples/release.yml` builds a draft with
  the first three; the fork maintainer signs and publishes it with `releasesign
  publish`, so the signing seed never reaches GitHub.
- **The signature** is ML-DSA-65 (`crypto/mldsa`, Go 1.27).
  - The public key is embedded from `internal/update/release_pubkey.hex`. In this
    snapshot that file holds no key.
  - The private seed is a 0600 file kept outside the repository.
  - `cmd/releasesign` creates the key and writes and signs `SHA256SUMS`.
- **`sopshq update`** (Linux, root) replaces the binary only and never touches the vault,
  data or config.
  - Its logic is in `internal/update` and `cmd/sopshq/update_*_linux.go`.
  - The operator's view is in [updating](../deployment.md#updating-linux).
- **Proof the new build came up:** the unlock status reply carries the running version.
