# Signed releases for a fork

This repository publishes no releases, and `sopshq update` is switched off in it: no
release signing key is embedded, so every update is refused. This page is for a fork
that wants to publish its own signed releases and let its installs update themselves.

If you only build from source, you do not need any of this: rebuild and run
`sudo ./dist/sopshq install` again (see the [deployment guide](deployment.md#updating-linux)).

## Contents

- [How it fits together](#how-it-fits-together)
- [1. Make your signing key](#1-make-your-signing-key)
- [2. Turn on the release workflow](#2-turn-on-the-release-workflow)
- [3. Cut a release](#3-cut-a-release)
- [4. Point installs at your repository](#4-point-installs-at-your-repository)
- [How sopshq update checks a release](#how-sopshq-update-checks-a-release)
- [Rotating the key](#rotating-the-key)
- [What to change in the code](#what-to-change-in-the-code)

## How it fits together

- A release holds the Linux and Windows binaries, `SHA256SUMS` and `SHA256SUMS.sig`.
- `SHA256SUMS` names the release version inside the signed bytes, so an old release
  cannot be passed off as a new one.
- The signature is ML-DSA-65 (Go's `crypto/mldsa`). The public key is compiled into the
  binary from `internal/update/release_pubkey.hex`; the private key (a seed file) stays
  on your own machine and never reaches GitHub.
- GitHub Actions builds a **draft** release. You sign it on your machine with
  `cmd/releasesign`, which uploads the signature and publishes the draft.
  `sopshq update` ignores drafts and refuses a release with no signature.

## 1. Make your signing key

From the repository root, naming a seed file **outside** the repository:

```sh
go run ./cmd/releasesign keygen -seed-out ~/sopshq-release-seed.hex
git add internal/update/release_pubkey.hex
git commit -m "release: embed the signing public key"
```

`keygen` writes the private seed to that file (mode 0600, never printed, refused inside
a git work tree, never overwritten) and the public key into
`internal/update/release_pubkey.hex`. Back the seed file up somewhere safe and offline:
losing it means no install can be updated again without a hand reinstall. Never commit
it; `.gitignore` already ignores `*seed*.hex`.

`keygen` refuses to replace a key that is already embedded, because a new key
invalidates every release signed with the old one.

## 2. Turn on the release workflow

Copy [examples/release.yml](examples/release.yml) to `.github/workflows/release.yml` in
your fork. On every pushed tag `vX.Y.Z` it:

- refuses unless the tag matches the `VERSION` file;
- runs `go vet` and the tests, then builds both binaries with `build.sh`;
- writes `SHA256SUMS` with the version inside, builds release notes from the commit
  subjects since the previous tag, and creates the draft release.

It holds no signing key and reads no secret. Its third-party actions are pinned by commit
hash; keep them current yourself (for example with Dependabot).

## 3. Cut a release

```sh
# 1. bump VERSION, commit, push
git tag vX.Y.Z && git push origin vX.Y.Z      # 2. the workflow builds the draft
# 3. wait for the workflow, look at the draft, then sign and publish it:
SOPSHQ_RELEASE_REPO=OWNER/REPO go run ./cmd/releasesign publish -tag vX.Y.Z -seed ~/sopshq-release-seed.hex
```

`publish` uses your own `gh` login. It downloads the draft's `SHA256SUMS` and refuses
unless the version inside matches the tag, the seed matches an embedded public key, and
the release is still an unsigned draft. Then it signs, checks its own signature, uploads
`SHA256SUMS.sig` and publishes the draft. `-repo OWNER/REPO` works instead of the
environment variable.

`releasesign sums` and `releasesign sign` do the checksum and signing steps on their own,
for a pipeline of your own; `sign` reads the hex seed from `SOPSHQ_RELEASE_SIGNING_SEED`.

The first binary that carries your key has to be installed by hand
(`sudo ./dist/sopshq install`). From then on, `sopshq update` works.

## 4. Point installs at your repository

`sopshq update` downloads from the repository named by the first of these that is set:

1. the `SOPSHQ_RELEASE_REPO` environment variable (`OWNER/REPO`);
2. `release_repo` in the install's `config.jsonc`;
3. on a terminal, a prompt; the answer is saved to `config.jsonc`.

The download uses the GitHub CLI (`gh`) logged in as your own user. Under `sudo` it runs
as the user who ran `sudo`, with root's privileges dropped; no token is typed or stored.

```sh
sopshq update --check            # the running version and the newest published one
sudo sopshq update               # install the newest release
sudo sopshq update --rollback    # go back to the newest older backup
sudo sopshq update --from DIR    # the same checks, from a folder holding the release files
```

The vault is locked after every update, because the service restarts. Run
`sudo sopshq unlock`. Windows has no `sopshq update`; it prints the manual steps.

## How sopshq update checks a release

It copies the release files into a root-owned staging folder, verifies the signature,
then the binary's SHA-256, then requires the signed version to be newer than the
installed one and the staged binary's own `version` to match it. A `dev` build refuses
every update.

It then checks the install is root-owned, stops the service and any stray `serve`, backs
the old binary up to `/opt/sopshq/backups/sopshq-<version>` (root, 0700), swaps the new
one in, starts the service if it was running, and waits for it to report the new version.
If that fails it restores the backup and starts it. After a good update it keeps the
three newest backups. It never touches the config (apart from saving the release
repository once), the data, the vault, the keys or the systemd unit.

## Rotating the key

To move to a new key without stranding installed binaries:

1. `go run ./cmd/releasesign keygen -slot next -seed-out <a path outside the repository>`
   fills `internal/update/release_pubkey_next.hex`.
2. Release as usual, signed with either seed. Binaries built from that release accept
   either key.
3. Once every install runs such a build, move the next key into `release_pubkey.hex`,
   empty the next file, and release again.

An empty primary slot always refuses every update, whatever the next slot holds.

## What to change in the code

Nothing beyond the key file is required. These are the places a fork usually touches:

- `internal/update/release_pubkey.hex`: your public key (written by `keygen`).
- `.github/workflows/release.yml`: copied from `docs/examples/`.
- `VERSION`: bumped for every release; the workflow refuses a tag that does not match.
- `ghFetcher` in `cmd/sopshq/update_system_linux.go`: how releases are listed and
  downloaded through `gh`, if you host releases somewhere other than GitHub.
