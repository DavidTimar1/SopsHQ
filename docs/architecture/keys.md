# Keys: placement contract

This part says where SopsHQ writes keys on disk and how other accounts reach them. The
other key documents, listed below, cover setup, safe wiring, reconcile, the write
guard, rotation and usage tracking. For the overview, start at the
[architecture index](README.md). Plain-language definitions are in
[terminology](../terminology.md).

## Contents

- [The key documents](#the-key-documents)
- [Placement contract](#placement-contract)
- [Several keys for one account](#several-keys-for-one-account)
- [The keystore folder](#the-keystore-folder)
- [Shared keybase root](#shared-keybase-root)
  - [Turning it on](#turning-it-on)
  - [Running as a dedicated account](#running-as-a-dedicated-account)
  - [Per-user access with POSIX ACLs](#per-user-access-with-posix-acls)
  - [Global sets under the root](#global-sets-under-the-root)
  - [Verification and failure](#verification-and-failure)
  - [How other accounts find their key](#how-other-accounts-find-their-key)
  - [Windows](#windows)
  - [Changing the root later](#changing-the-root-later)
- [The .sops.yaml file](#the-sopsyaml-file)

## The key documents

- [Account setup](keys-account-setup.md): preparing an OS account's keystore without
  root.
- [Safe wiring](keys-safe-wiring.md): never clobbering a key or config already on
  disk, adopting existing state, and the key lifecycle.
- [Reconcile and discovery](keys-reconcile.md): keeping the panel honest about disk,
  importing keys found on disk, and repairing discovery.
- [Write guard](keys-write-guard.md): refusing to overwrite a file somebody edited
  outside SopsHQ.
- [Rotation and everyday flow](keys-rotation-and-flow.md): rotating a key, and the
  day-to-day steps to define, place and use one.
- [Usage tracking](keys-usage-tracking.md): the optional, best-effort count of key use.

## Placement contract

SopsHQ places keys where `sops` and `age` already look for them, so a key placed by
SopsHQ and one placed by hand can coexist.

**Linux** (no root or sudo needed):

- SopsHQ writes `<base>/keys.txt` (0600) and `<base>/keys.pub` (0644).
- For a **self** placement (the account SopsHQ itself runs as) it also wires sops
  discovery in that account's own home:
  - `SOPS_AGE_KEY_FILE` under the `# sopshq:sops-age` marker in `~/.bashrc`;
  - a symlink `~/.config/sops/age/keys.txt` to the key.
- A placement for **another** account (into the [shared keybase root](#shared-keybase-root))
  writes the key store and the POSIX ACL grant, then stops. It never reads or writes
  that account's home.

**Windows:**

- SopsHQ writes `keys.txt` and `keys.pub` on the chosen volume.
- `icacls` restricts `keys.txt` to the owning account.
- A junction `%USERPROFILE%\.sops` points to the store.
- `SOPS_AGE_KEY_FILE` is persisted at User scope.

## Several keys for one account

- One OS account may be assigned several project keys, for example when it is in
  several projects that each use one shared keypair.
- age and sops accept several identities in one key file, so SopsHQ writes **all** of
  an account's assigned private keys into its `keys.txt`, one per line, and `sops -d`
  tries each.
- Placement is therefore grouped per account: it writes the account's full set at once.
  Drift is satisfied when a key is **among** those in the store.

## The keystore folder

- The default is sops's standard location: `~/.config/sops/age`, or
  `%AppData%\sops\age` on Windows. An account **with a home** then needs no explicit
  `SOPS_AGE_KEY_FILE`, because `sops` finds `keys.txt` there on its own.
- The operator can point the keystore at any other folder, in particular one on an
  **encrypted drive** (tick "store the private key on a secure drive"). The key is then
  unreadable until the volume is unlocked, and sops fails closed.
- In the secure-drive case the real `keys.txt` lives on the encrypted folder, and
  `~/.config/sops/age/keys.txt` becomes a symlink to it. Both the default location and
  an explicit `SOPS_AGE_KEY_FILE` then resolve to the same file.
- An account with no home needs an explicit folder; see
  [account setup](keys-account-setup.md).

## Shared keybase root

By default each account's key store lives under that account's home. Instead, the
operator can put **every** account's key store under one shared folder, for example
`/srv/sopshq-keys/` on an encrypted volume. SopsHQ then manages every account's keys
without root and without writing into other accounts' homes.

```
/srv/sopshq-keys/            <- neutral path (encrypted volume recommended), owned by the SopsHQ service account
  alice/    keys.txt
  mailsvc/  keys.txt
```

### Turning it on

- Set **`keybase_root`** in the config file to an absolute path.
- It is **machine-local** and never replicated, so each machine may use a different
  root or none.
- An OS user created with a **blank** keystore path while a root is set is stored with
  an empty `key_base`. Such a "root-derived" user's store is
  `<keybase_root>/<username>/keys.txt`.
- Because the stored `key_base` is empty, nothing machine-local replicates. On a peer,
  a root-derived user resolves against that peer's own `keybase_root`, or is left for
  the peer to manage if the account is not the peer's.
- Users that already have an explicit `key_base` are unchanged.

### Running as a dedicated account

- The recommended deployment runs SopsHQ as a dedicated unprivileged service account,
  for example `sopshq`, which **owns** the keybase root.
- The only privileged step is a one-time root bootstrap that creates the root and hands
  it to that account. `sudo sopshq setup` does this, together with the account, the
  folder layout and the `keybase_root` setting; see the
  [deployment guide](../deployment.md). The running service never creates the root.
- Without setup, create the root once as root:

  ```
  sudo mkdir -p /srv/sopshq-keys && sudo chown sopshq /srv/sopshq-keys && sudo chmod 0711 /srv/sopshq-keys
  ```

- After that, the `sopshq` account owns the tree. It writes every account's key store
  and runs `setfacl` on its own files without root.
- The root is `0711` (traverse, not list). An enrolled account can descend into its own
  subfolder, but no local account can list the root and read every enrolled username.

### Per-user access with POSIX ACLs

The key files stay owned by the SopsHQ account (0600). So that each account can read its
own key, and only its own, SopsHQ applies these ACLs with `setfacl` after writing
`keys.txt`:

- `--x` (traverse only) on the root for that account, so it can reach its own subfolder
  but cannot list or read a sibling's;
- `r-x` on its own subfolder;
- `r--` on its `keys.txt`;
- a **default** `r--` on its subfolder, so a file that sops later replaces through a
  temporary file and rename inherits the grant.

### Global sets under the root

- A [secret set](../terminology.md#groupings) placed for a root-derived account lives
  at `<keybase_root>/<username>/global/<set>/`, in folders the SopsHQ account creates
  as `0700`.
- So the account can read its own copy, SopsHQ grants:
  - `r-x` on `global/` and `global/<set>/`;
  - a **default** `r--` on both, so a later rewrite of `secrets.yaml` or `.sops.yaml`
    inherits the grant;
  - `r--` on the secret files.
- This runs only for root-derived accounts. An account whose set lives under its own
  home needs no ACL.

### Verification and failure

- After `setfacl`, SopsHQ runs `getfacl` to check the grants are really present.
- Both run with a fixed argument list, never through a shell, and the username and
  paths are validated first.
- If ACLs cannot be applied (the tools are missing, the filesystem lacks ACL support,
  or permission is denied), placement **fails loud**. It returns the exact `setfacl` or
  `sudo` commands that fix it and marks the key store as not managed, rather than
  leaving an unreadable key behind.
- The local drift check re-verifies the grants and reports a store whose ACLs were
  removed, so Apply never trusts an unreachable key.

### How other accounts find their key

Discovery wiring (the `~/.bashrc` export and the `~/.config/sops/age` symlink) is
**self-only**, because writing into another account's home would need root.

- Other accounts reach their key through the ACL grant. They run `sops` with explicit
  key and secrets paths, or set `SOPS_AGE_KEY_FILE=<keybase_root>/<username>/keys.txt`
  themselves, for example in their own systemd unit.
- The panel shows such a store's discovery state as **"n/a - reached via ACL"**, not as
  an error, and offers no "Fix discovery" button for it.
- For the account SopsHQ runs as, the export and the symlink are still written, so cron
  and systemd find the key with no environment variable.

### Windows

On Windows `keybase_root` works as a plain keys folder with the same
`<root>\<user>\keys.txt` layout, but without per-user ACLs: one account runs SopsHQ and
owns the whole tree through ordinary NTFS inheritance. The folder must exist before
`serve` starts.

### Changing the root later

`keybase_root` is set at install time and can be changed later on the Settings page's
"Keys root folder" panel. The change is saved to `config.jsonc` and takes effect in the
running service at once. It moves no key already placed.

## The .sops.yaml file

SopsHQ generates each project's `.sops.yaml` with a small writer of its own (no YAML
library):

- a "Generated by SopsHQ - do not hand-edit" header;
- a comment block naming whose each public key is;
- one creation rule listing the assigned public keys.
