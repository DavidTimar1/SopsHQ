# Secret values

This part explains how the panel edits secret values without SopsHQ ever holding one,
and the features built on that: the cross-project catalog, the reuse picker, global
sets, mass update, and Quick add. For the overview, start at the
[architecture index](README.md).

## Contents

- [Encrypt and forget](#encrypt-and-forget)
- [Cross-project secrets catalog](#cross-project-secrets-catalog)
- [Secret reuse picker](#secret-reuse-picker)
- [Global (shared) secrets](#global-shared-secrets)
- [Mass update of a secret](#mass-update-of-a-secret)
- [Quick add](#quick-add)

## Encrypt and forget

The panel can add, edit, and delete the name and value pairs in a project's
`secrets.yaml`. SopsHQ keeps **no copy** of any value: the encrypted file in the project
is the only copy.

- **No copy kept.** Each save runs `sops` to encrypt the value straight into the
  project's `secrets.yaml` on the local machine. Nothing of the value is retained.
- **The key reaches sops only through `SOPS_AGE_KEY`.** To read or write, SopsHQ unseals
  the project key's private half from its own vault (the key does not need to be placed
  on disk first) and passes it to the `sops` child process in that one environment
  variable.
- **The child environment is scrubbed.** Before the key is added, every ambient
  age-identity variable is removed: `SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE`,
  `SOPS_AGE_KEY_CMD`, `SOPS_AGE_SSH_PRIVATE_KEY_FILE` and `SOPS_AGE_SSH_PRIVATE_KEY_CMD`.
  So `sops` decrypts with only the key SopsHQ supplies, never an identity from the
  operator's shell.
- **The value goes on stdin.** It is passed to `sops set` on standard input, so it never
  appears in the process list.
- **Names only, everywhere.** The panel and the audit log show secret names only. A value
  is never stored, logged, audited, or written to any document.

## Cross-project secrets catalog

The **Secrets** page (admin-only) lists every secret SopsHQ can read on this machine,
across all projects, **grouped by identical value**, so the operator can see where a
value is reused and spot duplicates.

- **How it is built.** It is a deliberate, audited bulk decrypt. For each project with a
  local folder and a wired key, SopsHQ decrypts its `secrets.yaml` in memory (exactly as
  the editor does), groups the usages by value, then discards the plaintext.
- **What reaches the browser.** Only masked counts, names and locations, never a value. A
  value is sent only when the operator clicks **Show** on a row, which calls the same
  audited per-project reveal (audited by name only).
- **What is left out.** Projects this machine cannot decrypt are not listed.
- **Audit.** The whole sweep is one `secrets_catalog` audit entry, with counts only.

## Secret reuse picker

A project page's Secrets section has a collapsible **Reuse an existing secret** panel,
for admins only. It loads the same catalog the first time it is opened.

- **What it shows.** Each value with a checkbox. The value itself is never shown in the
  picker or sent to the browser.
- **What Add selected does.** For each ticked value, SopsHQ decrypts it from its source
  on demand and writes it into this project under the same name. The copy happens
  entirely on the server, and is audited by name like any other secret write.
- **No overwrite.** A name that already exists in this project is skipped, never
  overwritten, and the result is reported by name.
- **Access.** The server enforces admin-only on the add action
  (`POST /projects/{id}/secrets/bulk-add`), matching the admin-only catalog it reads.

## Global (shared) secrets

A value can also live in a **named set** that does not belong to any project folder.
The classic case is a shared `OPENROUTER_API_KEY`.

- **Readers.** A set names one or more OS accounts as its readers. It is encrypted to
  each chosen account's existing key (the same key SopsHQ places for their projects), so
  every reader decrypts with its **own** key. There is no shared private key.
- **Where the files live.** Each set is written to `<key base>/global/<set>/secrets.yaml`,
  with its own `.sops.yaml`, in every reader's key store. The copies are byte-identical,
  so no cross-account file permission is needed.
- **What the record holds.** The `GlobalSet` record holds only the set name and the
  reader account ids, and replicates like any record. The values live only in the
  encrypted files; a reveal is audited by set and name only.
- **How SopsHQ manages a set.** It unseals any one reader's key, re-encrypts the primary
  copy, then copies the identical ciphertext to the other readers' folders.
- **How an app reads a set.** The standard sops way, with no SopsHQ in the loop:
  `sops exec-env <path> '<command>'`. The panel shows each account's exact path. A
  reader's private key must be placed first; any **Apply** for one of their projects
  does this.
- **Scope.** The local machine's OS accounts. The encrypted values are never replicated;
  only the small set record is. A one-account set is "your own global secrets".

## Mass update of a secret

A secret can be renamed or given a new value once, and the change applied to **every
place that holds the exact same name and value**: project `secrets.yaml` files and
global sets on this machine.

- **Identity is name plus value.** A same-named secret with a different value, and a
  same-valued secret under a different name, are both left alone.
- **Entry points.** From the Secrets catalog, a row's **Edit** lists the affected places
  and updates them all on save. On a project page, editing a secret shows admins "this is
  also used in N other places"; ticking it updates them too, otherwise only that project
  changes.
- **How it runs.** It decrypts on demand only to match and to write the new value,
  re-encrypts each place independently (one failure does not roll back the rest), and
  audits by name only.
- **Access.** It decrypts and writes across projects, so it is admin-only.

## Quick add

The **Quick add** page wraps the whole flow in one guided form, so a person does not
have to understand the model first.

- **The form.** Pick the secret, choose where it lives, and pick the targets:
  - **Project**: one project; the granted OS accounts all get the project key.
  - **Global**: a shared set; the chosen accounts each read with their own key.
- **Pre-flight checks.** Before acting it shows non-secret alerts:
  - filesystem access (on Unix a uid, gid, mode and parent-traversal check; on Windows a
    best-effort `icacls` read);
  - whether an account has a real home folder;
  - secret-name collisions;
  - a re-encryption notice.
- **Set it up.** It creates the missing project and folder path, wires the key (generate,
  assign, place), runs Apply, and encrypts the secret, reusing the same audited
  operations as the individual pages, and reports each step.
- **Not covered.** Creating a new OS account. Quick add works with the machine's existing
  accounts; use the OS users page to add one.
