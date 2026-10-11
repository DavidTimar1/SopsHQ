# Keys: account setup without root

This part explains how SopsHQ prepares an OS account's keystore while never running as
root. The plain-language version, with example commands, is in
[terminology](../terminology.md#setting-up-an-accounts-keystore). The placement rules
are in [keys](keys.md).

## Contents

- [The rule: print, never run](#the-rule-print-never-run)
- [What SopsHQ does per account](#what-sopshq-does-per-account)
- [Windows](#windows)

## The rule: print, never run

- SopsHQ reads account facts with `getent passwd <user>`, which needs no privilege:
  does the account exist, and what is its home?
- From that it decides what it can do itself and what only root can do.
- For the root-only part it **prints the exact `sudo` commands** for the operator to
  run, and never runs them. This is called "Mode A". Modes that use root or a sudoers
  allowlist were rejected.
- The command strings live in `internal/keysetup`, and the OS users page shows the
  steps for each account.

## What SopsHQ does per account

- **Account with a usable home:** the keystore defaults to `~/.config/sops/age`, or any
  chosen folder. SopsHQ places the key and wires discovery as usual.
- **Account with no home** (home is `/nonexistent` or missing): the default does not
  resolve, so the account needs an explicit keystore it owns, for example
  `/etc/<service>/keys`. SopsHQ prints the `sudo mkdir`, `chown` and `chmod 700`
  commands that create it. The account's program then points `SOPS_AGE_KEY_FILE` at
  `keys.txt` inside it.
- **Account that does not exist yet:** SopsHQ prints `sudo useradd -m -d /home/<acct>
  <acct>`, then the keystore commands above.
- **Keystore inside another account's home:** only root can create the default-location
  symlink there, so SopsHQ prints the `sudo ln -s` command.

## Windows

The account checks use `getent`, so they are Linux-only. On Windows the keystore is a
plain folder path, `keys.txt` is restricted to the owning account with `icacls`, and no
account commands are printed.
