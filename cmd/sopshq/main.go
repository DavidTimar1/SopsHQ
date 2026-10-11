// Command sopshq is the SopsHQ control-plane binary.
//
// Run it with NO arguments for the status dashboard: it locates the install, shows
// whether the service is stopped/locked/unlocked, lists every path this machine uses,
// and prints the exact commands to run, unlock, and check SopsHQ. A "location pointer"
// under the user config dir remembers where the data lives, so the install is found
// even when it sits on an encrypted volume that is currently locked. `init` will not
// silently repoint that pointer at a different install once one is set; pass
// -set-default to change the machine default deliberately. When no install is found at
// all (e.g. a Windows double-click on a machine that has never been set up), the bare
// run instead opens the interactive menu (see the `menu` subcommand below), with a short
// welcome screen first, so a first-time operator is guided by numbered prompts.
//
// Subcommands: install (OS-appropriate install: Linux setup, or Windows init +
// launcher), menu (interactive terminal menu covering every subcommand), setup (Linux
// install), update (Linux: replace the binary with a newer verified release), init,
// serve, start, stop, unlock, status, export, restore, reset-2fa, reset-admin, version.
//
// The vault is NEVER auto-decrypted at boot: the vault key comes from the
// SOPSHQ_VAULT_KEY environment variable, or interactively from the
// terminal WITHOUT echo. It is held only in memory and never logged.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"sopshq/internal/agent"
	"sopshq/internal/audit"
	"sopshq/internal/auth"
	"sopshq/internal/backup"
	"sopshq/internal/config"
	"sopshq/internal/keysvc"
	"sopshq/internal/model"
	"sopshq/internal/notify"
	"sopshq/internal/permmap"
	"sopshq/internal/place"
	"sopshq/internal/repl"
	"sopshq/internal/sdnotify"
	"sopshq/internal/seal"
	"sopshq/internal/stamps"
	"sopshq/internal/store"
	"sopshq/internal/totp"
	"sopshq/internal/transport"
	"sopshq/internal/unlock"
	usagelog "sopshq/internal/usage"
	"sopshq/internal/vault"
	"sopshq/internal/web"
)

// stdin is the single shared buffered reader for ALL interactive input. It must
// be shared: bufio reads ahead, so creating a fresh reader per prompt would
// discard input already buffered by a previous prompt (which breaks piped input
// and multi-prompt flows). termReadSecret and promptLine both read from it.
var stdin = bufio.NewReader(os.Stdin)

// promptSecret reads one secret from the terminal without echoing it. It is a
// package variable (not a direct call to readSecret) so a test can supply scripted
// answers without a real terminal, exercising the transfer-key setup flow hermetically.
var promptSecret = readSecret

// version is the build version. It is injected at build time from the canonical
// root VERSION file via:
//
//	go build -ldflags "-X main.version=$(cat VERSION)" ./cmd/sopshq
//
// Plain `go run`/`go test` builds report "dev".
var version = "dev"

func main() {
	args := os.Args[1:]
	err := run(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sopshq: %v\n", err)
	}
	// The bare (double-clickable) run has no console to return to on Windows, so pause
	// for a keypress before the process exits - whether run() succeeded (e.g. after the
	// status dashboard, or after the first-run menu the not-installed case opens, is
	// closed) or errored - so the last message stays readable instead of vanishing with
	// the closing window. This is the single call site for the pause: it fires at most
	// once per run, after run() has already produced any output. Linux always launches
	// from an existing terminal that stays open once the process exits, so it never
	// pauses here.
	if shouldPauseBeforeExit(len(args), runtime.GOOS) {
		pauseBeforeExit()
	}
	if err != nil {
		os.Exit(1)
	}
}

// shouldPauseBeforeExit reports whether main() should call pauseBeforeExit for this
// run: a bare invocation (argc == 0, i.e. a double-click with no subcommand) on
// Windows. It is pure so the decision is unit-tested without a real console or process
// exit.
func shouldPauseBeforeExit(argc int, goos string) bool {
	return argc == 0 && goos == "windows"
}

func run(args []string) error {
	// No arguments -> the status dashboard (state, paths, commands). It never serves
	// or changes anything; use an explicit subcommand to act.
	if len(args) == 0 {
		return cmdDashboard()
	}
	switch args[0] {
	case "install":
		return cmdInstall(args[1:])
	case "menu":
		return cmdMenu(args[1:])
	case "setup":
		return cmdSetup(args[1:])
	case "update":
		return cmdUpdate(args[1:])
	case "init":
		return cmdInit(args[1:])
	case "serve":
		return cmdServe(args[1:])
	case "start":
		return cmdStart(args[1:])
	case "stop":
		return cmdStop(args[1:])
	case "unlock":
		return cmdUnlock(args[1:])
	case "status":
		return cmdStatus(args[1:])
	case "export":
		return cmdExport(args[1:])
	case "restore":
		return cmdRestore(args[1:])
	case "reset-2fa":
		return cmdResetTOTP(args[1:])
	case "reset-admin":
		return cmdResetAdmin(args[1:])
	case "install-launcher":
		return cmdInstallLauncher(args[1:])
	case "uninstall-launcher":
		return cmdUninstallLauncher(args[1:])
	case "version", "-version", "--version":
		fmt.Println("sopshq", strings.TrimSpace(version))
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `sopshq - SOPS/age key management control plane

Run with NO arguments for the status dashboard: it locates the install, shows the
state (stopped / locked / unlocked), lists the paths this machine uses, and prints the
exact commands to run, unlock, and check SopsHQ. When no install is found at all, it
opens the interactive menu instead (a short welcome screen, then the same menu "sopshq
menu" shows), so a first-time operator is guided by numbered prompts.

  sopshq                 status dashboard (state, paths, commands)

Subcommands:
  sopshq install   the recommended way to install (Linux: the setup flow below, root;
                   Windows: init + install-launcher in sequence). Same flags as the
                   OS's underlying subcommand(s).
  sopshq menu      interactive terminal menu covering every subcommand below - it
                   prompts for each one's inputs instead of requiring flags
  sopshq setup     (Linux, root) install as a service account + systemd unit
  sopshq update    (Linux) [--check] [--from DIR] [--rollback]  replace the installed binary
                   with the newest verified release; backs up the old one and rolls back
                   by itself if the new one will not start. --check changes nothing and
                   needs no root; the rest runs as root (sudo). The vault is left locked.
  sopshq init      [-dir DIR] [-config PATH] [-name NODE_NAME] [-set-default] [-keys DIR]
  sopshq serve     [-config PATH]    run in the foreground (auto-discovers config)
  sopshq start     [-config PATH]    run detached in the background (writes a pid file)
  sopshq stop      [-config PATH]    stop the background run
  sopshq unlock    [-runtime-dir DIR]  deliver the vault key to a locked service
  sopshq status    [-runtime-dir DIR]  show whether the service is locked/unlocked
  sopshq export    [-config PATH] -out FILE
  sopshq restore   -in FILE -dir DEST
  sopshq reset-2fa    -user NAME [-config PATH]
  sopshq reset-admin  -user NAME [-config PATH]
  sopshq install-launcher    [-config PATH]  (Windows) register a Startup-folder launcher
  sopshq uninstall-launcher                  (Windows) remove that launcher
  sopshq version

"serve" and "start" both begin LOCKED when there is no terminal to type the vault key
on (the systemd service, or a background "start"): run "sudo sopshq unlock" to type the
vault key (no echo) and bring the panel up. "sudo sopshq status" shows locked/unlocked
and the panel URL.

reset-2fa clears only a panel login's two-factor (authenticator + recovery codes).
reset-admin is the full lockout recovery: it sets a NEW password (typed twice, not
echoed) for the named panel login - restoring the account if it was removed - and
clears its two-factor, so the next sign-in is password-only and you re-enroll 2FA.

install-launcher (Windows only) registers a small script in the current user's Startup
folder, run once at install time (no admin/UAC needed - the Startup folder is inside
your own profile). At every later logon it polls FOREVER for the config file to appear
(useful when the data folder lives on a volume you decrypt by hand after logging in),
then runs "sopshq serve" in a visible console window where you type the vault key as
usual - it never auto-unlocks the vault. uninstall-launcher removes that script only; it
never touches the data folder, vault, or keys.

init's -keys flag (Windows) records a SEPARATE folder for private key files, distinct
from -dir's data folder. It carries no ACL/multi-user semantics (see keybase_root on
Linux) - it is a plain, single-user keys folder.

install is the recommended one-command way to install, on either OS. On Linux it is
exactly "sopshq setup" (root-required, unchanged) - a plain alias, not a second
implementation. On Windows, where there is no root-only installer, it runs init's core
logic (choose the vault key) and then install-launcher's core logic (register the
Startup-folder launcher) in sequence against the same -dir/-config, so one command does
both steps "sopshq init" + "sopshq install-launcher" used to require separately.

menu is a full interactive alternative to typing flags: it lists every subcommand above
by number and prompts for that subcommand's own inputs (paths, names, confirmations)
instead of requiring them on the command line. Every prompt gathers and validates its
inputs (an existing config, a non-blank username or path) BEFORE asking anything else, so
a missing prerequisite is reported immediately instead of after every other answer has
already been typed. A destructive item (reset-admin, restore, uninstall-launcher) then
asks its own specific y/N confirmation, naming the exact user/path/file it is about to
act on, built from those already-gathered inputs - never a generic "run this?" asked
before the menu knows it can. Install on Linux is not confirmed a second time here - it
already confirms internally, mirroring setup's own confirm prompt. On Linux, selecting
install while not already root re-runs this same binary under sudo so the privileged
steps happen there (harmlessly re-checked by install's own root guard); every other menu
item runs as the invoking user, exactly like typing the flags by hand.

A backup archive is an AES-256-GCM-sealed ZIP holding the data directory, the
config (config.jsonc), and a plain RESTORE_README.txt. "restore" unpacks all three
into DEST; put DEST/data where SopsHQ expects its data dir and use DEST/config.jsonc.

The vault key is read from SOPSHQ_VAULT_KEY or, interactively, from
the terminal without echo. The backup key (for export/restore on the command
line) is read from SOPSHQ_BACKUP_KEY or the terminal. The scheduled, in-panel
backup uses a separate backup password you set once in the panel (stored only as a
vault-sealed ciphertext); keep a copy of it in your password manager - it is required
to restore and is never recoverable from the backup itself.
`)
}

// defaultDir returns the per-user base directory for config + data when the
// operator does not pass -dir. Production deployments should pass an explicit
// path (e.g. a folder on an encrypted volume).
func defaultDir() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "sopshq")
	}
	return "sopshq-data"
}

// machinePointerFile is the fixed, machine-wide install location pointer written by
// `sopshq setup` (Linux system install). It is root-owned and world-READABLE (0644 in a
// 0755 dir), and records the DATA BASE path - not a secret (the systemd unit already
// exposes it). Because it lives at a fixed system path rather than under one user's
// config dir, ANY user (including root running the bare `sopshq` dashboard) can locate a
// system install, no matter which user's home the per-user pointer landed in. It is a
// package var so a test can point it at a scratch file instead of the real /etc.
var machinePointerFile = "/etc/sopshq/location"

// pointerFile is an always-reachable file (under the user config dir) that records
// WHERE SopsHQ keeps its data, so later runs find the install even when the data
// lives on an encrypted volume that is currently locked. It only serves that purpose
// when it sits OUTSIDE the data base; init skips writing it when it would land inside
// the data base (see pointerInsideBase).
func pointerFile() string { return filepath.Join(defaultDir(), "location") }

// readMachinePointer returns the data base recorded in the machine-wide pointer
// (machinePointerFile), if present. The bare-run dashboard uses it so a system install
// written by `sopshq setup` is found regardless of which user runs `sopshq`.
func readMachinePointer() (string, bool) {
	b, err := os.ReadFile(machinePointerFile)
	if err != nil {
		return "", false
	}
	base := strings.TrimSpace(string(b))
	return base, base != ""
}

// readPointer returns the recorded data base directory, if any.
func readPointer() (string, bool) {
	b, err := os.ReadFile(pointerFile())
	if err != nil {
		return "", false
	}
	base := strings.TrimSpace(string(b))
	return base, base != ""
}

// writePointer records the chosen data base directory at the always-reachable
// location, so later runs find the install.
func writePointer(base string) error {
	if err := os.MkdirAll(defaultDir(), 0o700); err != nil {
		return err
	}
	return os.WriteFile(pointerFile(), []byte(base+"\n"), 0o600)
}

// discoverConfigPath finds the config to serve when `serve` is given no -config:
// the default location if present, else the pointer's location, else the default.
func discoverConfigPath() string {
	def := filepath.Join(defaultDir(), "config.jsonc")
	if _, err := os.Stat(def); err == nil {
		return def
	}
	if base, ok := readPointer(); ok {
		return filepath.Join(base, "config.jsonc")
	}
	return def
}

// resolveConfigPath picks the config.jsonc the bare-run dashboard should read, in
// precedence order:
//
//  1. explicitConfig, when non-empty (an explicit -config path);
//  2. machineBase, when non-empty (the machine-wide /etc pointer's data base - the Linux
//     system install written by `sopshq setup`);
//  3. userBase, when non-empty (the per-user pointer's data base);
//  4. <defaultDir>/config.jsonc (the final fallback).
//
// Each pointer holds a data BASE dir; the config is <base>/config.jsonc. located reports
// whether an explicit path or a pointer supplied the answer (false means the default-dir
// fallback, i.e. no install pointer resolved). It is pure - the caller injects the two
// pointer values and the default dir - so precedence is unit-tested without touching
// /etc or a real user config dir.
func resolveConfigPath(explicitConfig, machineBase, userBase, defaultDir string) (path string, located bool) {
	switch {
	case explicitConfig != "":
		return explicitConfig, true
	case machineBase != "":
		return filepath.Join(machineBase, "config.jsonc"), true
	case userBase != "":
		return filepath.Join(userBase, "config.jsonc"), true
	default:
		return filepath.Join(defaultDir, "config.jsonc"), false
	}
}

// pauseBeforeExit keeps a double-clicked console window open so the operator can
// read an error before it vanishes. It returns immediately if stdin is not a
// console (piped/CI), where ReadString hits EOF at once.
func pauseBeforeExit() {
	fmt.Fprint(os.Stderr, "\nPress Enter to exit...")
	_, _ = stdin.ReadString('\n')
}

// initOptions holds `init`'s resolved settings, whether they came from CLI flags or
// from `sopshq install`'s own prompts (Windows) - the two callers that drive the same
// core logic (runInit) without duplicating it.
type initOptions struct {
	Dir        string
	ConfigPath string // empty means <Dir>/config.jsonc
	Name       string // empty means the hostname
	SetDefault bool
	KeysDir    string // machine keys root (config keybase_root); empty means per-home key stores
}

// parseInitFlags parses the `init` subcommand's flags into an initOptions.
func parseInitFlags(args []string) (initOptions, error) {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := fs.String("dir", defaultDir(), "base directory for config and data")
	cfgPath := fs.String("config", "", "config file path (default <dir>/config.jsonc)")
	name := fs.String("name", "", "human node name (default hostname)")
	setDefault := fs.Bool("set-default", false, "make this install the machine default (repoint the bare-run location pointer even if one already points elsewhere)")
	keysDir := fs.String("keys", "", "machine keys root: local OS users without their own keystore path get keys at <root>/<username>/keys.txt (POSIX ACLs on Linux; plain folder on Windows)")
	if err := fs.Parse(normalizeFlagArgs(args)); err != nil {
		return initOptions{}, err
	}
	applyTrailingQuoteFix("dir", dir)
	applyTrailingQuoteFix("config", cfgPath)
	applyTrailingQuoteFix("keys", keysDir)
	return initOptions{Dir: *dir, ConfigPath: *cfgPath, Name: *name, SetDefault: *setDefault, KeysDir: *keysDir}, nil
}

// cmdInit scaffolds the config file (if absent) and initializes the vault.
func cmdInit(args []string) error {
	opts, err := parseInitFlags(args)
	if err != nil {
		return err
	}
	return runInit(opts)
}

// runInit is init's core logic: it scaffolds the config file (if absent) and
// initializes the vault from the given options. It is a plain function (no flag
// parsing, no subprocess) so both the flag-driven `sopshq init` and `sopshq install`
// on Windows (which runs this, then the launcher registration, against the same
// resolved -dir/-config) share exactly one implementation.
func runInit(opts initOptions) error {
	path := opts.ConfigPath
	if path == "" {
		path = filepath.Join(opts.Dir, "config.jsonc")
	}

	cfg, err := config.Load(path)
	if errors.Is(err, config.ErrNotFound) {
		host := opts.Name
		if host == "" {
			host, _ = os.Hostname()
		}
		cfg = config.Default(path, opts.Dir, host)
		if strings.TrimSpace(opts.KeysDir) != "" {
			absKeys, err := filepath.Abs(opts.KeysDir)
			if err != nil {
				return fmt.Errorf("bad -keys path: %w", err)
			}
			if absKeys == cfg.DataDir {
				return fmt.Errorf("-keys %q must be a DIFFERENT path than the data folder %q", absKeys, cfg.DataDir)
			}
			cfg.KeybaseRoot = absKeys
		}
		if err := cfg.Save(); err != nil {
			return err
		}
		fmt.Printf("Wrote config: %s (node %q, id %s)\n", path, cfg.NodeName, cfg.NodeID)
		if cfg.KeybaseRoot != "" {
			fmt.Printf("Keys root: %s (local OS users without their own keystore path get keys at %s)\n",
				cfg.KeybaseRoot, filepath.Join(cfg.KeybaseRoot, "<username>", "keys.txt"))
		}
	} else if err != nil {
		return err
	} else {
		fmt.Printf("Config already exists: %s (node %q)\n", path, cfg.NodeName)
	}

	if vault.IsInitialized(cfg.VaultDir) {
		fmt.Printf("Vault already initialized at %s (nothing to do).\n", cfg.VaultDir)
		return nil
	}
	pass, err := readNewVaultKey()
	if err != nil {
		return err
	}
	if _, err := vault.Init(cfg.VaultDir, pass); err != nil {
		return err
	}
	// Record the bare-run location pointer so a later `sopshq` (no args) finds this
	// install - but NEVER silently hijack an existing default that points at a
	// DIFFERENT install (the footgun that let a second/throwaway init steal the
	// operator's real default). Repointing requires -set-default. Store an absolute
	// path so the bare run resolves it from any working directory.
	absDir, err := filepath.Abs(opts.Dir)
	if err != nil {
		return fmt.Errorf("bad -dir path: %w", err)
	}
	var msg string
	if pointerInsideBase(absDir) {
		// A homeless service account whose HOME is the data base itself resolves the
		// per-user pointer to <data>/.config/sopshq/location - inside the very volume
		// the pointer is meant to locate, where it is unreachable when that volume is
		// locked. Writing it there is useless, so skip it. A system install created by
		// `sopshq setup` is discovered through the machine-wide pointer instead.
		msg = fmt.Sprintf("Skipped the per-user location pointer: it would land inside the data base\n"+
			"  %s\n"+
			"and be unreachable when that volume is locked. A system install is found through\n"+
			"the machine pointer written by `sopshq setup`.", absDir)
	} else {
		existing, ok := readPointer()
		var write bool
		write, msg = pointerDecision(existing, ok, absDir, opts.SetDefault)
		if write {
			if err := writePointer(absDir); err != nil {
				return err
			}
		}
	}
	fmt.Printf("Vault initialized at %s.\n", cfg.VaultDir)
	if msg != "" {
		fmt.Println(msg)
	}
	fmt.Println("Remember this vault key yourself: you will need to type it again every time you")
	fmt.Println("unlock SopsHQ on this machine (serve/unlock) - it is not only for sharing. Store")
	fmt.Println("it somewhere safe, like a password manager (e.g. KeePass): forgetting it locks")
	fmt.Println("you out of your own vault. If you ever want another machine to share and manage")
	fmt.Println("these same keys, set this SAME vault key on that machine too.")
	fmt.Println("Next: run `sopshq` (or `sopshq serve`).")
	return nil
}

// pointerDecision decides whether `sopshq init` should write the machine-wide
// "default install" location pointer (read by the bare, no-argument run). It refuses
// to silently repoint an existing pointer that targets a DIFFERENT install - the
// footgun that let a throwaway or second `init` hijack the operator's real default.
// -set-default (setDefault=true) forces a repoint. It returns whether to write and an
// operator-facing message (empty when the pointer already matches).
func pointerDecision(existing string, existingOK bool, newDir string, setDefault bool) (write bool, message string) {
	switch {
	case !existingOK:
		return true, "Set as this machine's default install (bare `sopshq` will open it)."
	case samePath(existing, newDir):
		return false, "" // already the default; nothing to change
	case setDefault:
		return true, fmt.Sprintf("Default install changed to %s (was %s).", newDir, existing)
	default:
		return false, fmt.Sprintf("NOTE: this machine's default install is still:\n  %s\n"+
			"This new install was created but is NOT the default. Re-run init with -set-default\n"+
			"to make it the default, or start it explicitly with:\n  sopshq serve -config %s",
			existing, filepath.Join(newDir, "config.jsonc"))
	}
}

// samePath reports whether two paths refer to the same location, comparing absolute,
// cleaned forms (case-insensitively on Windows).
func samePath(a, b string) bool {
	ca, err := filepath.Abs(a)
	if err != nil {
		ca = a
	}
	cb, err := filepath.Abs(b)
	if err != nil {
		cb = b
	}
	ca, cb = filepath.Clean(ca), filepath.Clean(cb)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(ca, cb)
	}
	return ca == cb
}

// pointerInsideBase reports whether the per-user location pointer would be written
// inside the data base directory. That happens when the process HOME (or
// XDG_CONFIG_HOME) resolves under the data base - e.g. a homeless service account
// whose HOME is the data base itself - which puts the pointer on the very volume it
// is meant to locate, where it is unreachable when that volume is locked.
func pointerInsideBase(base string) bool {
	ptr, err := filepath.Abs(pointerFile())
	if err != nil {
		return false
	}
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return false
	}
	return pathWithin(ptr, baseAbs)
}

// pathWithin reports whether child is the same as, or nested under, parent - comparing
// cleaned absolute forms (case-insensitively on Windows). A child on a different
// Windows volume, or any path that escapes parent, is not within it.
func pathWithin(child, parent string) bool {
	c, p := filepath.Clean(child), filepath.Clean(parent)
	if runtime.GOOS == "windows" {
		c, p = strings.ToLower(c), strings.ToLower(p)
	}
	rel, err := filepath.Rel(p, c)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// cmdExport writes an encrypted backup of the data dir.
func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	cfgPath := fs.String("config", filepath.Join(defaultDir(), "config.jsonc"), "config file path")
	out := fs.String("out", "", "output archive path (required)")
	if err := fs.Parse(normalizeFlagArgs(args)); err != nil {
		return err
	}
	applyTrailingQuoteFix("config", cfgPath)
	applyTrailingQuoteFix("out", out)
	if *out == "" {
		return errors.New("export: -out is required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	pass, err := readBackupKey(true)
	if err != nil {
		return err
	}
	if err := backup.Export(cfg.DataDir, cfg.Path(), *out, pass); err != nil {
		return err
	}
	fmt.Printf("Encrypted backup written to %s.\n", *out)
	fmt.Println("Keep it (and the backup key) somewhere safe and offline.")
	return nil
}

// cmdRestore extracts an encrypted backup into a destination directory.
func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	in := fs.String("in", "", "backup archive path (required)")
	dir := fs.String("dir", "", "destination data directory (required, must be empty)")
	if err := fs.Parse(normalizeFlagArgs(args)); err != nil {
		return err
	}
	applyTrailingQuoteFix("in", in)
	applyTrailingQuoteFix("dir", dir)
	if *in == "" || *dir == "" {
		return errors.New("restore: -in and -dir are required")
	}
	pass, err := readBackupKey(false)
	if err != nil {
		return err
	}
	if err := backup.Restore(*in, *dir, pass); err != nil {
		return err
	}
	fmt.Printf("Restored backup into %s.\n", *dir)
	fmt.Println("It now holds: data/ (the SopsHQ data directory), config.jsonc, and")
	fmt.Println("RESTORE_README.txt. Put data/ where SopsHQ expects its data dir, use")
	fmt.Println("config.jsonc, then start SopsHQ and unlock the vault as usual.")
	return nil
}

// cmdResetTOTP is the escape hatch for a lost authenticator with no usable
// recovery codes (the sole-admin lockout). It opens the store with the vault
// vault key, rotates the named user's TOTP secret, and clears their TOTPEnabled
// flag and recovery codes - so at their next login (password only) the panel
// routes them to fresh enrollment. It never prints any secret.
func cmdResetTOTP(args []string) error {
	fs := flag.NewFlagSet("reset-2fa", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path (default: auto-discovered)")
	user := fs.String("user", "", "panel username whose 2FA to reset (required)")
	if err := fs.Parse(normalizeFlagArgs(args)); err != nil {
		return err
	}
	applyTrailingQuoteFix("config", cfgPath)
	if strings.TrimSpace(*user) == "" {
		return errors.New("reset-2fa: -user is required")
	}
	path := *cfgPath
	if path == "" {
		path = discoverConfigPath()
	}
	cfg, err := config.Load(path)
	if errors.Is(err, config.ErrNotFound) {
		return fmt.Errorf("no config at %s (run `sudo sopshq setup` on Linux, or `sopshq init`, to install first)", path)
	} else if err != nil {
		return err
	}
	if !vault.IsInitialized(cfg.VaultDir) {
		return fmt.Errorf("vault not initialized at %s", cfg.VaultDir)
	}
	v, err := vault.Load(cfg.VaultDir)
	if err != nil {
		return err
	}
	pass, err := readVaultKey("Vault key: ")
	if err != nil {
		return err
	}
	if err := v.Unlock(pass); err != nil {
		return err
	}
	cr, err := storeCrypter(v)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DataDir, cfg.NodeID, cr)
	if err != nil {
		return err
	}
	name := strings.TrimSpace(*user)
	if err := resetPanel2FA(v, st, name); err != nil {
		return err
	}
	auditLog := audit.Open(filepath.Join(cfg.DataDir, "audit.jsonl"), cfg.NodeID, cr)
	_ = auditLog.Record("cli", "reset_2fa_cli", name, audit.OK, "")
	fmt.Printf("Reset 2FA for %q. They will enroll a new authenticator (and recovery codes) at next login.\n", name)
	return nil
}

// resetPanel2FA rotates the named user's TOTP secret and clears their TOTPEnabled
// flag and recovery codes, so the panel routes them to fresh enrollment at next
// login. It requires an unlocked vault (to seal the new secret) and never returns
// or prints any secret value.
func resetPanel2FA(v *vault.Vault, st *store.Store, name string) error {
	u, err := st.PanelUsers.Find(func(pu *model.PanelUser) bool { return pu.Username == name })
	if err != nil {
		return fmt.Errorf("no panel user named %q", name)
	}
	secret, err := totp.NewSecret()
	if err != nil {
		return err
	}
	sealed, err := v.Seal([]byte(secret))
	if err != nil {
		return err
	}
	u.TOTPSealed = sealed
	u.TOTPEnabled = false
	u.RecoveryCodes = nil
	return st.PanelUsers.Put(u)
}

// cmdResetAdmin is the guaranteed lockout recovery: unlike reset-2fa (which only
// clears two-factor), it also sets a NEW password for a panel login, so an operator
// who has lost the password AND every recovery code can always get back in. It opens
// the store with the vault key, prompts for a new password (twice, never echoed),
// then restores (or creates) the named account with that password and no two-factor.
// It never prints any secret and audits by username only.
func cmdResetAdmin(args []string) error {
	fs := flag.NewFlagSet("reset-admin", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path (default: auto-discovered)")
	user := fs.String("user", "", "panel username to reset/restore (required)")
	if err := fs.Parse(normalizeFlagArgs(args)); err != nil {
		return err
	}
	applyTrailingQuoteFix("config", cfgPath)
	if strings.TrimSpace(*user) == "" {
		return errors.New("reset-admin: -user is required")
	}
	path := *cfgPath
	if path == "" {
		path = discoverConfigPath()
	}
	cfg, err := config.Load(path)
	if errors.Is(err, config.ErrNotFound) {
		return fmt.Errorf("no config at %s (run `sudo sopshq setup` on Linux, or `sopshq init`, to install first)", path)
	} else if err != nil {
		return err
	}
	if !vault.IsInitialized(cfg.VaultDir) {
		return fmt.Errorf("vault not initialized at %s", cfg.VaultDir)
	}
	v, err := vault.Load(cfg.VaultDir)
	if err != nil {
		return err
	}
	pass, err := readVaultKey("Vault key: ")
	if err != nil {
		return err
	}
	if err := v.Unlock(pass); err != nil {
		return err
	}
	newPass, err := readNewPanelPassword()
	if err != nil {
		return err
	}
	cr, err := storeCrypter(v)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DataDir, cfg.NodeID, cr)
	if err != nil {
		return err
	}
	name := strings.TrimSpace(*user)
	restored, err := resetPanelAdmin(v, st, name, newPass)
	if err != nil {
		return err
	}
	auditLog := audit.Open(filepath.Join(cfg.DataDir, "audit.jsonl"), cfg.NodeID, cr)
	action := "reset_admin_cli"
	if restored {
		action = "reset_admin_cli_restored"
	}
	_ = auditLog.Record("cli", action, name, audit.OK, "")
	fmt.Printf("Panel login for %q is ready. Sign in with the new password; you will enroll a new authenticator (and recovery codes) at next login.\n", name)
	return nil
}

// resetPanelAdmin restores or resets a panel login so the operator can sign in with a
// fresh password and no two-factor. It targets, in order: an existing LIVE account
// with that username; else a soft-deleted (tombstoned) one, which it un-deletes and
// restores; else a brand-new admin account. On the target it sets the new password
// hash, rotates the sealed two-factor secret to a fresh one, clears the enrolled flag
// and recovery codes, and enables it - so the next sign-in is password-only and routes
// to fresh two-factor enrollment. It requires an unlocked vault (to seal the new
// secret) and never returns or prints any secret. It reports whether it restored a
// tombstoned account. The username is set exactly as passed so login (an exact match)
// resolves to this record.
func resetPanelAdmin(v *vault.Vault, st *store.Store, name, newPassword string) (restored bool, err error) {
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return false, err
	}
	secret, err := totp.NewSecret()
	if err != nil {
		return false, err
	}
	sealed, err := v.Seal([]byte(secret))
	if err != nil {
		return false, err
	}
	u, wasTombstone, created := pickAdminTarget(st, name)
	u.Username = strings.TrimSpace(name)
	u.PassHash = hash
	u.TOTPSealed = sealed
	u.TOTPEnabled = false
	u.RecoveryCodes = nil
	u.Enabled = true
	u.M.Deleted = false // un-delete when restoring a tombstoned account
	if created {
		u.Role = model.RoleAdmin
	}
	if err := st.PanelUsers.Put(u); err != nil {
		return false, err
	}
	return wasTombstone, nil
}

// pickAdminTarget finds the panel account reset-admin should act on for username name
// (compared case-insensitively). It prefers a LIVE account (login resolves to a live
// record, so resetting it guarantees sign-in); otherwise a tombstoned one to restore;
// otherwise it mints a fresh admin account. Among equals it takes the smallest UUID so
// the choice is deterministic. It returns the target, whether it was a tombstone, and
// whether it is brand-new.
func pickAdminTarget(st *store.Store, name string) (u *model.PanelUser, wasTombstone, created bool) {
	lower := strings.ToLower(strings.TrimSpace(name))
	var live, dead *model.PanelUser
	for _, pu := range st.PanelUsers.All() {
		if strings.ToLower(strings.TrimSpace(pu.Username)) != lower {
			continue
		}
		if pu.M.Deleted {
			if dead == nil || pu.M.UUID < dead.M.UUID {
				dead = pu
			}
		} else if live == nil || pu.M.UUID < live.M.UUID {
			live = pu
		}
	}
	switch {
	case live != nil:
		return live, false, false
	case dead != nil:
		return dead, true, false
	default:
		return &model.PanelUser{M: model.Meta{UUID: store.NewID()}, Role: model.RoleAdmin}, false, true
	}
}

// readNewPanelPassword reads a new panel-login password twice (through the promptSecret
// seam, so a test can script it without a terminal) and confirms the two entries match.
// It enforces the same 8-character minimum as panel account creation. The bytes are
// never echoed back or logged.
func readNewPanelPassword() (string, error) {
	a, err := promptSecret("New panel password (min 8 chars): ")
	if err != nil {
		return "", err
	}
	if len(a) < 8 {
		return "", errors.New("password must be at least 8 characters")
	}
	b, err := promptSecret("Confirm new password: ")
	if err != nil {
		return "", err
	}
	if a != b {
		return "", errors.New("passwords do not match")
	}
	return a, nil
}

// readBackupKey reads the backup key from the environment or stdin.
// When confirm is true (export), it asks twice.
func readBackupKey(confirm bool) (string, error) {
	if p := os.Getenv("SOPSHQ_BACKUP_KEY"); p != "" {
		return p, nil
	}
	a, err := readSecret("Backup key: ")
	if err != nil {
		return "", err
	}
	if a == "" {
		return "", errors.New("empty backup key")
	}
	if confirm {
		b, err := readSecret("Confirm backup key: ")
		if err != nil {
			return "", err
		}
		if a != b {
			return "", errors.New("backup keys do not match")
		}
	}
	return a, nil
}

// buildBackupSinks turns a machine's stored destinations into backup sinks. A
// local destination with an empty folder falls back to the data dir. Each
// destination's credential is vault-sealed in the record; it is unsealed here, in
// process, only to construct the sink, and is never logged.
func buildBackupSinks(bset *model.BackupSettings, v *vault.Vault, dataDir string) ([]backup.Sink, error) {
	var sinks []backup.Sink
	for _, d := range bset.Destinations {
		switch d.Type {
		case "local":
			folder := d.Folder
			if folder == "" {
				folder = dataDir
			}
			sinks = append(sinks, backup.LocalSink{Folder: folder})
		case "ftp":
			pass, err := unsealCred(v, d.PasswordSealed)
			if err != nil {
				return nil, fmt.Errorf("backup ftp destination %q: %w", d.Host, err)
			}
			sinks = append(sinks, backup.FTPSink{
				Host: d.Host, Port: d.Port, User: d.User, Pass: pass,
				Dir: d.Path, FTPS: d.FTPS,
			})
		case "telegram":
			tok, err := unsealCred(v, d.BotTokenSealed)
			if err != nil {
				return nil, fmt.Errorf("backup telegram destination (chat %s): %w", d.ChatID, err)
			}
			sinks = append(sinks, backup.TelegramSink{Token: tok, ChatID: d.ChatID})
		}
	}
	return sinks, nil
}

// unsealCred opens a vault-sealed destination credential. An empty sealed value
// means "no credential configured" and yields an empty string (no error). The
// plaintext is returned to the caller for immediate in-process use and is never
// logged; the error message never carries the value.
func unsealCred(v *vault.Vault, sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	b, err := v.Open(sealed)
	if err != nil {
		return "", errors.New("could not unseal a stored credential (is the vault unlocked?)")
	}
	return string(b), nil
}

// runBackup reads this machine's stored backup settings, builds one sealed archive,
// and sends it to every configured destination. The plaintext backup password and
// every destination credential are unsealed from the vault, used only inside this
// call, and never logged, returned, or stored. Each destination's outcome is
// audited by NAME only (never a credential or value). It returns an ASCII status
// summary for the panel.
func runBackup(st *store.Store, cfg *config.Config, v *vault.Vault, auditLog *audit.Log) (string, error) {
	bset := st.BackupSettingsFor(cfg.LocalMachineID)
	if bset.PasswordSealed == "" {
		return "", errors.New("backup password is not set (set it in the panel under Backups)")
	}
	pass, err := v.Open(bset.PasswordSealed)
	if err != nil {
		return "", errors.New("could not open the backup password (is the vault unlocked?)")
	}
	sinks, err := buildBackupSinks(bset, v, cfg.DataDir)
	if err != nil {
		return "", err
	}
	filename := backup.BuildFilename(bset.BaseName, bset.DateFormat, bset.DatePosition, time.Now())
	res, err := backup.Run(cfg.DataDir, cfg.Path(), string(pass), filename, sinks)
	if err != nil {
		_ = auditLog.Record("system", "backup_run", filename, audit.Failed, "build failed")
		return "", fmt.Errorf("backup: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%d bytes)", res.Filename, res.Size)
	if len(res.Sinks) == 0 {
		b.WriteString(" - no destinations configured")
	}
	for _, sr := range res.Sinks {
		if sr.OK {
			_ = auditLog.Record("system", "backup_run", sr.Label, audit.OK, "")
			fmt.Fprintf(&b, "; %s [ok]", sr.Label)
		} else {
			_ = auditLog.Record("system", "backup_run", sr.Label, audit.Failed, "")
			fmt.Fprintf(&b, "; %s [failed: %s]", sr.Label, sr.Err)
		}
	}
	return b.String(), nil
}

// runBackupTicker fires doBackup once per day at the configured local "HH:MM". It
// blocks until ctx is cancelled. A run that errors is logged and the schedule
// continues, so a bad destination never stops serve.
func runBackupTicker(ctx context.Context, dailyAt string, doBackup func() (string, error)) {
	for {
		timer := time.NewTimer(untilNextDaily(time.Now(), dailyAt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			summary, err := doBackup()
			if err != nil {
				fmt.Fprintf(os.Stderr, "backup: %v\n", err)
			} else {
				fmt.Printf("Daily backup: %s\n", summary)
			}
		}
	}
}

// enforceAuditRetention applies this machine's audit-retention policy once. It
// re-reads the policy from configPath each run, so a change made in the panel takes
// effect without restarting serve. When a positive day limit is set, it removes
// audit entries older than that many days; with the export-then-purge action (the
// default) it first archives the entries it is about to remove to a timestamped
// JSONL under <dataDir>/audit-archive, then deletes them. It returns how many
// entries were removed and records the purge in the log (actor "system", count
// only - never a value). A zero or negative day limit is a no-op.
func enforceAuditRetention(configPath, dataDir string, auditLog *audit.Log, now time.Time) (int, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return 0, fmt.Errorf("reload config: %w", err)
	}
	ret := cfg.AuditRetention
	if ret.DaysToKeep <= 0 {
		return 0, nil
	}
	cutoff := now.AddDate(0, 0, -ret.DaysToKeep)
	if ret.Action != config.AuditActionPurge { // empty or export_then_purge -> archive first
		archiveDir := filepath.Join(dataDir, "audit-archive")
		if err := os.MkdirAll(archiveDir, 0o700); err != nil {
			return 0, fmt.Errorf("archive dir: %w", err)
		}
		dest := filepath.Join(archiveDir, "audit-"+now.Format("2006-01-02-150405")+".jsonl")
		if _, err := auditLog.ExportBefore(cutoff, dest); err != nil {
			return 0, fmt.Errorf("export: %w", err)
		}
	}
	removed, err := auditLog.PurgeBefore(cutoff)
	if err != nil {
		return removed, fmt.Errorf("purge: %w", err)
	}
	if removed > 0 {
		_ = auditLog.Record("system", "audit_retention", "audit", audit.OK, fmt.Sprintf("removed %d", removed))
	}
	return removed, nil
}

// retentionDailyAt is the local time-of-day the audit-retention ticker fires at.
// Retention has no operator-chosen time (unlike backups), so it runs once a day at
// a quiet hour.
const retentionDailyAt = "03:30"

// runRetentionTicker fires enforce once per day at retentionDailyAt. It blocks until
// ctx is cancelled. A run that errors is logged and the schedule continues, so a bad
// archive write or purge never stops serve.
func runRetentionTicker(ctx context.Context, enforce func() (int, error)) {
	for {
		timer := time.NewTimer(untilNextDaily(time.Now(), retentionDailyAt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			removed, err := enforce()
			if err != nil {
				fmt.Fprintf(os.Stderr, "audit retention: %v\n", err)
			} else if removed > 0 {
				fmt.Printf("Audit retention: removed %d entries\n", removed)
			}
		}
	}
}

// permmapDailyAt is the local time-of-day the permission-map drift scan fires at.
// It is offset from the retention ticker so the two background jobs do not start
// in the same instant.
const permmapDailyAt = "04:00"

// enforcePermmapDrift runs one permission-map drift pass: re-read config, and if
// the auditor is enabled, scan the configured roots as the scan user, store the
// result as the latest scan, and diff it against the operator-set baseline. When
// the diff is non-empty it records a count-only audit row and sends a digest
// through the notifier (EventPermDrift). It is Linux-only (a no-op elsewhere) and
// never logs any path or the map itself. With no baseline set it stores the scan
// but does not alert - the baseline is a deliberate operator action.
func enforcePermmapDrift(configPath string, st *permmap.Store, auditLog *audit.Log, notifier *notify.Notifier, now time.Time) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("reload config: %w", err)
	}
	pm := cfg.PermissionMap
	if !pm.Enabled {
		return nil
	}
	entries, err := permmap.Collect(pm.ScanUser, pm.EffectiveRoots())
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	snap := &permmap.Snapshot{ScannedAt: now, Roots: pm.EffectiveRoots(), Entries: entries}
	if err := st.WriteLatest(snap); err != nil {
		return fmt.Errorf("store scan: %w", err)
	}
	base, err := st.ReadBaseline()
	if err != nil {
		return fmt.Errorf("read baseline: %w", err)
	}
	if base == nil {
		return nil // no baseline yet; nothing to diff against
	}
	d := permmap.Compare(base.Entries, snap.Entries)
	if d.Empty() {
		return nil
	}
	auditLog.Record("system", "permmap_drift", "permmap", audit.OK,
		fmt.Sprintf("added=%d removed=%d changed=%d", len(d.Added), len(d.Removed), len(d.Changed)))
	notifier.Notify(model.EventPermDrift, fmt.Sprintf(
		"permission map drift: %d added, %d removed, %d changed since baseline",
		len(d.Added), len(d.Removed), len(d.Changed)))
	return nil
}

// runPermmapTicker fires enforce once per day at permmapDailyAt. It blocks until
// ctx is cancelled. A run that errors is logged and the schedule continues, so a
// bad scan never stops serve.
func runPermmapTicker(ctx context.Context, enforce func() error) {
	for {
		timer := time.NewTimer(untilNextDaily(time.Now(), permmapDailyAt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			if err := enforce(); err != nil {
				fmt.Fprintf(os.Stderr, "permission map drift: %v\n", err)
			}
		}
	}
}

// untilNextDaily returns the duration from now to the next occurrence of the local
// time-of-day hhmm ("HH:MM"). If that time already passed today, it targets tomorrow.
func untilNextDaily(now time.Time, hhmm string) time.Duration {
	t, err := time.ParseInLocation("15:04", hhmm, now.Location())
	if err != nil {
		// Unreachable: config validation rejects a malformed daily_at. Fall back to
		// roughly daily so a misconfig still does something sane rather than spin.
		return 24 * time.Hour
	}
	next := time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), 0, 0, now.Location())
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next.Sub(now)
}

// cmdServe unlocks the vault and runs the panel (explicit subcommand, for power
// users and service managers). The bare `sopshq` (no args) opens the dashboard or the
// first-run menu instead.
func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path (default: auto-discovered)")
	if err := fs.Parse(normalizeFlagArgs(args)); err != nil {
		return err
	}
	applyTrailingQuoteFix("config", cfgPath)
	path := *cfgPath
	if path == "" {
		path = discoverConfigPath()
	}
	cfg, err := config.Load(path)
	if errors.Is(err, config.ErrNotFound) {
		return fmt.Errorf("no config at %s (run `sudo sopshq setup` on Linux, or `sopshq init`, to install first)", path)
	} else if err != nil {
		return err
	}
	// Refuse to serve as root or from a data dir this process does not own: the
	// long-running service must run as the dedicated unprivileged sopshq account.
	if err := checkServeGuard(cfg.DataDir); err != nil {
		return err
	}
	// Preflight the writable paths BEFORE the vault key is ever touched, so a missing
	// data dir, a wrong owner, or an unmounted volume stops serve with a truthful,
	// path-naming error instead of a misleading read-only-filesystem crash after unlock.
	if err := runPreflight(cfg); err != nil {
		return err
	}
	// Single-instance: take an exclusive lock on the data directory for the whole run,
	// so a second serve on the same data directory is refused up front instead of two
	// processes fighting over the store, oplog, and unlock socket. Held until serve exits.
	releaseLock, err := acquireInstanceLock(cfg.DataDir)
	if err != nil {
		return err
	}
	defer releaseLock()
	if !vault.IsInitialized(cfg.VaultDir) {
		return fmt.Errorf("vault not initialized at %s (run `sopshq` with no arguments)", cfg.VaultDir)
	}
	v, err := vault.Load(cfg.VaultDir)
	if err != nil {
		return err
	}
	// Acquire the vault key and boot, in this order:
	//  1. SOPSHQ_VAULT_KEY in the environment -> unlock now (automation).
	//  2. An interactive terminal -> prompt without echo, unlock now (foreground start).
	//  3. Otherwise (systemd / no terminal) -> LOCKED SOCKET MODE: start locked and wait
	//     for `sopshq unlock` to deliver the vault key over a private socket.
	// The vault never auto-unlocks: every path takes the key from the operator (or an
	// explicit env var), holds it only in memory, and never logs it.
	if key, ok := envVaultKey(); ok {
		if err := v.Unlock(key); err != nil {
			return err
		}
		fmt.Println("Vault unlocked.")
		return runServer(cfg, v, nil)
	}
	if stdinIsTTY() {
		pass, err := readSecret("Vault key: ")
		if err != nil {
			return err
		}
		if err := v.Unlock(pass); err != nil {
			return err
		}
		fmt.Println("Vault unlocked.")
		return runServer(cfg, v, nil)
	}
	return lockedServe(cfg, v)
}

// panelURLSink receives the panel's base URL once the listener address is resolved, so
// the unlock socket's status reply can report where the panel is. It is satisfied by
// the unlock server in locked-socket mode and is nil for the foreground paths.
type panelURLSink interface{ SetPanelURL(url string) }

// lockedServe runs the service in LOCKED state: it opens the private unlock socket,
// signals systemd it is up, and waits for `sopshq unlock` to deliver the vault key. It
// serves NO panel or agent until the vault is unlocked. On unlock it boots the full
// server, leaving the socket answering `sopshq status` for the rest of the run. The
// vault key travels the socket and is never logged.
func lockedServe(cfg *config.Config, v *vault.Vault) error {
	runtimeDir := defaultRuntimeDir()
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return fmt.Errorf("create runtime dir %s: %w", runtimeDir, err)
	}
	sockPath := filepath.Join(runtimeDir, "unlock.sock")
	srv, err := unlock.Listen(sockPath)
	if err != nil {
		return err
	}
	defer srv.Close()
	// Advertise our data dir over the status socket so `sopshq unlock` can refuse to
	// deliver the vault key to a stale process on a different data path.
	srv.SetDataDir(cfg.DataDir)
	// Advertise the running version so `sopshq update` can confirm the new build is the
	// one that came up.
	srv.SetVersion(strings.TrimSpace(version))

	notifier := sdnotify.New()
	_ = notifier.Ready("locked; run: sudo sopshq unlock")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Accept unlock/status requests for the whole run. onUnlock derives and verifies the
	// vault key in memory; a wrong key returns an error and the service stays locked so
	// the operator can retry.
	go srv.Serve(func(key string) error { return v.Unlock(key) })

	fmt.Printf("SopsHQ started LOCKED (vault not unlocked). Unlock it with:\n  sudo sopshq unlock\nWaiting for the vault key on %s ...\n", sockPath)

	select {
	case <-ctx.Done():
		return nil // stopped before it was ever unlocked
	case <-srv.Unlocked():
	}
	_ = notifier.SetStatus("unlocked")
	fmt.Println("Vault unlocked.")
	return runServer(cfg, v, srv)
}

// storeCrypter derives the at-rest crypter that seals the record store, the
// oplog, and the audit log. The 32-byte key comes from the UNLOCKED vault (via
// HKDF over the vault DEK), so callers must unlock the vault first; the key is
// never logged. Every code path that opens the store/audit goes through this so
// the on-disk data is unreadable as plaintext.
func storeCrypter(v *vault.Vault) (*seal.Crypter, error) {
	key, err := v.DeriveStoreKey()
	if err != nil {
		return nil, err
	}
	return seal.New(key)
}

// effectiveBind returns the address a listener should actually bind. A peer (or a
// browser on another tailnet machine) cannot reach a loopback address, so when the
// configured address is loopback and this host has a Tailscale address, it binds on
// that instead - reachable over the tailnet ONLY, never a public interface. Any
// other configured address is used as-is. label + the log line make the choice
// visible. The address others use to reach this node is this same stable Tailscale IP.
func effectiveBind(label, listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || !transport.IsLoopbackHost(host) {
		return listen
	}
	if tsip, ok := transport.TailscaleIP(); ok {
		bound := net.JoinHostPort(tsip, port)
		fmt.Printf("%s: binding on Tailscale address %s (config was loopback, which other machines cannot reach)\n", label, bound)
		return bound
	}
	fmt.Printf("%s: bound on loopback only (no Tailscale address found); reach it via an SSH tunnel.\n", label)
	return listen
}

// runServer opens the store, starts the agent + replication + admin panel, and
// blocks until interrupted. The vault must already be unlocked. When urlSink is
// non-nil (locked-socket mode) it receives the resolved panel URL so `sopshq status`
// can report it; foreground callers pass nil.
func runServer(cfg *config.Config, v *vault.Vault, urlSink panelURLSink) error {
	cr, err := storeCrypter(v)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DataDir, cfg.NodeID, cr)
	if err != nil {
		return err
	}
	auditLog := audit.Open(filepath.Join(cfg.DataDir, "audit.jsonl"), cfg.NodeID, cr)
	_ = auditLog.Record("system", "serve_start", cfg.NodeName, audit.OK, "version "+strings.TrimSpace(version))

	ks := keysvc.New(st, v, auditLog, cfg.LocalMachineID)
	ks.SetUsage(usagelog.Open(filepath.Join(cfg.DataDir, "usage.jsonl")))
	// Shared keybase root (machine-local): when set, root-derived OS users store their
	// keys under it and SopsHQ grants each user read on their own key via POSIX ACLs.
	// SopsHQ never creates the root; warn loudly (with the one-time sudo commands) if it
	// is missing or not owned by this account, so placement failures are not a surprise.
	ks.SetKeybaseRoot(cfg.KeybaseRoot)
	if cfg.KeybaseRoot != "" {
		if err := place.CheckSharedRoot(cfg.KeybaseRoot); err != nil {
			fmt.Fprintf(os.Stderr, "keybase_root: %v\n", err)
		}
	}

	// Machine-local external-change guard: a SHA-384 content stamp per managed file
	// (keys.txt, .sops.yaml, secrets.yaml) so a write that would clobber a hand-edit
	// pauses for the operator to reconcile. It holds hashes + secret names only (no
	// values) and is never replicated.
	stmp, err := stamps.Open(filepath.Join(cfg.DataDir, "stamps.json"))
	if err != nil {
		return err
	}
	ks.SetStamps(stmp)

	// Best-effort usage ingestion token (lets the sops shim report decrypts).
	ingestToken, err := loadOrCreateIngestToken(cfg.DataDir)
	if err != nil {
		return err
	}

	// Shared transfer key for machine-to-machine sync, unsealed from the config (it
	// is stored vault-sealed). Empty until the operator sets a transfer key in the
	// panel; while empty this node neither serves peers nor pulls from them. Changing
	// it in the panel takes effect on the next start.
	var transferKey string
	if cfg.TransferKeySealed != "" {
		tk, err := v.Open(cfg.TransferKeySealed)
		if err != nil {
			return fmt.Errorf("unseal transfer key: %w", err)
		}
		transferKey = string(tk)
	}
	ks.SetTransferKey(transferKey)

	ag := agent.NewServer(transferKey, cfg.NodeName, strings.TrimSpace(version))
	ag.SetOplogSource(st.Oplog().Since) // expose our oplog to peers for replication
	// A peer must be able to REACH this agent, so a loopback bind (the default) is
	// useless in a cluster. When agent_listen is loopback and this host has a
	// Tailscale address, bind on that instead so peers can reach it over the tailnet
	// (and ONLY the tailnet - not a public interface). Logged so it is not a surprise.
	agentBind := effectiveBind("Agent", cfg.AgentListen)
	agentSrv := ag.HTTPServer(agentBind)
	go func() {
		fmt.Printf("Agent listening on http://%s/\n", agentBind)
		if e := agentSrv.ListenAndServe(); e != nil && !errors.Is(e, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "agent: %v\n", e)
		}
	}()
	defer agentSrv.Close()

	// Event notifier: reads this machine's NotificationSettings on each event and
	// fans enabled events out to Telegram/Slack. It reads cfg.LocalMachineID live
	// (it can change when the operator designates the local machine) and never
	// blocks or fails the action that triggers it. It is built before the
	// replication loop so a failed peer pull can alert through it.
	notifier := notify.New(st, v, auditLog, func() string { return cfg.LocalMachineID })

	// Replication: pull each enrolled peer's oplog and apply with last-writer-wins.
	syncer := repl.NewSyncer(st, auditLog, cfg.DataDir)
	syncOnce := func() (peers, applied, conflicts int) {
		if transferKey == "" {
			return // no transfer key set yet -> nothing to sync
		}
		for _, mc := range st.Machines.List() {
			if mc.M.UUID == cfg.LocalMachineID || mc.TailscaleHost == "" || mc.AgentPort == 0 {
				continue
			}
			peers++
			cli := agent.Dial(transport.AgentBaseURL(mc.TailscaleHost, mc.AgentPort), transferKey)
			res, err := syncer.Pull(mc.M.UUID, mc.Name, cli)
			if err != nil {
				fmt.Fprintf(os.Stderr, "sync %s: %v\n", mc.Name, err)
				notifier.Notify(model.EventReplicationError, "sync from "+mc.Name+" failed")
				continue
			}
			applied += res.Applied
			conflicts += res.Conflicts
		}
		return
	}

	panel, err := web.NewServer(st, v, auditLog, ks, cfg, strings.TrimSpace(version), 12*time.Hour)
	if err != nil {
		return err
	}
	panel.SetSync(syncOnce)
	// Live per-peer status for the Machines page: ping each peer (short timeout so the
	// page never hangs on an unreachable host) and fold in the last pull outcome.
	panel.SetPeerStatus(func() []web.PeerStatus {
		var out []web.PeerStatus
		for _, mc := range st.Machines.List() {
			if mc.M.UUID == cfg.LocalMachineID {
				continue
			}
			ps := web.PeerStatus{MachineID: mc.M.UUID}
			switch {
			case mc.TailscaleHost == "" || mc.AgentPort == 0:
				ps.Err = "no Tailscale address set for this machine"
			case transferKey == "":
				ps.Err = "transfer key not set on this machine"
			default:
				url := transport.AgentBaseURL(mc.TailscaleHost, mc.AgentPort)
				if pr, err := agent.DialTimeout(url, transferKey, 3*time.Second).Ping(); err != nil {
					ps.Err = err.Error()
				} else {
					ps.Reachable = pr.OK
					ps.Version = pr.Version
				}
			}
			if ss := syncer.Status(mc.M.UUID); ss.AtUnix != 0 {
				ps.LastSyncUnix = ss.AtUnix
				ps.Applied = ss.Applied
				ps.Conflicts = ss.Conflicts
				if ps.Err == "" && ss.Err != "" {
					ps.Err = ss.Err
				}
			}
			out = append(out, ps)
		}
		return out
	})
	panel.SetIngestToken(ingestToken)
	panel.SetNotifier(notifier)

	// Machine-local permission-auditor storage: the latest scan and the baseline,
	// vault-sealed and NEVER replicated (the map reveals the whole filesystem
	// layout). The panel reads scans from it; the daily drift ticker writes them.
	pmStore, err := permmap.OpenStore(cfg.DataDir, cr)
	if err != nil {
		return err
	}
	panel.SetPermmap(pmStore)

	// Self-backup runner: builds a sealed archive (data + config + restore guide)
	// and sends it to every configured destination. It re-reads this machine's
	// stored backup settings on every run and unseals credentials in process, so
	// the daily ticker and the panel "Back up now" button both reuse it and always
	// see the latest settings. The vault is already unlocked here. Each run alerts
	// the notifier with a per-destination, credential-free outcome summary.
	doBackup := func() (string, error) {
		summary, err := runBackup(st, cfg, v, auditLog)
		if err != nil {
			notifier.Notify(model.EventBackup, "backup failed: "+err.Error())
		} else {
			notifier.Notify(model.EventBackup, "backup ok - "+summary)
		}
		return summary, err
	}
	panel.SetBackupRunner(doBackup)

	// Serve the panel over plain HTTP. Transport security comes from the network
	// boundary, not the app: bind loopback (reach it via an SSH tunnel) or a
	// Tailscale address (WireGuard-encrypted, tailnet-only). Login (password + TOTP)
	// and CSRF still gate every request; the session cookie's Secure flag is simply
	// off over HTTP, which is fine on loopback/Tailscale.
	panelBind := effectiveBind("Panel", cfg.PanelListen)
	// Bind the panel port eagerly (before reporting it) so a port already held by
	// another process fails here with a clear, address-naming error instead of a late,
	// buried goroutine log. This is the port half of single-instance enforcement.
	panelLn, err := net.Listen("tcp", panelBind)
	if err != nil {
		return fmt.Errorf("cannot bind the panel on %s (is another SopsHQ or service already using this port?): %w", panelBind, err)
	}
	if urlSink != nil {
		urlSink.SetPanelURL("http://" + panelBind + "/")
	}
	fmt.Printf("Usage ingestion: POST http://%s/ingest/keyused (token in %s)\n",
		panelBind, filepath.Join(cfg.DataDir, "ingest.token"))
	srv := &http.Server{Addr: panelBind, Handler: panel.Handler(), ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Background "changes need applying" check: computes drift on this machine and
	// probes peers (off the request path, since a peer can be slow/offline).
	panel.StartPendingRefresher(ctx.Done())

	// Daily self-backup ticker. Only runs while serve is up (the operator accepts
	// that trade-off). A failed run is logged and never crashes serve. The schedule
	// is read from this machine's stored backup settings.
	if bset := st.BackupSettingsFor(cfg.LocalMachineID); bset.Enabled {
		go runBackupTicker(ctx, bset.DailyAt, doBackup)
	}

	// Daily audit-retention ticker. It only starts when a positive day limit is set
	// at boot; each run re-reads the policy from config so a later panel change to the
	// day count or action takes effect without a restart. A failed run is logged and
	// never crashes serve.
	if cfg.AuditRetention.DaysToKeep > 0 {
		go runRetentionTicker(ctx, func() (int, error) {
			return enforceAuditRetention(cfg.Path(), cfg.DataDir, auditLog, time.Now())
		})
	}

	// Daily permission-map drift ticker (Linux only). Each run re-reads config, so
	// enabling/disabling the auditor from the panel takes effect without a restart;
	// it is a no-op while disabled. A failed scan is logged and never crashes serve.
	// Drift alerts fire only once the operator has set a baseline (a deliberate act).
	if runtime.GOOS == "linux" {
		go runPermmapTicker(ctx, func() error {
			return enforcePermmapDrift(cfg.Path(), pmStore, auditLog, notifier, time.Now())
		})
	}

	// Periodic background replication.
	go func() {
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				syncOnce()
			}
		}
	}()
	errCh := make(chan error, 1)
	go func() {
		fmt.Printf("Panel listening on http://%s/ (Ctrl-C to stop)\n", panelBind)
		errCh <- srv.Serve(panelLn)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// loadOrCreateIngestToken loads (or creates) the local usage-ingestion token.
// The token only authorizes appending a best-effort usage note (no key access),
// so the file is world-readable (0644) - the sops shim, run as a normal user,
// must be able to read it.
func loadOrCreateIngestToken(dataDir string) (string, error) {
	path := filepath.Join(dataDir, "ingest.token")
	if b, err := os.ReadFile(path); err == nil {
		if tok := strings.TrimSpace(string(b)); tok != "" {
			return tok, nil
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("ingest token: %w", err)
	}
	tok := hex.EncodeToString(raw)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("ingest token: %w", err)
	}
	return tok, nil
}

// envVaultKey returns the vault key from SOPSHQ_VAULT_KEY if set, and
// CLEARS it from this process's environment after reading. Clearing it means the
// vault key is not left sitting in /proc/<pid>/environ for the life of the
// process, so neither the operator's shell (the script passes it only to this
// child) nor a later inspector finds it there. The value stays only in memory.
func envVaultKey() (string, bool) {
	p := os.Getenv("SOPSHQ_VAULT_KEY")
	if p == "" {
		return "", false
	}
	_ = os.Unsetenv("SOPSHQ_VAULT_KEY")
	// Normalize exactly like the interactive readers, which TrimRight "\r\n". A
	// vault key supplied through the environment routinely picks up trailing
	// whitespace it was never meant to carry - a here-doc or CRLF file leaves a
	// "\r" or "\n", a shell may append a space - and an untrimmed value derives a
	// DIFFERENT vault key than the same vault key typed at the prompt, so unlock
	// fails with "wrong vault key" even though the vault key is correct. Trim
	// trailing whitespace so the env path and the prompt path agree.
	p = strings.TrimRight(p, " \t\r\n")
	if p == "" {
		return "", false
	}
	return p, true
}

// readNewVaultKey reads a vault key twice (from stdin) and confirms they
// match. It is used by `init`. The bytes are never echoed back or logged.
func readNewVaultKey() (string, error) {
	if p, ok := envVaultKey(); ok {
		return p, nil
	}
	a, err := readVaultKey("Choose a vault key: ")
	if err != nil {
		return "", err
	}
	b, err := readVaultKey("Confirm vault key: ")
	if err != nil {
		return "", err
	}
	if a != b {
		return "", errors.New("vault keys do not match")
	}
	if a == "" {
		return "", errors.New("empty vault key")
	}
	return a, nil
}

// readVaultKey obtains the vault key from the environment if set (clearing it
// from the process env), otherwise reads it from the terminal without echo.
func readVaultKey(prompt string) (string, error) {
	if p, ok := envVaultKey(); ok {
		return p, nil
	}
	return readSecret(prompt)
}

// errNoEcho is returned by termReadSecret when no-echo input is not available
// (stdin is not an interactive terminal, or the platform has no implementation).
var errNoEcho = errors.New("no-echo terminal input unavailable")

// readSecret reads a secret from the terminal WITHOUT echoing it, trying three
// layers in order:
//
//  1. the native no-echo path (Windows console API / Linux termios);
//  2. `stty -echo` - covers MSYS/Cygwin terminals like Git Bash on Windows, where
//     stdin is a pseudo-terminal the Windows console API does not recognize;
//  3. a plain visible read (piped input, or no terminal control available), with
//     a one-time note so the caller never blocks.
func readSecret(prompt string) (string, error) {
	if s, err := termReadSecret(prompt); err == nil {
		return s, nil
	} else if !errors.Is(err, errNoEcho) {
		return "", err
	}
	if s, err := sttyReadSecret(prompt); err == nil {
		return s, nil
	} else if !errors.Is(err, errNoEcho) {
		return "", err
	}
	fmt.Fprintln(os.Stderr, "  (note: input may be visible - no no-echo terminal available)")
	return promptLine(prompt)
}

// sttyReadSecret disables terminal echo via the `stty` command (present in
// MSYS/Git Bash and on Unix), reads one line, and restores echo. Returns
// errNoEcho if stty is unavailable or stdin is not a terminal, so readSecret
// falls through to a visible read.
func sttyReadSecret(prompt string) (string, error) {
	sttyPath, err := exec.LookPath("stty")
	if err != nil {
		return "", errNoEcho
	}
	off := exec.Command(sttyPath, "-echo")
	off.Stdin = os.Stdin
	if err := off.Run(); err != nil {
		return "", errNoEcho // no controlling terminal (piped/redirected)
	}
	defer func() {
		on := exec.Command(sttyPath, "echo")
		on.Stdin = os.Stdin
		_ = on.Run()
	}()
	fmt.Print(prompt)
	line, rerr := stdin.ReadString('\n')
	fmt.Println() // the user's Enter was not echoed
	if rerr != nil && line == "" {
		return "", rerr
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// promptLine reads a single visible line from stdin after printing prompt. It
// consults no environment variable.
func promptLine(prompt string) (string, error) {
	fmt.Print(prompt)
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("read input: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}
