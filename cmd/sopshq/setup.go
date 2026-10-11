package main

import (
	"bytes"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"text/template"
)

// serviceTemplate is the systemd unit, rendered by `sopshq setup` with the chosen
// paths and service account. It ships INSIDE the binary (no separate .service file),
// so a release is just the binary.
//
//go:embed deploy/sopshq.service.tmpl
var serviceTemplate string

// Neutral defaults for the setup prompts. Each is confirmed or changed at the prompt
// (or overridden by a flag). Data base and keybase root belong on a neutral path outside
// any user home (an encrypted mount is recommended, not required).
const (
	setupPrefixDefault  = "/opt/sopshq"      // install prefix: the binary lives here (root:root 0755)
	setupDataDefault    = "/srv/sopshq"      // data base: config + vault + store + audit + sealed keys (0700)
	setupKeybaseDefault = "/srv/sopshq-keys" // keybase root: per-user key stores (0711); blank to skip
	setupUserDefault    = "sopshq"           // dedicated unprivileged service account
)

// PATH symlink: setup points /usr/local/bin/sopshq at <prefix>/sopshq so the `sopshq`
// command resolves on PATH (the install prefix itself is not on PATH). /usr/local/bin is
// on sudo's secure_path, so `sudo sopshq unlock` / `sudo sopshq status` work after setup.
const (
	pathSymlink    = "/usr/local/bin/sopshq"
	pathSymlinkDir = "/usr/local/bin"
)

// The optional permission-scan account and its sudoers rule. Setup never creates them:
// the panel prints the commands (internal/permmap EnableInstructions) and the operator
// runs them. printFootprint names them so a manual uninstall removes them too.
const (
	scanUserDefault = "sopshq-scan"
	scanSudoersFile = "/etc/sudoers.d/sopshq-permmap"
)

// setupOptions holds the operator's setup choices (from flags, then interactive
// prompts). It is filled with the neutral defaults first.
type setupOptions struct {
	Prefix     string
	Data       string
	Keybase    string
	User       string
	ForceHome  bool
	Unattended bool // --yes / --unattended: skip the confirm prompt and the per-path prompts
	DryRun     bool // print the preview + resolved plan and make NO changes (runnable as non-root)
}

// setupPlan is the resolved, derived layout that setup executes and that the unit
// template is rendered from. All paths are absolute.
type setupPlan struct {
	Prefix      string
	Data        string
	Keybase     string // empty means "no keybase root" (keys live under each user's home)
	User        string
	BinDest     string // <prefix>/sopshq
	Config      string // <data>/config.jsonc
	DataSubdir  string // <data>/data
	UnitDest    string // /etc/systemd/system/sopshq.service
	ProtectHome string // "yes" or "no" (systemd ProtectHome=)
	ReadWrite   string // systemd ReadWritePaths= value: "<data>" or "<data> <keybase>"
}

// unitFields is the value passed to the embedded systemd unit template.
type unitFields struct {
	User        string
	Bin         string
	Config      string
	WorkDir     string
	ProtectHome string
	ReadWrite   string
}

// cmdSetup is the one-time, root-required installer: it stands SopsHQ up as a
// dedicated unprivileged service account with a neutral folder layout outside any
// user home (an encrypted mount is recommended), installs a systemd unit (not enabled
// at boot), and hands off to the binary for the interactive vault-key setup. It is Linux-only and, apart from --dry-run, requires
// root; the long-running `serve` is the mirror image (it refuses root).
func cmdSetup(args []string) error {
	if runtime.GOOS != "linux" {
		return errors.New("sopshq setup is only supported on Linux (it creates a system service account, " +
			"directories, and a systemd unit). On other systems, run `sopshq init` to set up config + vault instead")
	}

	opts, err := parseSetupFlags(args)
	if err != nil {
		return err
	}

	// Real setup requires root - refuse up front, before the preview or any prompt,
	// so the operator is told immediately rather than after filling in every path.
	// --dry-run only previews (no changes) and is allowed as a normal user.
	if !opts.DryRun && os.Geteuid() != 0 {
		return errors.New("sopshq setup must be run as root. Re-run with: sudo sopshq setup " +
			"(to preview the plan without making changes, no root needed: sopshq setup --dry-run)")
	}

	// 1. Print the FULL layout plan before any prompt, so the operator sees exactly
	//    what will be created and why.
	printSetupPreview(os.Stdout, opts)

	// 2. Prompt for each path (interactive only): a flag value pre-seeds the default,
	//    Enter accepts it. Skipped under --dry-run and --unattended, and when stdin is
	//    not a terminal, so automation and tests never block.
	if !opts.DryRun && !opts.Unattended && stdinIsTTY() {
		if err := promptSetupPaths(&opts); err != nil {
			return err
		}
	}

	// 3. Validate the choices and resolve the derived plan.
	if err := validateSetupPaths(opts.Prefix, opts.Data, opts.Keybase, opts.User, opts.ForceHome); err != nil {
		return err
	}
	plan := resolvePlan(opts)

	// 4. Echo the resolved plan.
	printSetupPlan(os.Stdout, plan)

	// --dry-run stops here: it changed nothing and needs no root.
	if opts.DryRun {
		fmt.Println("\nDry run: no changes were made.")
		return nil
	}

	// 5. Confirm before any change, unless --yes/--unattended.
	if !opts.Unattended {
		ok, err := promptLine("\nProceed and make these changes? [y/N]: ")
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(ok)) {
		case "y", "yes":
		default:
			fmt.Println("Aborted. Nothing was changed.")
			return nil
		}
	}

	unit, err := renderUnit(plan)
	if err != nil {
		return err
	}

	// Before writing anything, reconcile any already-running SopsHQ: stop the systemd
	// unit and detect + stop any stale `serve` process (showing its data path, pid, and
	// command first, and confirming). A serve left alive on the previous data path would
	// otherwise make `unlock` feed the vault key to that stale process.
	if err := reconcileExistingServe(opts.Unattended); err != nil {
		return err
	}

	return executeSetup(plan, unit)
}

// parseSetupFlags parses the setup subcommand flags into a setupOptions seeded with
// the neutral defaults.
func parseSetupFlags(args []string) (setupOptions, error) {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	prefix := fs.String("prefix", setupPrefixDefault, "install prefix (the binary is installed at <prefix>/sopshq)")
	data := fs.String("data", setupDataDefault, "data base directory (config, vault, store, audit, sealed keys)")
	keybase := fs.String("keybase", setupKeybaseDefault, "keybase root for per-user key stores (blank to skip)")
	svcUser := fs.String("user", setupUserDefault, "dedicated unprivileged service account")
	forceHome := fs.Bool("force-home", false, "allow a data or keybase path under /home/* (refused otherwise)")
	yes := fs.Bool("yes", false, "skip the confirmation and per-path prompts (unattended)")
	unattended := fs.Bool("unattended", false, "alias for --yes")
	dryRun := fs.Bool("dry-run", false, "print the preview and resolved plan, then exit making NO changes (runs as non-root)")
	if err := fs.Parse(normalizeFlagArgs(args)); err != nil {
		return setupOptions{}, err
	}
	applyTrailingQuoteFix("prefix", prefix)
	applyTrailingQuoteFix("data", data)
	applyTrailingQuoteFix("keybase", keybase)
	return setupOptions{
		Prefix:     *prefix,
		Data:       *data,
		Keybase:    strings.TrimSpace(*keybase),
		User:       *svcUser,
		ForceHome:  *forceHome,
		Unattended: *yes || *unattended,
		DryRun:     *dryRun,
	}, nil
}

// promptSetupPaths asks for each path with the current value as the default (a flag
// override shows as that default). An empty answer keeps the current value.
func promptSetupPaths(opts *setupOptions) error {
	fmt.Println("Choose the install paths (press Enter to accept a default):")
	fmt.Println()
	for _, p := range []struct {
		label string
		dst   *string
	}{
		{"  Install prefix (binary dir)", &opts.Prefix},
		{"  Data base directory", &opts.Data},
		{"  Keybase root (blank to skip)", &opts.Keybase},
		{"  Service account", &opts.User},
	} {
		in, err := promptLine(fmt.Sprintf("%s [%s]: ", p.label, *p.dst))
		if err != nil {
			return err
		}
		if in = strings.TrimSpace(in); in != "" {
			*p.dst = in
		}
	}
	return nil
}

// validateSetupPaths enforces the setup path invariants: absolute paths, a non-empty
// service account, distinct data base and keybase root (they carry different perms),
// and no /home/* placement unless forceHome is set. It is pure (no I/O) so it is unit
// tested directly.
func validateSetupPaths(prefix, data, keybase, user string, forceHome bool) error {
	if !filepath.IsAbs(prefix) {
		return fmt.Errorf("install prefix must be an absolute path: %s", prefix)
	}
	if !filepath.IsAbs(data) {
		return fmt.Errorf("data directory must be an absolute path: %s", data)
	}
	if keybase != "" && !filepath.IsAbs(keybase) {
		return fmt.Errorf("keybase root must be an absolute path: %s", keybase)
	}
	if strings.TrimSpace(user) == "" {
		return errors.New("service account name must not be empty")
	}
	if keybase != "" && data == keybase {
		return errors.New("data directory and keybase root must be DIFFERENT paths (they have different perms: 0700 vs 0711)")
	}
	if !forceHome {
		if underHome(data) {
			return fmt.Errorf("refusing a data directory under /home/* (%s). Use a neutral path outside any home (an encrypted mount is recommended), or pass --force-home", data)
		}
		if keybase != "" && underHome(keybase) {
			return fmt.Errorf("refusing a keybase root under /home/* (%s). Use a neutral path outside any home (an encrypted mount is recommended), or pass --force-home", keybase)
		}
	}
	return nil
}

// underHome reports whether p is under /home/ (a user home tree), which setup refuses
// for the data base and keybase root unless --force-home is given.
func underHome(p string) bool { return strings.HasPrefix(p, "/home/") }

// resolvePlan derives the full layout (binary, config, data subdir, unit path, and the
// systemd ProtectHome/ReadWritePaths values) from the validated options. It is pure.
func resolvePlan(opts setupOptions) setupPlan {
	p := setupPlan{
		Prefix:      opts.Prefix,
		Data:        opts.Data,
		Keybase:     opts.Keybase,
		User:        opts.User,
		BinDest:     filepath.Join(opts.Prefix, "sopshq"),
		Config:      filepath.Join(opts.Data, "config.jsonc"),
		DataSubdir:  filepath.Join(opts.Data, "data"),
		UnitDest:    systemdUnitPath,
		ProtectHome: "yes",
		ReadWrite:   opts.Data,
	}
	if opts.Keybase != "" {
		p.ReadWrite = opts.Data + " " + opts.Keybase
	}
	// If data or keys live under a home (the --force-home path), the service must be
	// able to reach them, so ProtectHome must be off.
	if underHome(opts.Data) || (opts.Keybase != "" && underHome(opts.Keybase)) {
		p.ProtectHome = "no"
	}
	return p
}

// renderUnit fills the embedded systemd unit template from the plan and returns the
// unit text. It errors if any placeholder is left unrendered, so a template drift can
// never write an invalid unit. It is pure.
func renderUnit(plan setupPlan) (string, error) {
	tmpl, err := template.New("sopshq.service").Option("missingkey=error").Parse(serviceTemplate)
	if err != nil {
		return "", fmt.Errorf("parse unit template: %w", err)
	}
	var b bytes.Buffer
	if err := tmpl.Execute(&b, unitFields{
		User:        plan.User,
		Bin:         plan.BinDest,
		Config:      plan.Config,
		WorkDir:     plan.Data,
		ProtectHome: plan.ProtectHome,
		ReadWrite:   plan.ReadWrite,
	}); err != nil {
		return "", fmt.Errorf("render unit template: %w", err)
	}
	out := b.String()
	if strings.Contains(out, "{{") || strings.Contains(out, "@@") {
		return "", errors.New("rendered systemd unit still contains a placeholder")
	}
	return out, nil
}

// pkgManager names a package manager and the argv that installs the acl package with it.
type pkgManager struct {
	Name    string
	Install []string
}

// detectPackageManager returns the first known package manager whose command is present
// (via the injected have func), and the argv that installs the acl package with it. It
// returns ok=false when none is found. Injecting the lookup keeps it pure and testable.
func detectPackageManager(have func(cmd string) bool) (pkgManager, bool) {
	candidates := []pkgManager{
		{"apt-get", []string{"apt-get", "install", "-y", "acl"}},
		{"dnf", []string{"dnf", "install", "-y", "acl"}},
		{"zypper", []string{"zypper", "--non-interactive", "install", "acl"}},
		{"pacman", []string{"pacman", "-Sy", "--noconfirm", "acl"}},
		{"yum", []string{"yum", "install", "-y", "acl"}},
	}
	for _, c := range candidates {
		if have(c.Name) {
			return c, true
		}
	}
	return pkgManager{}, false
}

// setKeybaseRootInConfig wires the keybase root into a config.jsonc body idempotently.
// It only fills an EMPTY value; a value already equal to keybase is left as-is; a
// different existing value is a conflict the caller surfaces (the config is not changed).
// It returns the (possibly unchanged) body, whether it changed it, and whether it hit a
// conflict. It is a pure string transform so it is unit tested directly.
func setKeybaseRootInConfig(body, keybase string) (out string, changed, conflict bool) {
	if keybase == "" {
		return body, false, false
	}
	if strings.Contains(body, `"keybase_root": "`+keybase+`"`) {
		return body, false, false // already set to this value
	}
	const empty = `"keybase_root": ""`
	if strings.Contains(body, empty) {
		return strings.Replace(body, empty, `"keybase_root": "`+keybase+`"`, 1), true, false
	}
	return body, false, true // set to some other value: leave it, flag a conflict
}

// printSetupPreview prints the full layout plan (paths, owners, perms, purpose, how
// per-user ACLs are applied later, and why not a home) BEFORE any prompt, so the
// operator sees the RECOMMENDED structure before setting the actual paths in the
// prompts that follow.
func printSetupPreview(w io.Writer, opts setupOptions) {
	fmt.Fprintf(w, `
==============================================================================
 SopsHQ setup - the recommended layout (you set the actual paths next)
==============================================================================

SopsHQ is a MANAGEMENT plane for SOPS/age keys. It runs as a dedicated,
UNPRIVILEGED service account (%q) - never root - and keeps its data and the
private keys it holds on a NEUTRAL path OUTSIDE any user's home (an encrypted
mount is recommended, not required).

Below is the RECOMMENDED layout. The paths shown are defaults - you set the
actual paths in the prompts that follow (each one is editable next).

`, opts.User)

	fmt.Fprint(w, renderSetupTable(opts))

	fmt.Fprintf(w, `
Why NOT a home directory (an encrypted mount is recommended):
  * A home is 0750, so the sopshq account cannot traverse into it - key placement
    for OTHER users would need root. A neutral 0711 keybase root avoids that.
  * The keys belong to a neutral service identity, not to one human's account.
  * An encrypted mount is RECOMMENDED (not required): it keeps everything unreadable
    at rest until you unlock it. Any neutral path outside a home works.

How per-user access works (applied later, at key-placement time, NOT now):
  * The keybase root is 0711 (traverse, not list) so no local user can read every
    enrolled username.
  * Each key file stays owned by %s (0600). SopsHQ grants each user read on ONLY
    their own key with POSIX ACLs (setfacl) - which is why the "acl" package is a
    prerequisite this setup ensures is present.

The systemd service is installed but NOT enabled at boot: SopsHQ never auto-unlocks
its vault. You start it by hand with "systemctl start sopshq"; because the service has
no terminal, it starts LOCKED and waits, and you unlock it with "sudo sopshq unlock"
(which prompts for the vault key without echo).

`, opts.User)
}

// renderSetupTable lays out the recommended layout rows (PATH, OWNER, PERMS, PURPOSE)
// with text/tabwriter so the columns align for ANY path lengths. The indented sub-rows
// (config.jsonc, data/, <username>/) are part of the PATH column with leading spaces.
// The whole table is indented two spaces to sit under the surrounding prose. ASCII only.
func renderSetupTable(opts setupOptions) string {
	var raw strings.Builder
	tw := tabwriter.NewWriter(&raw, 0, 0, 2, ' ', 0)
	owner := opts.User + ":" + opts.User
	fmt.Fprintln(tw, "PATH\tOWNER\tPERMS\tPURPOSE")
	fmt.Fprintf(tw, "%s/sopshq\troot:root\t0755\tthe binary - setup installs it here; all users execute\n", opts.Prefix)
	fmt.Fprintf(tw, "%s\troot:root\tsymlink\t-> %s/sopshq so \"sopshq\" is on PATH\n", pathSymlink, opts.Prefix)
	fmt.Fprintf(tw, "%s/\t%s\t0700\tdata base (see below), sopshq ONLY\n", opts.Data, owner)
	fmt.Fprintf(tw, "  config.jsonc\t%s\t0600\tconfig\n", owner)
	fmt.Fprintf(tw, "  data/\t%s\t0700\tvault, store, oplog, audit, sealed keys\n", owner)
	fmt.Fprintf(tw, "%s/\t%s\t0711\tkeybase root (traverse only)\n", opts.Keybase, owner)
	fmt.Fprintf(tw, "  <username>/\t%s\t0700\tper-user key store + POSIX ACL\n", owner)
	tw.Flush()

	var out strings.Builder
	for _, line := range strings.Split(strings.TrimRight(raw.String(), "\n"), "\n") {
		out.WriteString("  ")
		out.WriteString(line)
		out.WriteString("\n")
	}
	return out.String()
}

// staleServeMatch decides, from a process's argv, whether it is a `sopshq serve` and,
// if so, which config it was told to use. The caller has already confirmed the process
// runs the sopshq binary (by resolving /proc/<pid>/exe); this reads only the arguments.
// It recognizes both "-config PATH" / "--config PATH" and the "=" forms. It is pure so
// the argv parsing is unit-tested without a real process.
func staleServeMatch(argv []string) (configPath string, isServe bool) {
	for i, a := range argv {
		if i == 0 {
			continue // the program name
		}
		switch {
		case a == "serve":
			isServe = true
		case a == "-config" || a == "--config":
			if i+1 < len(argv) {
				configPath = argv[i+1]
			}
		default:
			if v, ok := strings.CutPrefix(a, "-config="); ok {
				configPath = v
			} else if v, ok := strings.CutPrefix(a, "--config="); ok {
				configPath = v
			}
		}
	}
	return configPath, isServe
}

// junctionOffLimits reports whether a path component must NEVER have its permissions
// weakened by the path-permission review. Three classes are protected:
//
//   - the filesystem root "/";
//   - any first-level directory (a single component under "/", e.g. /mnt, /opt, /home) -
//     weakening these would affect the whole system;
//   - any mount point (isMount true), typically an encrypted volume's mount root -
//     its access is the operator's deliberate boundary and SopsHQ never loosens it.
//
// isMount is injected (in production, membership in the /proc/mounts set) so the
// decision is pure and unit-tested with the three named paths.
func junctionOffLimits(path string, isMount func(string) bool) bool {
	clean := filepath.Clean(path)
	if clean == "/" {
		return true
	}
	if filepath.Dir(clean) == "/" {
		return true // a first-level directory, e.g. /mnt or /opt
	}
	return isMount(clean)
}

// serviceCanTraverse reports whether the service account can SEARCH (traverse) a
// directory - the "x" bit that lets it descend through the directory toward the data dir
// or keybase root. It applies the standard POSIX precedence: an ACL entry that already
// grants execute wins (aclExec); otherwise the owner bits apply when the account owns the
// directory, the group bits when one of the account's groups owns it, and the other bits
// as the fallback. perm is the permission bits only (fi.Mode().Perm()). It is pure so the
// traversal logic is unit-tested without a real directory.
func serviceCanTraverse(perm os.FileMode, ownerUID, ownerGID, svcUID int, svcGIDs []int, aclExec bool) bool {
	if aclExec {
		return true
	}
	if svcUID == ownerUID {
		return perm&0o100 != 0
	}
	for _, g := range svcGIDs {
		if g == ownerGID {
			return perm&0o010 != 0
		}
	}
	return perm&0o001 != 0
}

// printSetupPlan echoes the resolved plan with the operator's choices before setup
// asks for confirmation.
func printSetupPlan(w io.Writer, plan setupPlan) {
	fmt.Fprint(w, `
------------------------------------------------------------------------------
 Resolved plan
------------------------------------------------------------------------------
`)
	fmt.Fprintf(w, "  Service account : %s (system user, nologin, no home)\n", plan.User)
	fmt.Fprintf(w, "  Binary          : %s (root:root 0755)\n", plan.BinDest)
	fmt.Fprintf(w, "  PATH symlink    : %s -> %s (so \"sopshq\" is on PATH)\n", pathSymlink, plan.BinDest)
	fmt.Fprintf(w, "  Data base       : %s (%s:%s 0700)\n", plan.Data, plan.User, plan.User)
	fmt.Fprintf(w, "    config        : %s (%s:%s 0600)\n", plan.Config, plan.User, plan.User)
	fmt.Fprintf(w, "    data subdir   : %s (%s:%s 0700)\n", plan.DataSubdir, plan.User, plan.User)
	if plan.Keybase != "" {
		fmt.Fprintf(w, "  Keybase root    : %s (%s:%s 0711)\n", plan.Keybase, plan.User, plan.User)
	} else {
		fmt.Fprintln(w, "  Keybase root    : (skipped - keys will live under each user's home)")
	}
	fmt.Fprintf(w, "  systemd unit    : %s (ProtectHome=%s; NOT enabled at boot)\n", plan.UnitDest, plan.ProtectHome)
}

// printFootprint lists every path setup created or modified, plus the optional
// permission-scan account, so the operator has a complete record of what is on the
// machine. It is printed after a successful run. The paths match exactly what
// executeSetup writes (temp files are renamed into place, so none are left behind).
// Removal is not listed here: uninstall.sh at the repository root does it, because the
// order of the steps and the two removals that cannot be undone (the data base and the
// keybase root hold the only copy of the vault and the keys) need a decision at each
// step, and a printed command list cannot ask. It is pure over the plan.
func printFootprint(w io.Writer, plan setupPlan) {
	fmt.Fprint(w, `
------------------------------------------------------------------------------
 Footprint - everything setup created or modified (for a manual uninstall)
------------------------------------------------------------------------------
`)
	fmt.Fprintf(w, "  %s (install prefix: the binary and, after an update, backups/)\n", plan.Prefix)
	fmt.Fprintf(w, "  %s (PATH symlink)\n", pathSymlink)
	fmt.Fprintf(w, "  %s (data base, config, and data/ within)\n", plan.Data)
	if plan.Keybase != "" {
		fmt.Fprintf(w, "  %s (keybase root)\n", plan.Keybase)
	}
	fmt.Fprintf(w, "  %s (systemd unit)\n", plan.UnitDest)
	fmt.Fprintf(w, "  %s (machine location pointer)\n", machinePointerFile)
	fmt.Fprintf(w, "  service account: %s (system user and its same-named group)\n", plan.User)
	fmt.Fprintf(w, "  optional, only if the permission scan was enabled: user %s and %s\n", scanUserDefault, scanSudoersFile)
	fmt.Fprint(w, `
  To remove SopsHQ, run uninstall.sh from the SopsHQ source folder, as root:
    sudo ./uninstall.sh --dry-run    (shows every command, changes nothing)
    sudo ./uninstall.sh
  It asks before each removal. The data base and the keybase root hold the only copy
  of the vault and of plaintext private keys: it offers to move them aside instead.
`)
}
