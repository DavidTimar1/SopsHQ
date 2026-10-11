package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"sopshq/internal/backup"
	"sopshq/internal/config"
)

// menuEntry is one numbered line in the interactive menu: what it is called, the
// subcommand it drives, and the function that gathers its inputs (via the shared
// prompt helpers) and returns the argv to run.
//
// A destructive entry's own prompt function gathers and validates its inputs FIRST,
// then asks its own specific y/N confirmation built from those inputs (returning
// errMenuCancelled on a decline) - there is no separate generic confirmation step in
// runMenuEntry. This ordering avoids asking the operator to confirm an action before
// the menu even knows whether it has valid inputs to run it with.
type menuEntry struct {
	number     int
	label      string
	subcommand string
	prompt     func() ([]string, error) // returns the subcommand's flag argv (not including the subcommand name)
}

// menuEntries lists every capability the menu drives, in display order. It is built
// fresh on each call so its prompt closures always read the current package vars
// (promptSecret, stdin) rather than capturing stale ones.
func menuEntries() []menuEntry {
	return []menuEntry{
		{1, "install - set up SopsHQ on this machine", "install", promptMenuInstall},
		{2, "export - encrypted backup", "export", promptMenuExport},
		{3, "restore - unpack an encrypted backup", "restore", promptMenuRestore},
		{4, "reset-2fa - clear a panel login's two-factor", "reset-2fa", promptMenuReset2FA},
		{5, "reset-admin - reset a panel login's password + two-factor", "reset-admin", promptMenuResetAdmin},
		{6, "serve - run in the foreground", "serve", promptMenuServe},
		{7, "start - run detached in the background", "start", promptMenuStart},
		{8, "stop - stop the background run", "stop", promptMenuStop},
		{9, "unlock - open the locked vault before it can be used to manage keys", "unlock", promptMenuUnlock},
		{10, "status - show locked/unlocked state", "status", promptMenuStatus},
		{11, "install-launcher - register the Windows Startup launcher", "install-launcher", promptMenuInstallLauncher},
		{12, "uninstall-launcher - remove the Windows Startup launcher", "uninstall-launcher", promptMenuUninstallLauncher},
	}
}

// menuDispatch maps a subcommand name to the in-process function that runs it. Every
// entry is the SAME function the flag-driven CLI calls (cmd/sopshq/main.go's run()
// switch) - the menu builds argv and calls it, rather than re-implementing any
// subcommand's logic.
var menuDispatch = map[string]func([]string) error{
	"install":            cmdInstall,
	"export":             cmdExport,
	"restore":            cmdRestore,
	"reset-2fa":          cmdResetTOTP,
	"reset-admin":        cmdResetAdmin,
	"serve":              cmdServe,
	"start":              cmdStart,
	"stop":               cmdStop,
	"unlock":             cmdUnlock,
	"status":             cmdStatus,
	"install-launcher":   cmdInstallLauncher,
	"uninstall-launcher": cmdUninstallLauncher,
}

// cmdMenu is the `sopshq menu` subcommand: the full interactive terminal menu with no
// first-run welcome and no automatic PATH-help print, since an operator who already
// typed `sopshq menu` has SopsHQ on PATH.
func cmdMenu(args []string) error {
	return runMenuLoop(false, "", "")
}

// runMenuLoop is the interactive menu's loop: it lists every capability by number,
// reads a choice, gathers that item's own inputs via prompts (never flags) - with a
// destructive item asking its own specific y/N confirmation only once those inputs are
// gathered and validated - and runs it. It loops until the operator quits. Every
// vault-key or new-secret prompt happens INSIDE the subcommand it calls (readVaultKey /
// readNewVaultKey / promptSecret), at the point of use - the menu itself never collects
// or reuses one across selections.
//
// firstRun marks the not-installed bare-run case (see cmdFirstRunMenu): the first time
// "install" succeeds in that case, the loop prints the PATH help once (goos/bin resolve
// pathHelpRows), so a first-time operator learns how to call `sopshq` from anywhere
// right after setting it up, without that advice cluttering every later `sopshq menu`
// session or repeating on every menu item.
func runMenuLoop(firstRun bool, goos, bin string) error {
	entries := menuEntries()
	printedPathHelp := false
	for {
		printMenu(entries)
		choice, err := promptLine("Choice (blank to quit): ")
		if err != nil {
			return err
		}
		choice = strings.TrimSpace(choice)
		if choice == "" || strings.EqualFold(choice, "q") || strings.EqualFold(choice, "quit") {
			return nil
		}
		n, err := strconv.Atoi(choice)
		if err != nil {
			fmt.Println("Not a number; try again.")
			continue
		}
		entry, ok := findMenuEntry(entries, n)
		if !ok {
			fmt.Println("No such item; try again.")
			continue
		}
		runErr := runMenuEntry(entry)
		if runErr != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", entry.subcommand, runErr)
		} else if !printedPathHelp && entry.subcommand == "install" {
			printedPathHelp = true
			offerOrPrintPathHelp(firstRun, goos, bin)
		}
		fmt.Println()
	}
}

// offerOrPrintPathHelp follows a successful menu "install". When `sopshq` already
// resolves through PATH to this same binary there is nothing to add, so it prints
// nothing. Otherwise, on Windows it asks whether to add the binary's folder to the
// operator's user PATH and performs the addition on a yes (falling back to the
// printed manual advice on a no or a failure); on other systems it prints the manual
// PATH help, on the first run only - `sopshq setup` on Linux already places the
// /usr/local/bin symlink, so repeat menu sessions need no reminder.
//
// goos/bin default to this process (runtime.GOOS / os.Executable) when the caller
// passed them blank - `sopshq menu` does, since only the first-run entry point
// resolves them itself.
func offerOrPrintPathHelp(firstRun bool, goos, bin string) {
	if goos == "" {
		goos = runtime.GOOS
	}
	if bin == "" {
		exe, err := os.Executable()
		if err != nil {
			return
		}
		bin = exe
	}
	if sopshqOnPath(bin) {
		return
	}
	fmt.Println()
	if goos != "windows" {
		if firstRun {
			printPathHelp(goos, bin)
		}
		return
	}
	dir := filepath.Dir(bin)
	ok, err := confirmYN(fmt.Sprintf("Add %s to your PATH so `sopshq` works from any new terminal? [y/N]: ", dir))
	if err != nil || !ok {
		printPathHelp(goos, bin)
		return
	}
	if err := addUserPath(dir); err != nil {
		fmt.Fprintf(os.Stderr, "could not update the user PATH: %v\n", err)
		printPathHelp(goos, bin)
		return
	}
	fmt.Printf("[ok] %s added to your user PATH - open a NEW terminal to call `sopshq` from anywhere.\n", dir)
}

// printPathHelp prints the "call `sopshq` from anywhere" block for goos/bin, the same
// content the installed dashboard shows in its own PATH HELP section.
func printPathHelp(goos, bin string) {
	fmt.Println("PATH HELP (call `sopshq` from anywhere)")
	var b strings.Builder
	writeRows(&b, pathHelpRows(goos, bin))
	fmt.Print(b.String())
	if goos == "linux" {
		fmt.Println("  note: `sopshq setup` already creates the /usr/local/bin symlink on Linux.")
	}
}

// printMenu renders the numbered list of capabilities.
func printMenu(entries []menuEntry) {
	title := "SopsHQ " + strings.TrimSpace(version) + " - interactive menu"
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", len(title)))
	for _, e := range entries {
		fmt.Printf("  %2d) %s\n", e.number, e.label)
	}
}

// findMenuEntry returns the entry with the given display number.
func findMenuEntry(entries []menuEntry, n int) (menuEntry, bool) {
	for _, e := range entries {
		if e.number == n {
			return e, true
		}
	}
	return menuEntry{}, false
}

// runMenuEntry gathers the chosen entry's inputs - a destructive entry's own prompt
// function asks its own specific y/N confirmation internally, only after its inputs are
// gathered and validated (see menuEntry.destructive and errMenuCancelled) - and runs it,
// elevated under sudo when the subcommand needs root on this OS and the process is not
// already root. Linux `install` needs no special-casing here: it dispatches to
// cmdSetup, which prints its own plan and asks its own y/N confirmation, and it is not
// marked destructive in menuEntries(), so nothing here confirms it a second time.
//
// A blank answer to a required field (see promptRequiredLine) is handled the same way
// as a declined confirmation: the entry is abandoned and the menu prints a plain
// message, rather than re-asking the same question or letting the entry continue on
// to any later prompt with a field it still needs.
func runMenuEntry(e menuEntry) error {
	argv, err := e.prompt()
	if errors.Is(err, errMenuCancelled) {
		fmt.Println("Cancelled.")
		return nil
	}
	var missing *menuRequiredMissingError
	if errors.As(err, &missing) {
		fmt.Printf("%s - returning to the menu.\n", missing.Error())
		return nil
	}
	if err != nil {
		return err
	}
	return runMenuSubcommand(e.subcommand, argv)
}

// runMenuSubcommand runs subcommand with argv: elevated under sudo when
// menuNeedsElevation says this OS/euid/subcommand combination needs it, otherwise
// in-process via menuDispatch - the SAME function the flag-driven CLI uses.
func runMenuSubcommand(subcommand string, argv []string) error {
	if menuNeedsElevation(runtime.GOOS, os.Geteuid(), subcommand) {
		bin, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate this binary: %w", err)
		}
		return runElevated(bin, append([]string{subcommand}, argv...))
	}
	fn, ok := menuDispatch[subcommand]
	if !ok {
		return fmt.Errorf("menu: unknown subcommand %q", subcommand)
	}
	return fn(argv)
}

// menuNeedsElevation reports whether running subcommand from the menu, on this
// OS/euid combination, must be spawned under sudo rather than called in-process. Only
// Linux `install` needs it: it dispatches to cmdSetup, which requires real root
// (cmdSetup's own root check still fires inside the sudo'd child - harmlessly true - as
// defense in depth; this decision never bypasses it). Every other menu item runs as the
// invoking user, exactly like typing its flags by hand - none of them require root.
func menuNeedsElevation(goos string, euid int, subcommand string) bool {
	return goos == "linux" && subcommand == "install" && euid != 0
}

// nopCloser is a no-op io.Closer, used when forwardStdinToChild has nothing to close
// (the direct os.Stdin passthrough case).
type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// forwardStdinToChild wires cmd's stdin so the elevated child sees every byte the
// operator types, in order - including any the menu already pulled into the shared
// bufio.Reader (the package var `stdin`) before deciding to elevate.
//
// Why this matters: bufio.Reader reads ahead from the OS in chunks. Once a byte has
// been delivered into that internal buffer, it is GONE from the OS-level console/pipe -
// os.Stdin will never yield it again. So if the menu's own prompts (choosing the item,
// answering a confirm) left anything buffered beyond what was consumed, wiring the
// child straight to raw os.Stdin would silently skip those bytes and the child's first
// prompt (a path, or the vault key) would hang waiting for input that already arrived.
//
// The common interactive case has nothing buffered (a real terminal delivers exactly
// one typed line per read), so the fast path just hands the child raw os.Stdin - the
// same direct-fd pattern the existing setup handoff (buildInitHandoff) uses, with no
// copy goroutine and so no risk of anything outliving the child. Only when bytes ARE
// already buffered (piped/scripted input, or an operator who typed ahead) does this
// drain them into the child's stdin pipe first, then relay whatever follows on raw
// os.Stdin. The relay goroutine is not explicitly joined: io.Copy blocks on os.Stdin,
// which offers no cancellation, but that is harmless here - once the elevated command
// exits, this function's caller (runElevated) has already returned, and the menu's next
// read is a fresh prompt the operator has not started answering yet.
func forwardStdinToChild(cmd *exec.Cmd) (io.Closer, error) {
	if stdin.Buffered() == 0 {
		cmd.Stdin = os.Stdin
		return nopCloser{}, nil
	}
	w, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	n := stdin.Buffered()
	peeked, _ := stdin.Peek(n)
	buffered := append([]byte(nil), peeked...) // copy out: Discard invalidates the peeked slice
	if _, err := stdin.Discard(n); err != nil {
		return nil, err
	}
	go func() {
		defer w.Close()
		if _, err := w.Write(buffered); err != nil {
			return
		}
		_, _ = io.Copy(w, os.Stdin)
	}()
	return w, nil
}

// runElevated re-execs this same binary under `sudo` with the given subcommand argv,
// forwarding stdin correctly (forwardStdinToChild) and passing stdout/stderr straight
// through, then waits for it to finish. It is used only when menuNeedsElevation says
// the chosen subcommand needs root and the current process is not already root.
func runElevated(bin string, argv []string) error {
	if _, err := exec.LookPath("sudo"); err != nil {
		return errors.New("this needs root and `sudo` was not found on PATH; re-run as root instead")
	}
	cmd := exec.Command("sudo", append([]string{bin}, argv...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	closer, err := forwardStdinToChild(cmd)
	if err != nil {
		return err
	}
	defer closer.Close()
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Wait()
}

// promptOptional prompts for a value, showing deflt as the shown default; a blank
// answer keeps deflt. It uses the shared promptLine helper (the package-level `stdin`
// reader), so it composes correctly with every other prompt in the menu and with a
// later handoff to an elevated child.
func promptOptional(label, deflt string) (string, error) {
	shown := deflt
	if shown == "" {
		shown = "(blank)"
	}
	in, err := promptLine(fmt.Sprintf("%s [%s]: ", label, shown))
	if err != nil {
		return "", err
	}
	if in = strings.TrimSpace(in); in != "" {
		return in, nil
	}
	return deflt, nil
}

// menuRequiredMissingError reports that a required menu prompt (one with no sensible
// default - see promptRequiredLine) was answered with a blank line, naming the field
// that was left blank. runMenuEntry recognizes it (via errors.As) and aborts the whole
// menu entry straight back to the main menu instead of re-asking the same question or
// continuing on to any later prompt in that entry.
type menuRequiredMissingError struct {
	field string
}

func (e *menuRequiredMissingError) Error() string {
	return fmt.Sprintf("a value is required for %s", e.field)
}

// promptRequiredLine asks for field once and reports whether the answer was blank: a
// non-blank answer is returned as-is; a blank one is rejected immediately by returning
// a *menuRequiredMissingError instead of re-asking the same question. There is no
// retry loop here on purpose - a field with no sensible default (an output path, a
// username, an archive to restore from) is worth abandoning the current menu
// selection over, not worth looping on, so the caller propagates this error up to
// runMenuEntry, which prints a plain message and returns straight to the main menu.
func promptRequiredLine(field string) (string, error) {
	ans, err := promptLine(field + ": ")
	if err != nil {
		return "", err
	}
	if ans = strings.TrimSpace(ans); ans != "" {
		return ans, nil
	}
	return "", &menuRequiredMissingError{field: field}
}

// errMenuCancelled signals that the operator declined a destructive menu item's own
// specific confirmation. runMenuEntry recognizes it and prints a plain "Cancelled."
// instead of reporting it as a failure.
var errMenuCancelled = errors.New("cancelled")

// confirmYN prompts once and reports whether the answer was y/yes (case-insensitive);
// anything else, including a blank answer, is "no".
func confirmYN(prompt string) (bool, error) {
	ans, err := promptLine(prompt)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(ans)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// menuConfigDefault returns the path shown as the "Config file path" prompt's
// default: the auto-discovered config location when a config file actually exists
// there, and "" (the prompt shows "(blank)") when it does not - a default the
// operator accepts with Enter must never point at a file that is not there.
func menuConfigDefault() string {
	p := discoverConfigPath()
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// requireLoadableConfig verifies a real, loadable SopsHQ config exists at
// resolvedPath, returning a plain-language error naming "install" (menu item 1) as
// the fix when it does not. An empty resolvedPath means no config was answered and
// none was found on this machine (see menuConfigDefault). action names what the
// operator was about to do (e.g. "exporting"), so the message reads naturally in
// context.
//
// Every menu prompt whose underlying subcommand's first real action is loading a
// config that must already exist calls this right after the config-path prompt is
// answered, before asking anything further - so a missing config aborts the chosen
// item straight back to the main menu (runMenuEntry reports the returned error and
// the menu is printed again) instead of only surfacing once every other answer has
// already been collected.
func requireLoadableConfig(resolvedPath, action string) error {
	if resolvedPath == "" {
		return fmt.Errorf("no SopsHQ config found on this machine - install SopsHQ on this machine first (menu item 1) before %s", action)
	}
	if _, err := config.Load(resolvedPath); err != nil {
		if errors.Is(err, config.ErrNotFound) {
			return fmt.Errorf("no SopsHQ config found at %s - install SopsHQ on this machine first (menu item 1) before %s", resolvedPath, action)
		}
		return fmt.Errorf("config at %s could not be loaded: %w", resolvedPath, err)
	}
	return nil
}

// --- per-item argv builders (pure) and prompt gatherers (impure: read via promptLine/promptOptional/confirmYN) ---

// buildWindowsInstallArgv builds `install`'s Windows argv from resolved answers. It is
// pure so the flag-shape is unit-tested without a terminal.
func buildWindowsInstallArgv(dir, configPath, name string, setDefault bool, keysDir string) []string {
	var argv []string
	if dir != "" {
		argv = append(argv, "-dir", dir)
	}
	if configPath != "" {
		argv = append(argv, "-config", configPath)
	}
	if name != "" {
		argv = append(argv, "-name", name)
	}
	if setDefault {
		argv = append(argv, "-set-default")
	}
	if keysDir != "" {
		argv = append(argv, "-keys", keysDir)
	}
	return argv
}

// buildConfigOnlyArgv builds the argv for a subcommand whose only input is -config
// (serve, start, stop). Pure.
func buildConfigOnlyArgv(configPath string) []string {
	if configPath == "" {
		return nil
	}
	return []string{"-config", configPath}
}

// buildExportArgv builds export's argv. Pure.
func buildExportArgv(configPath, out string) []string {
	var argv []string
	if configPath != "" {
		argv = append(argv, "-config", configPath)
	}
	argv = append(argv, "-out", out)
	return argv
}

// buildRestoreArgv builds restore's argv. Pure.
func buildRestoreArgv(in, dir string) []string {
	return []string{"-in", in, "-dir", dir}
}

// buildUserConfigArgv builds the argv for a subcommand needing -user and optionally
// -config (reset-2fa, reset-admin). Pure.
func buildUserConfigArgv(configPath, user string) []string {
	argv := []string{"-user", user}
	if configPath != "" {
		argv = append(argv, "-config", configPath)
	}
	return argv
}

// buildUnlockArgv builds unlock's argv. Pure.
func buildUnlockArgv(runtimeDir, configPath string) []string {
	var argv []string
	if runtimeDir != "" {
		argv = append(argv, "-runtime-dir", runtimeDir)
	}
	if configPath != "" {
		argv = append(argv, "-config", configPath)
	}
	return argv
}

// buildStatusArgv builds status's argv. Pure.
func buildStatusArgv(runtimeDir string) []string {
	if runtimeDir == "" {
		return nil
	}
	return []string{"-runtime-dir", runtimeDir}
}

func promptMenuInstall() ([]string, error) {
	if runtime.GOOS != "linux" {
		dir, err := promptOptional("Base directory for config and data", defaultDir())
		if err != nil {
			return nil, err
		}
		cfgPath, err := promptOptional("Config file path", filepath.Join(dir, "config.jsonc"))
		if err != nil {
			return nil, err
		}
		host, _ := os.Hostname()
		name, err := promptOptional("Node name (this machine's label in the panel)", host)
		if err != nil {
			return nil, err
		}
		setDefault, err := confirmYN("Make this the install that `sopshq` opens when run without -config, replacing any current default? [y/N]: ")
		if err != nil {
			return nil, err
		}
		keysDir, err := promptOptional("Keys root folder (blank = keys stay in each OS user's home key store)", "")
		if err != nil {
			return nil, err
		}
		return buildWindowsInstallArgv(dir, cfgPath, name, setDefault, keysDir), nil
	}
	// Linux: pass NO flags. cmdSetup prints its own plan, prompts for each path itself
	// (when interactive), and asks its own y/N confirmation - reproducing that here
	// would prompt the operator twice for the same thing.
	return nil, nil
}

func promptMenuExport() ([]string, error) {
	cfgPath, err := promptOptional("Config file path", menuConfigDefault())
	if err != nil {
		return nil, err
	}
	if err := requireLoadableConfig(cfgPath, "exporting"); err != nil {
		return nil, err
	}
	out, err := promptRequiredLine("Output archive path")
	if err != nil {
		return nil, err
	}
	return buildExportArgv(cfgPath, out), nil
}

// promptMenuRestore collects both restore inputs (aborting straight back to the menu
// on a blank answer for either, rather than only failing at execution time), then -
// when the answered destination directory already exists and holds something - asks
// its own specific confirmation naming that directory and stating plainly that
// matching files inside it will be overwritten. When the destination is empty there is
// nothing to lose, so restore proceeds with no confirmation at all, using the same
// backup.DestDirNotEmpty check backup.Restore itself enforces.
func promptMenuRestore() ([]string, error) {
	in, err := promptRequiredLine("Backup archive path")
	if err != nil {
		return nil, err
	}
	dir, err := promptRequiredLine("Destination directory (must be empty)")
	if err != nil {
		return nil, err
	}
	notEmpty, err := backup.DestDirNotEmpty(dir)
	if err != nil {
		return nil, err
	}
	if notEmpty {
		ok, err := confirmYN(fmt.Sprintf(
			"This will overwrite any existing files in %s with the same names as those in the archive. Are you sure? [y/N]: ",
			dir))
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errMenuCancelled
		}
	}
	return buildRestoreArgv(in, dir), nil
}

func promptMenuReset2FA() ([]string, error) {
	cfgPath, err := promptOptional("Config file path", menuConfigDefault())
	if err != nil {
		return nil, err
	}
	if err := requireLoadableConfig(cfgPath, "resetting two-factor"); err != nil {
		return nil, err
	}
	user, err := promptRequiredLine("Panel username")
	if err != nil {
		return nil, err
	}
	return buildUserConfigArgv(cfgPath, user), nil
}

// promptMenuResetAdmin gathers reset-admin's inputs first - a loadable config and a
// non-blank username - and only once both are in hand does it ask its own specific y/N
// confirmation naming the exact user and config it is about to reset, rather than a
// generic "run reset-admin?" asked before the menu even knows whether it has a valid
// user to act on.
func promptMenuResetAdmin() ([]string, error) {
	cfgPath, err := promptOptional("Config file path", menuConfigDefault())
	if err != nil {
		return nil, err
	}
	if err := requireLoadableConfig(cfgPath, "resetting the admin login"); err != nil {
		return nil, err
	}
	user, err := promptRequiredLine("Panel username")
	if err != nil {
		return nil, err
	}
	ok, err := confirmYN(fmt.Sprintf("Reset the admin login for user %q (config: %s)? [y/N]: ", user, cfgPath))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errMenuCancelled
	}
	return buildUserConfigArgv(cfgPath, user), nil
}

func promptMenuServe() ([]string, error) {
	cfgPath, err := promptOptional("Config file path", menuConfigDefault())
	if err != nil {
		return nil, err
	}
	if err := requireLoadableConfig(cfgPath, "serving"); err != nil {
		return nil, err
	}
	return buildConfigOnlyArgv(cfgPath), nil
}

func promptMenuStart() ([]string, error) {
	cfgPath, err := promptOptional("Config file path", menuConfigDefault())
	if err != nil {
		return nil, err
	}
	if err := requireLoadableConfig(cfgPath, "starting"); err != nil {
		return nil, err
	}
	return buildConfigOnlyArgv(cfgPath), nil
}

func promptMenuStop() ([]string, error) {
	cfgPath, err := promptOptional("Config file path", menuConfigDefault())
	if err != nil {
		return nil, err
	}
	if err := requireLoadableConfig(cfgPath, "stopping"); err != nil {
		return nil, err
	}
	return buildConfigOnlyArgv(cfgPath), nil
}

func promptMenuUnlock() ([]string, error) {
	runtimeDir, err := promptOptional("Runtime directory (unlock socket)", defaultRuntimeDir())
	if err != nil {
		return nil, err
	}
	cfgPath, err := promptOptional("Config file path", menuConfigDefault())
	if err != nil {
		return nil, err
	}
	return buildUnlockArgv(runtimeDir, cfgPath), nil
}

func promptMenuStatus() ([]string, error) {
	runtimeDir, err := promptOptional("Runtime directory (unlock socket)", defaultRuntimeDir())
	if err != nil {
		return nil, err
	}
	return buildStatusArgv(runtimeDir), nil
}

func promptMenuInstallLauncher() ([]string, error) {
	cfgPath, err := promptOptional("Config file path", menuConfigDefault())
	if err != nil {
		return nil, err
	}
	return buildConfigOnlyArgv(cfgPath), nil
}

// promptMenuUninstallLauncher has no inputs to gather, so it goes straight to its own
// specific confirmation naming the exact script it will remove.
func promptMenuUninstallLauncher() ([]string, error) {
	ok, err := confirmYN(fmt.Sprintf("Remove the Windows Startup launcher (%s) for this user? [y/N]: ", launcherScriptName))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errMenuCancelled
	}
	return nil, nil
}
