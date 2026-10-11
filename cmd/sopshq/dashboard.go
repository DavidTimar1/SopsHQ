package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/tabwriter"

	"sopshq/internal/config"
	"sopshq/internal/unlock"
)

// systemdUnitPath is where `sopshq setup` installs the service unit on Linux. The
// dashboard lists it so the operator can find and edit it.
const systemdUnitPath = "/etc/systemd/system/sopshq.service"

// dashboard is the fully-resolved state the bare-run status dashboard renders. It
// holds only primitive, already-decided values so renderDashboard is pure and
// unit-testable: the impure gathering (config load, socket query, owner lookup)
// happens in cmdDashboard and fills this in.
type dashboard struct {
	goos         string // runtime.GOOS ("linux", "windows", ...)
	euid         int    // effective uid; -1 on platforms without a Unix uid model
	svcUser      string // account that owns the data dir (the service account on Linux)
	ownsDataDir  bool   // this process's user owns the data dir (no sudo needed to start/stop)
	bin          string // absolute path of this binary (os.Executable)
	onPath       bool   // `sopshq` on PATH resolves to this binary (see sopshqOnPath)
	configPath   string // config file
	dataDir      string // cfg.DataDir
	keybaseRoot  string // cfg.KeybaseRoot; empty means per-home key stores
	unlockSocket string // path to the unlock socket
	systemdUnit  string // systemd unit path (Linux); empty elsewhere
	pidFile      string // background-run pid file
	logFile      string // background-run log file
	state        string // "stopped" | "running (LOCKED)" | "running (UNLOCKED)"
	panelURL     string // panel base URL when unlocked; empty otherwise
}

// locateInstall resolves which config.jsonc the bare dashboard should read and reports
// whether an install is actually present there. It reads the machine-wide pointer and
// the per-user pointer (impure), defers precedence to resolveConfigPath (machine pointer,
// then per-user pointer, then the default dir), then stats the resolved config: installed
// is true only when that file exists. This is what lets root find a `sopshq setup`
// install - the machine pointer at /etc/sopshq/location resolves the data base even
// though root's own config dir holds nothing.
func locateInstall() (cfgPath string, installed bool) {
	machineBase, _ := readMachinePointer()
	userBase, _ := readPointer()
	path, _ := resolveConfigPath("", machineBase, userBase, defaultDir())
	_, err := os.Stat(path)
	return path, err == nil
}

// cmdDashboard is the bare, no-argument entry point: it locates the install, queries
// the running state, and prints an aligned status dashboard (state, paths, the exact
// commands to run, and how to put `sopshq` on PATH). When nothing is installed it
// prints how to install and exits cleanly. It never changes anything and never serves.
func cmdDashboard() error {
	bin, err := os.Executable()
	if err != nil || bin == "" {
		bin = "sopshq"
	}
	cfgPath, installed := locateInstall()
	if !installed {
		return cmdFirstRunMenu(runtime.GOOS, bin)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		// The install exists but its config could not be read (commonly a permission
		// error when the config is owned by the sopshq service account). Point the
		// operator at the likely fix rather than dumping a raw error.
		fmt.Printf("Found a SopsHQ config at %s but could not read it:\n  %v\n", cfgPath, err)
		if runtime.GOOS == "linux" {
			fmt.Println("If SopsHQ runs as the 'sopshq' account here, re-run this with sudo: sudo sopshq")
		}
		return nil
	}

	sock := filepath.Join(defaultRuntimeDir(), unlockSocketName)
	rep, statErr := unlock.Status(sock)
	state, panelURL := deriveState(statErr, rep.Locked, rep.URL)

	d := dashboard{
		goos:         runtime.GOOS,
		euid:         os.Geteuid(),
		svcUser:      setupUserDefault,
		ownsDataDir:  true,
		bin:          bin,
		onPath:       sopshqOnPath(bin),
		configPath:   cfgPath,
		dataDir:      cfg.DataDir,
		keybaseRoot:  cfg.KeybaseRoot,
		unlockSocket: sock,
		pidFile:      filepath.Join(cfg.DataDir, pidFileName),
		logFile:      filepath.Join(cfg.DataDir, logFileName),
		state:        state,
		panelURL:     panelURL,
	}
	// On a Unix host, resolve the data dir's owning account: that is the service
	// account the foreground/background commands must run as, and whether this
	// operator already owns it decides if those commands need sudo.
	if uid, ok := dirOwnerUID(cfg.DataDir); ok {
		if u, uerr := user.LookupId(strconv.Itoa(uid)); uerr == nil && u.Username != "" {
			d.svcUser = u.Username
		}
		d.ownsDataDir = uid == os.Getuid()
	}
	if runtime.GOOS == "linux" {
		d.systemdUnit = systemdUnitPath
	}
	fmt.Print(renderDashboard(d))
	return nil
}

// deriveState maps an unlock-socket status query into the dashboard's state string and
// panel URL. Any status error (including "not running") means the service is stopped;
// otherwise the reply's locked flag distinguishes locked from unlocked, and an unlocked
// service reports its panel URL.
func deriveState(statusErr error, locked bool, url string) (state, panelURL string) {
	switch {
	case statusErr != nil:
		return "stopped", ""
	case locked:
		return "running (LOCKED)", ""
	default:
		return "running (UNLOCKED)", url
	}
}

// renderDashboard produces the aligned, ASCII status dashboard for an installed
// machine. It is pure: every input comes from d, so it can be exercised directly in a
// test. Columns are aligned with text/tabwriter; commands that need root are shown in
// their sudo form and annotated so a non-root operator sees the requirement at a glance.
func renderDashboard(d dashboard) string {
	var b strings.Builder
	title := "SopsHQ " + strings.TrimSpace(version) + " - this machine"
	fmt.Fprintf(&b, "%s\n%s\n\n", title, strings.Repeat("=", len(title)))

	fmt.Fprintln(&b, "STATE")
	fmt.Fprintf(&b, "  status: %s\n", d.state)
	if d.panelURL != "" {
		fmt.Fprintf(&b, "  panel:  %s\n", d.panelURL)
	}
	if d.goos == "linux" && d.euid > 0 {
		fmt.Fprintf(&b, "  you are not root (euid %d); commands marked \"(needs sudo)\" require sudo.\n", d.euid)
	}
	fmt.Fprintln(&b)

	fmt.Fprintln(&b, "PATHS")
	paths := [][2]string{
		{"config file", d.configPath},
		{"data dir", d.dataDir},
		{"keybase root", orPlaceholder(d.keybaseRoot, "(per-home; no shared root)")},
	}
	paths = append(paths,
		[2]string{"binary", d.bin},
		[2]string{"unlock socket", d.unlockSocket},
	)
	if d.systemdUnit != "" {
		paths = append(paths, [2]string{"systemd unit", d.systemdUnit})
	}
	paths = append(paths,
		[2]string{"PID file", d.pidFile},
		[2]string{"log file", d.logFile},
	)
	writeRows(&b, paths)
	fmt.Fprintln(&b)

	fmt.Fprintln(&b, "COMMANDS")
	writeRows(&b, commandRows(d))
	fmt.Fprintln(&b)

	if !d.onPath {
		fmt.Fprintln(&b, "PATH HELP (call `sopshq` from anywhere)")
		writeRows(&b, pathHelpRows(d.goos, d.bin))
		if d.goos == "linux" {
			fmt.Fprintln(&b, "  note: `sopshq setup` already creates the /usr/local/bin symlink on Linux.")
		}
	}
	return b.String()
}

// commandRows builds the COMMANDS block: the exact invocation for each way to run,
// unlock, and check SopsHQ, with sudo annotations. On Linux the long-running service
// runs as the data dir's owning account, so foreground/background commands use
// "sudo -u <svcUser>"; the managed (systemd) option is Linux-only.
func commandRows(d dashboard) [][2]string {
	serveBin := d.bin
	if d.onPath {
		serveBin = "sopshq"
	}
	if d.goos != "linux" {
		return [][2]string{
			{"foreground", fmt.Sprintf("%s serve -config %s", serveBin, d.configPath)},
			{"background start", "sopshq start"},
			{"background stop", "sopshq stop"},
			{"unlock", "sopshq unlock"},
			{"status", "sopshq status"},
		}
	}
	start := fmt.Sprintf("sudo -u %s sopshq start", d.svcUser)
	stop := fmt.Sprintf("sudo -u %s sopshq stop", d.svcUser)
	startAnn, stopAnn := " (needs sudo)", " (needs sudo)"
	if d.ownsDataDir {
		start, stop = "sopshq start", "sopshq stop"
		startAnn, stopAnn = "", ""
	}
	return [][2]string{
		{"foreground", fmt.Sprintf("sudo -u %s %s serve -config %s", d.svcUser, serveBin, d.configPath)},
		{"background start", start + startAnn},
		{"background stop", stop + stopAnn},
		{"managed start", "sudo systemctl start sopshq (needs sudo; survives reboot)"},
		{"managed stop", "sudo systemctl stop sopshq (needs sudo)"},
		{"unlock", "sudo sopshq unlock (needs sudo)"},
		{"status", "sudo sopshq status (needs sudo)"},
	}
}

// pathHelpRows explains how to make the `sopshq` command resolve from any directory:
// on Unix a symlink into /usr/local/bin (on PATH and sudo's secure_path) plus a
// shell-rc PATH line; on Windows a PATH update for the binary's folder.
func pathHelpRows(goos, bin string) [][2]string {
	dir := filepath.Dir(bin)
	if goos == "windows" {
		cmd := fmt.Sprintf("powershell -Command \"[Environment]::SetEnvironmentVariable('Path', [Environment]::GetEnvironmentVariable('Path','User') + ';%s', 'User')\"", dir)
		return [][2]string{
			{"add to PATH", cmd},
		}
	}
	return [][2]string{
		{"symlink", fmt.Sprintf("sudo ln -s %s /usr/local/bin/sopshq", bin)},
		{"shell rc", fmt.Sprintf("echo 'export PATH=\"%s:$PATH\"' >> ~/.bashrc && source ~/.bashrc", dir)},
	}
}

// cmdFirstRunMenu is the bare-run entry point when no install is found on this
// machine (e.g. a Windows double-click, or `sopshq` with no arguments, on a machine
// that has never been set up). It prints firstRunIntro - the zero-CLI-experience
// welcome - then hands off into the SAME
// interactive menu `sopshq menu` shows, so a first-time operator is guided by numbered
// prompts (starting with "install") instead of being told to type another command
// themselves. Once "install" succeeds, the menu loop prints the PATH help once (see
// runMenuLoop), so the operator can call `sopshq` from anywhere afterward.
func cmdFirstRunMenu(goos, bin string) error {
	fmt.Print(firstRunIntro(goos))
	fmt.Println()
	return runMenuLoop(true, goos, bin)
}

// firstRunIntro is the welcome screen shown once, immediately before the interactive
// menu takes over, when no install is found. It assumes zero command-line experience:
// it states plainly that SopsHQ has never been set up here, then explains what
// choosing "install" from the menu below will do - on Linux, that it re-execs itself
// under sudo when not already root; on Windows, that it will ask for a NEW vault key,
// that nothing appears on screen while typing it (no dots, no characters - that is
// normal, not a stuck keyboard), that the operator needs this SAME vault key themselves
// every time they unlock SopsHQ on this machine (so store it securely, e.g. in a
// password manager), and that setting this SAME vault key on any additional machine
// lets that machine share and manage these same keys too.
func firstRunIntro(goos string) string {
	var b strings.Builder
	fmt.Fprintln(&b, "SopsHQ has never been set up on this machine.")
	fmt.Fprintln(&b)
	if goos == "linux" {
		fmt.Fprintln(&b, "The menu below can set it up: choose \"install\". If you are not already root,")
		fmt.Fprintln(&b, "it re-runs itself under sudo for you (you may be asked for your sudo password).")
	} else {
		fmt.Fprintln(&b, "The menu below can set it up: choose \"install\" (option 1).")
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "Before you do: install will ask you to type a NEW vault key. As you type it,")
		fmt.Fprintln(&b, "nothing will appear on screen - no dots, no characters. That is normal and")
		fmt.Fprintln(&b, "expected; your keyboard is not stuck. Just type the vault key and press Enter.")
		fmt.Fprintln(&b, "Remember this vault key: you will need to type it again yourself every time")
		fmt.Fprintln(&b, "you unlock SopsHQ on this machine (serve/unlock) - it is not only for sharing.")
		fmt.Fprintln(&b, "Store it somewhere safe, like a password manager (e.g. KeePass): forgetting it")
		fmt.Fprintln(&b, "locks you out of your own vault. If you ever want another machine to share and")
		fmt.Fprintln(&b, "manage these same keys, set this SAME vault key on that machine too.")
	}
	return b.String()
}

// orPlaceholder returns s, or placeholder when s is empty, so a blank optional path
// reads as a clear "(none)" note instead of an empty column.
func orPlaceholder(s, placeholder string) string {
	if s == "" {
		return placeholder
	}
	return s
}

// writeRows renders label/value pairs as two aligned, space-padded columns (each row
// indented two spaces) using text/tabwriter, so every value starts at the same column.
func writeRows(b *strings.Builder, rows [][2]string) {
	tw := tabwriter.NewWriter(b, 0, 2, 2, ' ', 0)
	for _, r := range rows {
		fmt.Fprintf(tw, "  %s\t%s\n", r[0], r[1])
	}
	_ = tw.Flush()
}
