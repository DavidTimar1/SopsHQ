package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sopshq/internal/unlock"
)

// TestLocateInstall exercises the bare-run install detection via an injected machine
// pointer, without root or a real /etc write. With the machine pointer pointing at a
// scratch data base that holds a config.jsonc, the install is located and reported
// installed - the exact case root hit when a setup install's per-user pointer landed in
// the service account's home. With no machine pointer and an isolated (empty) per-user
// config dir, nothing resolves and it reports not installed.
func TestLocateInstall(t *testing.T) {
	sandboxUserConfigDir(t) // a real per-user pointer on the test host must not leak in
	orig := machinePointerFile
	t.Cleanup(func() { machinePointerFile = orig })

	t.Run("machine pointer -> installed", func(t *testing.T) {
		base := t.TempDir()
		if err := os.WriteFile(filepath.Join(base, "config.jsonc"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		ptr := filepath.Join(t.TempDir(), "location")
		if err := os.WriteFile(ptr, []byte(base+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		machinePointerFile = ptr

		cfgPath, installed := locateInstall()
		if !installed {
			t.Fatalf("locateInstall() installed = false; want true (cfgPath %q)", cfgPath)
		}
		if want := filepath.Join(base, "config.jsonc"); cfgPath != want {
			t.Fatalf("locateInstall() cfgPath = %q; want %q", cfgPath, want)
		}
	})

	t.Run("no pointer -> not installed", func(t *testing.T) {
		machinePointerFile = filepath.Join(t.TempDir(), "absent-location")
		if _, installed := locateInstall(); installed {
			t.Fatalf("locateInstall() installed = true; want false")
		}
	})
}

// TestDeriveState covers the mapping from an unlock-socket status query to the
// dashboard's state string and panel URL.
func TestDeriveState(t *testing.T) {
	tests := []struct {
		name      string
		statusErr error
		locked    bool
		url       string
		wantState string
		wantURL   string
	}{
		{"not running -> stopped", unlock.ErrNotRunning, false, "", "stopped", ""},
		{"other error -> stopped", errors.New("boom"), true, "http://x/", "stopped", ""},
		{"locked", nil, true, "", "running (LOCKED)", ""},
		{"unlocked reports url", nil, false, "http://100.1.2.3:8770/", "running (UNLOCKED)", "http://100.1.2.3:8770/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, url := deriveState(tt.statusErr, tt.locked, tt.url)
			if state != tt.wantState || url != tt.wantURL {
				t.Fatalf("deriveState(%v,%v,%q) = %q,%q; want %q,%q",
					tt.statusErr, tt.locked, tt.url, state, url, tt.wantState, tt.wantURL)
			}
		})
	}
}

// linuxDashboard is a representative installed-machine model for Linux rendering tests.
func linuxDashboard() dashboard {
	return dashboard{
		goos:         "linux",
		euid:         1000,
		svcUser:      "sopshq",
		ownsDataDir:  false,
		bin:          "/opt/sopshq/sopshq",
		configPath:   "/srv/sopshq/config.jsonc",
		dataDir:      "/srv/sopshq/data",
		keybaseRoot:  "",
		unlockSocket: "/run/sopshq/unlock.sock",
		systemdUnit:  systemdUnitPath,
		pidFile:      "/srv/sopshq/data/sopshq.pid",
		logFile:      "/srv/sopshq/data/serve.log",
		state:        "running (UNLOCKED)",
		panelURL:     "http://100.1.2.3:8770/",
	}
}

// TestRenderDashboardLinux asserts the Linux dashboard shows the right state, all
// config-based paths, the sudo-annotated commands, and the PATH help.
func TestRenderDashboardLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("exercises Linux absolute-path semantics; host filepath must be Linux")
	}
	out := renderDashboard(linuxDashboard())

	wantSubstrings := []string{
		"status: running (UNLOCKED)",
		"panel:  http://100.1.2.3:8770/",
		"you are not root (euid 1000)",
		"(per-home; no shared root)", // empty keybase root -> placeholder
		"/run/sopshq/unlock.sock",
		systemdUnitPath,
		"/srv/sopshq/data/sopshq.pid",
		"/srv/sopshq/data/serve.log",
		// Commands, with the exact sudo forms + annotations.
		"sudo -u sopshq /opt/sopshq/sopshq serve -config /srv/sopshq/config.jsonc",
		"sudo -u sopshq sopshq start (needs sudo)",
		"sudo -u sopshq sopshq stop (needs sudo)",
		"sudo systemctl start sopshq (needs sudo; survives reboot)",
		"sudo systemctl stop sopshq (needs sudo)",
		"sudo sopshq unlock (needs sudo)",
		"sudo sopshq status (needs sudo)",
		// PATH help.
		"sudo ln -s /opt/sopshq/sopshq /usr/local/bin/sopshq",
		"export PATH=\"/opt/sopshq:$PATH\"",
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(out, s) {
			t.Errorf("dashboard missing %q\n---\n%s", s, out)
		}
	}
	// tabwriter must expand tabs to spaces (no raw tabs leak into the output).
	if strings.Contains(out, "\t") {
		t.Errorf("dashboard contains a raw tab; tabwriter did not expand columns\n---\n%s", out)
	}
}

// TestDashboardPathsAlign confirms the PATHS block is column-aligned: distinct rows'
// values start at the same column (that is what text/tabwriter guarantees).
func TestDashboardPathsAlign(t *testing.T) {
	out := renderDashboard(linuxDashboard())
	// valueCol finds the PATHS row whose (indented) label matches, then returns the
	// column where its value begins.
	valueCol := func(label, value string) int {
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(strings.TrimLeft(line, " "), label) {
				return strings.Index(line, value)
			}
		}
		return -1
	}
	cfgCol := valueCol("config file", "/srv/sopshq/config.jsonc")
	binCol := valueCol("binary", "/opt/sopshq/sopshq")
	if cfgCol < 0 || binCol < 0 {
		t.Fatalf("could not locate path values (cfgCol=%d binCol=%d)", cfgCol, binCol)
	}
	if cfgCol != binCol {
		t.Errorf("PATHS values not aligned: config value at col %d, binary value at col %d", cfgCol, binCol)
	}
}

// TestRenderDashboardLinuxOwnsData confirms that when this operator already owns the
// data dir, the background commands drop the "sudo -u" prefix and the sudo annotation.
func TestRenderDashboardLinuxOwnsData(t *testing.T) {
	d := linuxDashboard()
	d.ownsDataDir = true
	out := renderDashboard(d)
	for _, s := range []string{"sopshq start", "sopshq stop"} {
		if !strings.Contains(out, s) {
			t.Errorf("expected plain %q command\n---\n%s", s, out)
		}
	}
	if strings.Contains(out, "sudo -u sopshq sopshq start") {
		t.Errorf("owns-data model should not prefix start with sudo -u\n---\n%s", out)
	}
	if strings.Contains(out, "background start  sopshq start (needs sudo)") {
		t.Errorf("owns-data model should not annotate start with (needs sudo)\n---\n%s", out)
	}
}

// TestRenderDashboardWindows confirms the Windows dashboard uses the operator-run
// commands (no sudo, no systemd) and Windows PATH help.
func TestRenderDashboardWindows(t *testing.T) {
	d := dashboard{
		goos:         "windows",
		euid:         -1,
		bin:          `C:\sopshq\sopshq.exe`,
		configPath:   `C:\sopshq\config.jsonc`,
		dataDir:      `C:\sopshq\data`,
		unlockSocket: `\run\sopshq\unlock.sock`,
		pidFile:      `C:\sopshq\data\sopshq.pid`,
		logFile:      `C:\sopshq\data\serve.log`,
		state:        "stopped",
	}
	out := renderDashboard(d)
	wantSubstrings := []string{
		"status: stopped",
		`C:\sopshq\sopshq.exe serve -config C:\sopshq\config.jsonc`,
		"sopshq start",
		"sopshq stop",
		"sopshq unlock",
		"sopshq status",
		"[Environment]::SetEnvironmentVariable('Path'",
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(out, s) {
			t.Errorf("windows dashboard missing %q\n---\n%s", s, out)
		}
	}
	for _, s := range []string{"sudo", "systemctl", "systemd unit"} {
		if strings.Contains(out, s) {
			t.Errorf("windows dashboard should not contain %q\n---\n%s", s, out)
		}
	}
}

// TestFirstRunIntro covers the welcome screen shown just before the interactive menu
// takes over when no install is found, per OS: a plain "never been set up" statement,
// pointing at the menu's "install" item, and - on Windows - the vault-key typing
// warning (no on-screen characters, that the operator needs it themselves on this
// machine every time they unlock, to store it securely, and that setting the same key
// on another machine lets it share these keys too) since Windows install prompts for a
// brand-new vault key inline.
func TestFirstRunIntro(t *testing.T) {
	linux := firstRunIntro("linux")
	for _, s := range []string{
		"SopsHQ has never been set up on this machine.",
		`choose "install"`,
		"re-runs itself under sudo",
	} {
		if !strings.Contains(linux, s) {
			t.Errorf("linux first-run intro missing %q\n---\n%s", s, linux)
		}
	}

	win := firstRunIntro("windows")
	for _, s := range []string{
		"SopsHQ has never been set up on this machine.",
		`choose "install" (option 1)`,
		"install will ask you to type a NEW vault key",
		"nothing will appear on screen",
		"not stuck",
		"unlock SopsHQ on this machine",
		"password manager",
		"set this SAME vault key on that machine too",
	} {
		if !strings.Contains(win, s) {
			t.Errorf("windows first-run intro missing %q\n---\n%s", s, win)
		}
	}
	if strings.Contains(win, "sudo") {
		t.Errorf("windows first-run intro should not mention sudo\n---\n%s", win)
	}
}

// TestPrintPathHelpContent confirms printPathHelp's rows (used once, after a
// first-run "install" succeeds) match the same PATH HELP content the installed
// dashboard shows, per OS.
func TestPrintPathHelpContent(t *testing.T) {
	var b strings.Builder
	writeRows(&b, pathHelpRows("linux", "/opt/sopshq/sopshq"))
	out := b.String()
	if !strings.Contains(out, "sudo ln -s /opt/sopshq/sopshq /usr/local/bin/sopshq") {
		t.Errorf("linux PATH help missing symlink command\n---\n%s", out)
	}

	var wb strings.Builder
	writeRows(&wb, pathHelpRows("windows", `C:\sopshq\sopshq.exe`))
	wout := wb.String()
	if !strings.Contains(wout, "[Environment]::SetEnvironmentVariable('Path'") {
		t.Errorf("windows PATH help missing the user-scope PATH command\n---\n%s", wout)
	}
	if strings.Contains(wout, "setx") {
		t.Errorf("windows PATH help must not suggest setx (it truncates and flattens PATH)\n---\n%s", wout)
	}
}
