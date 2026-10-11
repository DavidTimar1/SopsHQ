package main

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"sopshq/internal/config"
)

// scriptStdin points the shared `stdin` reader (the one every menu prompt reads
// through) at a scripted sequence of answer lines, restoring the original reader via
// t.Cleanup - so a test can drive promptLine/promptOptional exactly as an operator's
// keystrokes would, without a real terminal.
func scriptStdin(t *testing.T, lines ...string) {
	t.Helper()
	orig := stdin
	stdin = bufio.NewReader(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	t.Cleanup(func() { stdin = orig })
}

// writeValidConfig scaffolds a minimal, loadable config.jsonc under dir (via the same
// config.Default + Save the real `init` subcommand uses) and returns its path.
func writeValidConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "config.jsonc")
	cfg := config.Default(path, dir, "test-node")
	if err := cfg.Save(); err != nil {
		t.Fatalf("save config: %v", err)
	}
	return path
}

// requireMissingConfigAbort asserts that a prompt function's result is the
// abort-to-menu shape for a missing config: a nil argv and an error whose message
// points the operator at "install" (menu item 1). Each caller supplies only the
// config-path answer on stdin, so if the code incorrectly fell through to a later
// prompt, promptLine would hit EOF and return a generic "read input" error instead
// of this one - asserting on the message proves no later prompt ever ran.
func requireMissingConfigAbort(t *testing.T, argv []string, err error) {
	t.Helper()
	if argv != nil {
		t.Fatalf("argv = %#v, want nil when no config exists at the answered path", argv)
	}
	if err == nil {
		t.Fatalf("expected an error when no config exists at the answered path, got nil")
	}
	if !strings.Contains(err.Error(), "install SopsHQ on this machine first (menu item 1)") {
		t.Fatalf("error %q does not point at install; a later prompt may have run instead", err.Error())
	}
}

// TestBuildWindowsInstallArgv covers the menu's Windows install prompt-to-argv
// building: every non-empty/non-false answer becomes its flag, and blank/false
// answers are omitted (so the subcommand's own defaults apply, exactly as they would
// if the operator had simply not passed that flag on the command line).
func TestBuildWindowsInstallArgv(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		configPath string
		nodeName   string
		setDefault bool
		keysDir    string
		want       []string
	}{
		{"all blank", "", "", "", false, "", nil},
		{"dir only", "C:\\SopsHQ", "", "", false, "", []string{"-dir", "C:\\SopsHQ"}},
		{
			"everything set",
			"C:\\SopsHQ", "C:\\SopsHQ\\config.jsonc", "my-box", true, "D:\\Keys",
			[]string{"-dir", "C:\\SopsHQ", "-config", "C:\\SopsHQ\\config.jsonc", "-name", "my-box", "-set-default", "-keys", "D:\\Keys"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildWindowsInstallArgv(tt.dir, tt.configPath, tt.nodeName, tt.setDefault, tt.keysDir)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("buildWindowsInstallArgv(...) = %#v, want %#v", got, tt.want)
			}
		})
	}
}

// TestBuildConfigOnlyArgv covers serve/start/stop's argv building: a blank config path
// omits -config entirely (so auto-discovery runs), a non-blank one is passed through.
func TestBuildConfigOnlyArgv(t *testing.T) {
	if got := buildConfigOnlyArgv(""); got != nil {
		t.Fatalf("buildConfigOnlyArgv(\"\") = %#v, want nil", got)
	}
	want := []string{"-config", "/data/config.jsonc"}
	if got := buildConfigOnlyArgv("/data/config.jsonc"); !reflect.DeepEqual(got, want) {
		t.Fatalf("buildConfigOnlyArgv(...) = %#v, want %#v", got, want)
	}
}

// TestBuildExportArgv covers export's argv building: -out is always present (required);
// -config is only added when non-blank.
func TestBuildExportArgv(t *testing.T) {
	tests := []struct {
		name       string
		configPath string
		out        string
		want       []string
	}{
		{"no config", "", "backup.bk", []string{"-out", "backup.bk"}},
		{"with config", "/data/config.jsonc", "backup.bk", []string{"-config", "/data/config.jsonc", "-out", "backup.bk"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildExportArgv(tt.configPath, tt.out)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("buildExportArgv(...) = %#v, want %#v", got, tt.want)
			}
		})
	}
}

// TestBuildRestoreArgv covers restore's argv building: both -in and -dir are required
// and always present.
func TestBuildRestoreArgv(t *testing.T) {
	want := []string{"-in", "backup.bk", "-dir", "/restore"}
	if got := buildRestoreArgv("backup.bk", "/restore"); !reflect.DeepEqual(got, want) {
		t.Fatalf("buildRestoreArgv(...) = %#v, want %#v", got, want)
	}
}

// TestBuildUserConfigArgv covers reset-2fa/reset-admin's argv building: -user is
// always present (required), -config only when non-blank.
func TestBuildUserConfigArgv(t *testing.T) {
	tests := []struct {
		name       string
		configPath string
		user       string
		want       []string
	}{
		{"no config", "", "alice", []string{"-user", "alice"}},
		{"with config", "/data/config.jsonc", "alice", []string{"-user", "alice", "-config", "/data/config.jsonc"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildUserConfigArgv(tt.configPath, tt.user)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("buildUserConfigArgv(...) = %#v, want %#v", got, tt.want)
			}
		})
	}
}

// TestBuildUnlockArgv covers unlock's argv building: both -runtime-dir and -config are
// optional and each is omitted independently when blank.
func TestBuildUnlockArgv(t *testing.T) {
	tests := []struct {
		name       string
		runtimeDir string
		configPath string
		want       []string
	}{
		{"both blank", "", "", nil},
		{"runtime dir only", "/run/sopshq", "", []string{"-runtime-dir", "/run/sopshq"}},
		{"config only", "", "/data/config.jsonc", []string{"-config", "/data/config.jsonc"}},
		{"both set", "/run/sopshq", "/data/config.jsonc", []string{"-runtime-dir", "/run/sopshq", "-config", "/data/config.jsonc"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildUnlockArgv(tt.runtimeDir, tt.configPath)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("buildUnlockArgv(...) = %#v, want %#v", got, tt.want)
			}
		})
	}
}

// TestBuildStatusArgv covers status's argv building: a blank runtime dir omits the
// flag entirely.
func TestBuildStatusArgv(t *testing.T) {
	if got := buildStatusArgv(""); got != nil {
		t.Fatalf("buildStatusArgv(\"\") = %#v, want nil", got)
	}
	want := []string{"-runtime-dir", "/run/sopshq"}
	if got := buildStatusArgv("/run/sopshq"); !reflect.DeepEqual(got, want) {
		t.Fatalf("buildStatusArgv(...) = %#v, want %#v", got, want)
	}
}

// TestMenuNeedsElevation covers the sudo-elevation decision: ONLY Linux `install`, run
// by a non-root euid, needs to be spawned under sudo. Every other OS/subcommand/euid
// combination runs in-process as the invoking user - including Linux install when
// already root (nothing to elevate to) and every non-install subcommand on Linux
// (none of them require root).
func TestMenuNeedsElevation(t *testing.T) {
	tests := []struct {
		name       string
		goos       string
		euid       int
		subcommand string
		want       bool
	}{
		{"linux install as non-root -> elevate", "linux", 1000, "install", true},
		{"linux install as root -> no elevation needed", "linux", 0, "install", false},
		{"linux export as non-root -> no elevation", "linux", 1000, "export", false},
		{"linux serve as non-root -> no elevation", "linux", 1000, "serve", false},
		{"windows install -> no elevation (no sudo concept)", "windows", -1, "install", false},
		{"darwin install as non-root -> no elevation (not linux)", "darwin", 1000, "install", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := menuNeedsElevation(tt.goos, tt.euid, tt.subcommand); got != tt.want {
				t.Fatalf("menuNeedsElevation(%q, %d, %q) = %v, want %v", tt.goos, tt.euid, tt.subcommand, got, tt.want)
			}
		})
	}
}

// TestRunMenuEntryAbortsOnRequiredMissing covers the abort-to-menu handling itself:
// when a menu entry's prompt function reports a blank required field, runMenuEntry
// must return nil (so runMenuLoop goes straight back to printing the menu and asking
// "Choice (blank to quit):" again) rather than propagating the error as a reported
// subcommand failure, and it must never dispatch the entry's subcommand.
func TestRunMenuEntryAbortsOnRequiredMissing(t *testing.T) {
	entry := menuEntry{
		number:     99,
		label:      "test entry",
		subcommand: "does-not-exist", // never reached: proves runMenuSubcommand was not called
		prompt: func() ([]string, error) {
			return nil, &menuRequiredMissingError{field: "Some field"}
		},
	}
	if err := runMenuEntry(entry); err != nil {
		t.Fatalf("runMenuEntry() = %v, want nil (abort to menu, not a reported failure)", err)
	}
}

// TestMenuEntriesCoverEveryDispatchTarget makes sure every menu entry's subcommand has
// a matching menuDispatch function, so the menu can never present an item it cannot
// actually run.
func TestMenuEntriesCoverEveryDispatchTarget(t *testing.T) {
	for _, e := range menuEntries() {
		if _, ok := menuDispatch[e.subcommand]; !ok {
			t.Fatalf("menu entry %q has no menuDispatch function for subcommand %q", e.label, e.subcommand)
		}
	}
}

// TestRequireLoadableConfig covers the shared early-validation helper: a path with no
// config file errors with a message pointing at "install" (menu item 1), while a real,
// loadable config passes silently.
func TestRequireLoadableConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "config.jsonc")
	err := requireLoadableConfig(missing, "doing the thing")
	if err == nil {
		t.Fatalf("missing config: expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "install SopsHQ on this machine first (menu item 1)") {
		t.Fatalf("missing config: error %q does not point at install", err.Error())
	}
	if !strings.Contains(err.Error(), "doing the thing") {
		t.Fatalf("missing config: error %q does not name the action", err.Error())
	}

	dir := t.TempDir()
	valid := writeValidConfig(t, dir)
	if err := requireLoadableConfig(valid, "doing the thing"); err != nil {
		t.Fatalf("valid config: unexpected error: %v", err)
	}
}

// TestPromptMenuExportStopsBeforeAskingForOut covers export's config check: with no
// config file at the answered path, promptMenuExport must abort back to the menu
// (an error naming "install", menu item 1) WITHOUT ever prompting for the output
// archive path.
func TestPromptMenuExportStopsBeforeAskingForOut(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.jsonc") // deliberately never created
	scriptStdin(t, cfgPath)

	got, err := promptMenuExport()
	requireMissingConfigAbort(t, got, err)
}

// sandboxUserConfigDir redirects os.UserConfigDir - and with it defaultDir, the
// per-user location pointer, and so discoverConfigPath - into a per-test directory
// on every OS, so config-discovery tests never see the real machine's install.
func sandboxUserConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)         // windows
	t.Setenv("XDG_CONFIG_HOME", dir) // unix
	t.Setenv("HOME", dir)            // darwin
	return dir
}

// TestMenuConfigDefault covers the shown default's existence check: the discovered
// config path is offered as the prompt default only when a config file really
// exists there, and "" (rendered as "(blank)") otherwise.
func TestMenuConfigDefault(t *testing.T) {
	sandboxUserConfigDir(t)
	if got := menuConfigDefault(); got != "" {
		t.Fatalf("menuConfigDefault() = %q, want \"\" when no config exists on the machine", got)
	}
	def := filepath.Join(defaultDir(), "config.jsonc")
	if err := os.MkdirAll(filepath.Dir(def), 0o700); err != nil {
		t.Fatal(err)
	}
	writeValidConfig(t, filepath.Dir(def))
	if got := menuConfigDefault(); got != def {
		t.Fatalf("menuConfigDefault() = %q, want %q", got, def)
	}
}

// TestPromptMenuExportAbortsWhenNoConfigAnywhere covers the not-installed case: no
// default is shown, so a blank answer resolves to no config at all and the entry
// aborts back to the menu pointing at install, without asking for the output path.
func TestPromptMenuExportAbortsWhenNoConfigAnywhere(t *testing.T) {
	sandboxUserConfigDir(t)
	scriptStdin(t, "")

	got, err := promptMenuExport()
	requireMissingConfigAbort(t, got, err)
}

// TestPromptMenuExportBlankConfigUsesShownDefault covers the config prompt's default:
// a blank answer must resolve to the default path the prompt displays (the default
// config location under the user config dir), not abort - so pressing Enter accepts
// the visible default exactly as shown.
func TestPromptMenuExportBlankConfigUsesShownDefault(t *testing.T) {
	dir := sandboxUserConfigDir(t)
	def := filepath.Join(defaultDir(), "config.jsonc")
	if err := os.MkdirAll(filepath.Dir(def), 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeValidConfig(t, filepath.Dir(def))
	outPath := filepath.Join(dir, "backup.bk")
	scriptStdin(t, "", outPath) // blank config answer = accept the shown default

	got, err := promptMenuExport()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"-config", cfgPath, "-out", outPath}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("promptMenuExport() = %#v, want %#v", got, want)
	}
}

// TestPromptMenuExportProceedsWhenConfigExists confirms the fix does not block the
// normal case: with a real, loadable config at the answered path, promptMenuExport
// still asks for the output path and builds export's usual argv.
func TestPromptMenuExportProceedsWhenConfigExists(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeValidConfig(t, dir)
	outPath := filepath.Join(dir, "backup.bk")
	scriptStdin(t, cfgPath, outPath)

	got, err := promptMenuExport()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"-config", cfgPath, "-out", outPath}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("promptMenuExport() = %#v, want %#v", got, want)
	}
}

// TestPromptMenuRestoreAbortsOnBlankArchivePath covers restore's first prompt: a
// blank answer must abort straight back to the menu (a *menuRequiredMissingError
// naming the archive-path field), not be re-asked and not fall through to the
// destination prompt - only one scripted line is supplied, so if the code
// incorrectly re-asked or continued, promptLine would hit EOF and return a
// different (generic "read input") error instead of this one.
func TestPromptMenuRestoreAbortsOnBlankArchivePath(t *testing.T) {
	scriptStdin(t, "")

	got, err := promptMenuRestore()
	if got != nil {
		t.Fatalf("promptMenuRestore() = %#v, want nil", got)
	}
	var missing *menuRequiredMissingError
	if !errors.As(err, &missing) {
		t.Fatalf("expected a *menuRequiredMissingError, got %v", err)
	}
	if !strings.Contains(missing.field, "Backup archive path") {
		t.Fatalf("missing.field = %q, want it to name the archive path", missing.field)
	}
}

// TestPromptMenuRestoreAbortsOnBlankDestination covers the same abort-to-menu
// behavior for the second prompt (destination directory): a blank answer aborts
// immediately rather than being re-asked or letting the entry continue on to the
// overwrite check.
func TestPromptMenuRestoreAbortsOnBlankDestination(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "backup.bin")
	scriptStdin(t, archive, "")

	got, err := promptMenuRestore()
	if got != nil {
		t.Fatalf("promptMenuRestore() = %#v, want nil", got)
	}
	var missing *menuRequiredMissingError
	if !errors.As(err, &missing) {
		t.Fatalf("expected a *menuRequiredMissingError, got %v", err)
	}
	if !strings.Contains(missing.field, "Destination directory") {
		t.Fatalf("missing.field = %q, want it to name the destination directory", missing.field)
	}
}

// TestPromptMenuRestoreSkipsExtraConfirmWhenDestEmpty confirms the second,
// overwrite-specific confirmation is skipped when there is nothing at the
// destination to lose - so a fresh, empty restore target never has to answer
// an extra prompt on top of the generic destructive-action confirm.
func TestPromptMenuRestoreSkipsExtraConfirmWhenDestEmpty(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "backup.bin")
	dst := filepath.Join(t.TempDir(), "restored") // nonexistent: nothing to overwrite
	scriptStdin(t, archive, dst)                  // no third answer supplied

	got, err := promptMenuRestore()
	if err != nil {
		t.Fatalf("unexpected error (extra confirm should not have been asked): %v", err)
	}
	want := []string{"-in", archive, "-dir", dst}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("promptMenuRestore() = %#v, want %#v", got, want)
	}
}

// TestPromptMenuRestoreExtraConfirmWhenDestNonEmpty covers the overwrite
// warning itself: when the destination directory already holds a file, the
// extra confirmation must fire, naming that directory; declining it aborts
// without building restore's argv, and accepting it proceeds normally.
func TestPromptMenuRestoreExtraConfirmWhenDestNonEmpty(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "backup.bin")

	t.Run("declined", func(t *testing.T) {
		dst := t.TempDir()
		if err := os.WriteFile(filepath.Join(dst, "keep.txt"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		scriptStdin(t, archive, dst, "n")

		_, err := promptMenuRestore()
		if !errors.Is(err, errMenuCancelled) {
			t.Fatalf("expected errMenuCancelled when the overwrite confirm is declined, got %v", err)
		}
	})

	t.Run("accepted", func(t *testing.T) {
		dst := t.TempDir()
		if err := os.WriteFile(filepath.Join(dst, "keep.txt"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		scriptStdin(t, archive, dst, "y")

		got, err := promptMenuRestore()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"-in", archive, "-dir", dst}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("promptMenuRestore() = %#v, want %#v", got, want)
		}
	})
}

// TestPromptMenuResetAdminStopsBeforeAskingForUser covers reset-admin's config
// check: with no config file at the answered path, promptMenuResetAdmin must abort
// back to the menu WITHOUT ever prompting for the username or asking for
// confirmation.
func TestPromptMenuResetAdminStopsBeforeAskingForUser(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.jsonc") // deliberately never created
	scriptStdin(t, cfgPath)

	got, err := promptMenuResetAdmin()
	requireMissingConfigAbort(t, got, err)
}

// TestPromptMenuResetAdminAbortsOnBlankUser covers reset-admin's username prompt:
// a blank answer must abort straight back to the menu (a *menuRequiredMissingError
// naming the username field) WITHOUT ever asking for the confirmation - only one
// scripted line follows the config path, so a fall-through to the confirm prompt
// would hit EOF and return a different error instead of this one.
func TestPromptMenuResetAdminAbortsOnBlankUser(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeValidConfig(t, dir)
	scriptStdin(t, cfgPath, "")

	got, err := promptMenuResetAdmin()
	if got != nil {
		t.Fatalf("promptMenuResetAdmin() = %#v, want nil", got)
	}
	var missing *menuRequiredMissingError
	if !errors.As(err, &missing) {
		t.Fatalf("expected a *menuRequiredMissingError, got %v", err)
	}
	if !strings.Contains(missing.field, "Panel username") {
		t.Fatalf("missing.field = %q, want it to name the username field", missing.field)
	}
}

// TestPromptMenuResetAdminConfirmDeclineAndAccept covers reset-admin's own
// specific confirmation: it fires only after the config and username are
// gathered and validated, names the exact user and config, and a decline
// returns errMenuCancelled without building the argv.
func TestPromptMenuResetAdminConfirmDeclineAndAccept(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeValidConfig(t, dir)

	t.Run("declined", func(t *testing.T) {
		scriptStdin(t, cfgPath, "alice", "n")
		_, err := promptMenuResetAdmin()
		if !errors.Is(err, errMenuCancelled) {
			t.Fatalf("expected errMenuCancelled when the confirm is declined, got %v", err)
		}
	})

	t.Run("accepted", func(t *testing.T) {
		scriptStdin(t, cfgPath, "alice", "y")
		got, err := promptMenuResetAdmin()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"-user", "alice", "-config", cfgPath}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("promptMenuResetAdmin() = %#v, want %#v", got, want)
		}
	})
}

// TestPromptMenuExportAbortsOnBlankOut covers export's output-path prompt: a
// blank answer must abort straight back to the menu (a *menuRequiredMissingError
// naming the output-path field), not be re-asked and not accepted through to
// cmdExport's own "-out is required" check.
func TestPromptMenuExportAbortsOnBlankOut(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeValidConfig(t, dir)
	scriptStdin(t, cfgPath, "")

	got, err := promptMenuExport()
	if got != nil {
		t.Fatalf("promptMenuExport() = %#v, want nil", got)
	}
	var missing *menuRequiredMissingError
	if !errors.As(err, &missing) {
		t.Fatalf("expected a *menuRequiredMissingError, got %v", err)
	}
	if !strings.Contains(missing.field, "Output archive path") {
		t.Fatalf("missing.field = %q, want it to name the output-path field", missing.field)
	}
}

// TestPromptMenuReset2FAAbortsOnBlankUser covers reset-2fa's username prompt with
// the same abort-to-menu behavior as reset-admin's.
func TestPromptMenuReset2FAAbortsOnBlankUser(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeValidConfig(t, dir)
	scriptStdin(t, cfgPath, "")

	got, err := promptMenuReset2FA()
	if got != nil {
		t.Fatalf("promptMenuReset2FA() = %#v, want nil", got)
	}
	var missing *menuRequiredMissingError
	if !errors.As(err, &missing) {
		t.Fatalf("expected a *menuRequiredMissingError, got %v", err)
	}
	if !strings.Contains(missing.field, "Panel username") {
		t.Fatalf("missing.field = %q, want it to name the username field", missing.field)
	}
}

// TestPromptMenuReset2FAAbortsOnMissingConfig covers reset-2fa's config check: with
// no loadable config at the answered path, it aborts back to the menu and never
// reaches the username prompt.
func TestPromptMenuReset2FAAbortsOnMissingConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.jsonc") // deliberately never created
	scriptStdin(t, cfgPath)

	got, err := promptMenuReset2FA()
	requireMissingConfigAbort(t, got, err)
}

// TestPromptMenuServeAbortsOnMissingConfig covers serve's config check: no loadable
// config at the answered path aborts back to the menu rather than proceeding.
func TestPromptMenuServeAbortsOnMissingConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.jsonc") // deliberately never created
	scriptStdin(t, cfgPath)

	got, err := promptMenuServe()
	requireMissingConfigAbort(t, got, err)
}

// TestPromptMenuStartAbortsOnMissingConfig mirrors TestPromptMenuServeAbortsOnMissingConfig
// for start.
func TestPromptMenuStartAbortsOnMissingConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.jsonc") // deliberately never created
	scriptStdin(t, cfgPath)

	got, err := promptMenuStart()
	requireMissingConfigAbort(t, got, err)
}

// TestPromptMenuStopAbortsOnMissingConfig mirrors TestPromptMenuServeAbortsOnMissingConfig
// for stop.
func TestPromptMenuStopAbortsOnMissingConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.jsonc") // deliberately never created
	scriptStdin(t, cfgPath)

	got, err := promptMenuStop()
	requireMissingConfigAbort(t, got, err)
}

// TestPromptMenuUninstallLauncherConfirm covers uninstall-launcher's own
// specific confirmation, asked immediately since it has no inputs to gather:
// it names the exact script file it will remove, a decline returns
// errMenuCancelled, and an accept returns a nil argv (uninstall-launcher
// takes no flags).
func TestPromptMenuUninstallLauncherConfirm(t *testing.T) {
	t.Run("declined", func(t *testing.T) {
		scriptStdin(t, "n")
		_, err := promptMenuUninstallLauncher()
		if !errors.Is(err, errMenuCancelled) {
			t.Fatalf("expected errMenuCancelled when the confirm is declined, got %v", err)
		}
	})

	t.Run("accepted", func(t *testing.T) {
		scriptStdin(t, "y")
		got, err := promptMenuUninstallLauncher()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Fatalf("promptMenuUninstallLauncher() = %#v, want nil", got)
		}
	})
}
