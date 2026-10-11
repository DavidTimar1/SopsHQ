package main

import (
	"errors"
	"flag"
	"path/filepath"
	"runtime"
)

// cmdInstall is the single, OS-appropriate entry point for installing SopsHQ. On Linux
// it IS `sopshq setup` (a plain dispatch, not a second implementation): the existing
// root-required service-account + systemd flow, unchanged. On Windows, where there is
// no root-only installer, it runs init's core logic (choose the vault key) and then
// install-launcher's core logic (register the Startup-folder launcher) in sequence
// against the same resolved -dir/-config, so one command replaces the two-step
// `sopshq init` + `sopshq install-launcher`. Both
// branches are plain functions the menu also calls directly, so there is exactly one
// implementation of "install" per OS.
func cmdInstall(args []string) error {
	if runtime.GOOS == "linux" {
		return cmdSetup(args)
	}
	return cmdInstallWindows(args)
}

// windowsInstallOptions holds the resolved settings for a Windows `sopshq install`: the
// union of what init and install-launcher each need, since install runs both against
// the same paths.
type windowsInstallOptions struct {
	Dir        string
	ConfigPath string // empty means <Dir>/config.jsonc
	Name       string
	SetDefault bool
	KeysDir    string
}

// parseWindowsInstallFlags parses `sopshq install`'s Windows flags - the same flag set
// init accepts, since install's first step IS init - into a windowsInstallOptions.
func parseWindowsInstallFlags(args []string) (windowsInstallOptions, error) {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	dir := fs.String("dir", defaultDir(), "base directory for config and data")
	cfgPath := fs.String("config", "", "config file path (default <dir>/config.jsonc)")
	name := fs.String("name", "", "human node name (default hostname)")
	setDefault := fs.Bool("set-default", false, "make this install the machine default (repoint the bare-run location pointer even if one already points elsewhere)")
	keysDir := fs.String("keys", "", "machine keys root: local OS users without their own keystore path get keys at <root>/<username>/keys.txt (POSIX ACLs on Linux; plain folder on Windows)")
	if err := fs.Parse(normalizeFlagArgs(args)); err != nil {
		return windowsInstallOptions{}, err
	}
	applyTrailingQuoteFix("dir", dir)
	applyTrailingQuoteFix("config", cfgPath)
	applyTrailingQuoteFix("keys", keysDir)
	return windowsInstallOptions{Dir: *dir, ConfigPath: *cfgPath, Name: *name, SetDefault: *setDefault, KeysDir: *keysDir}, nil
}

// cmdInstallWindows is `sopshq install` on Windows: parse the flags, then run the
// shared core (runWindowsInstall).
func cmdInstallWindows(args []string) error {
	if runtime.GOOS != "windows" {
		return errors.New("sopshq install's Windows path only runs on Windows (on Linux, install runs `sopshq setup` instead)")
	}
	opts, err := parseWindowsInstallFlags(args)
	if err != nil {
		return err
	}
	return runWindowsInstall(opts)
}

// runWindowsInstall is `sopshq install`'s Windows core: it runs init's core logic
// (runInit), then, once the config path is known, install-launcher's core logic
// (runInstallLauncher) against that same path - so one call does both steps. It is a
// plain function (no flag parsing) so the flag-driven CLI and the menu share exactly
// one implementation.
func runWindowsInstall(opts windowsInstallOptions) error {
	if err := runInit(initOptions{
		Dir:        opts.Dir,
		ConfigPath: opts.ConfigPath,
		Name:       opts.Name,
		SetDefault: opts.SetDefault,
		KeysDir:    opts.KeysDir,
	}); err != nil {
		return err
	}
	path := opts.ConfigPath
	if path == "" {
		path = filepath.Join(opts.Dir, "config.jsonc")
	}
	return runInstallLauncher(installLauncherOptions{ConfigPath: path})
}
