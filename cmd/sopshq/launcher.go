package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
)

// launcherScriptName is the file `install-launcher` writes into the current user's
// Startup folder and `uninstall-launcher` removes. A fixed, deterministic name means
// re-running install-launcher converges (it overwrites the same file) and
// uninstall-launcher always knows exactly what to delete.
const launcherScriptName = "sopshq-launcher.cmd"

// installLauncherOptions holds `install-launcher`'s resolved settings, whether they
// came from CLI flags or from `sopshq install`'s own Windows flow (which runs this
// straight after runInit, against the very config path init just wrote) - the two
// callers that drive the same core logic (runInstallLauncher) without duplicating it.
type installLauncherOptions struct {
	ConfigPath string // empty means auto-discovered
}

// parseInstallLauncherFlags parses the `install-launcher` subcommand's flags into an
// installLauncherOptions.
func parseInstallLauncherFlags(args []string) (installLauncherOptions, error) {
	fs := flag.NewFlagSet("install-launcher", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path (default: auto-discovered)")
	if err := fs.Parse(normalizeFlagArgs(args)); err != nil {
		return installLauncherOptions{}, err
	}
	applyTrailingQuoteFix("config", cfgPath)
	return installLauncherOptions{ConfigPath: *cfgPath}, nil
}

// cmdInstallLauncher registers a Windows Startup-folder launcher (Windows only): a
// small batch script written to the current user's Startup folder
// (%AppData%\Microsoft\Windows\Start Menu\Programs\Startup), so it runs automatically
// at every logon. It polls FOREVER (no timeout) for the given config file to appear -
// the data folder may live on a volume the operator manually decrypts and mounts after
// logging in - then launches `sopshq serve` in a VISIBLE console window, where SopsHQ
// prompts for the vault key exactly like any other foreground run. The vault is never
// auto-unlocked: this only automates getting `serve` running and waiting for the
// operator to type the key. Registering this script is a one-time, per-user action
// (no admin/UAC required - the Startup folder is inside the user's own profile).
func cmdInstallLauncher(args []string) error {
	if runtime.GOOS != "windows" {
		return errors.New("sopshq install-launcher is only supported on Windows")
	}
	opts, err := parseInstallLauncherFlags(args)
	if err != nil {
		return err
	}
	return runInstallLauncher(opts)
}

// runInstallLauncher is install-launcher's core logic: it writes the Startup-folder
// script for the given (or auto-discovered) config path. It is a plain function (no
// flag parsing) so both the flag-driven `sopshq install-launcher` and `sopshq install`
// on Windows share exactly one implementation.
func runInstallLauncher(opts installLauncherOptions) error {
	path := opts.ConfigPath
	if path == "" {
		path = discoverConfigPath()
	}
	bin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate this binary: %w", err)
	}
	scriptPath, err := installLauncherScript(bin, path)
	if err != nil {
		return err
	}
	fmt.Printf("Installed the Windows Startup launcher:\n  %s\n", scriptPath)
	fmt.Printf("It waits for %s to appear, then runs:\n  %s serve -config %s\n", path, bin, path)
	fmt.Println("It runs automatically at every logon from now on (log off and back on, or sign out and in, to test it).")
	fmt.Println("Remove it any time with: sopshq uninstall-launcher")
	return nil
}

// cmdUninstallLauncher removes the Windows Startup-folder launcher registered by
// install-launcher (Windows only). It NEVER touches the data folder, the vault, or any
// installed key material - it only deletes the one small script file it wrote.
func cmdUninstallLauncher(args []string) error {
	if runtime.GOOS != "windows" {
		return errors.New("sopshq uninstall-launcher is only supported on Windows")
	}
	fs := flag.NewFlagSet("uninstall-launcher", flag.ContinueOnError)
	if err := fs.Parse(normalizeFlagArgs(args)); err != nil {
		return err
	}
	scriptPath, removed, err := uninstallLauncherScript()
	if err != nil {
		return err
	}
	if !removed {
		fmt.Printf("No Startup launcher was registered (nothing at %s).\n", scriptPath)
		return nil
	}
	fmt.Printf("Removed the Windows Startup launcher: %s\n", scriptPath)
	fmt.Println("The data folder, vault, and keys were not touched.")
	return nil
}

// buildLauncherScript renders the Startup-folder batch script content for bin
// (the sopshq.exe path) and configPath (the config file it waits for). It is pure so
// the script text is unit-tested without touching a real Startup folder. The script:
//  1. polls FOREVER (no timeout) until configPath exists - the data folder may sit on
//     a volume the operator decrypts and mounts by hand after logging in;
//  2. then runs `<bin> serve -config <configPath>` in this same (visible) console
//     window, so SopsHQ prompts for the vault key interactively, exactly like any
//     other foreground run - the vault is never auto-supplied or cached;
//  3. pauses after serve exits, so an error or the normal Ctrl-C shutdown message
//     stays on screen instead of the window vanishing immediately.
func buildLauncherScript(bin, configPath string) string {
	return "@echo off\r\n" +
		"setlocal\r\n" +
		"set \"SOPSHQ_BIN=" + bin + "\"\r\n" +
		"set \"SOPSHQ_CONFIG=" + configPath + "\"\r\n" +
		"echo SopsHQ launcher: waiting for %SOPSHQ_CONFIG% to become available...\r\n" +
		":wait\r\n" +
		"if not exist \"%SOPSHQ_CONFIG%\" (\r\n" +
		"  timeout /t 5 /nobreak >nul\r\n" +
		"  goto wait\r\n" +
		")\r\n" +
		"echo SopsHQ launcher: found %SOPSHQ_CONFIG%, starting SopsHQ...\r\n" +
		"\"%SOPSHQ_BIN%\" serve -config \"%SOPSHQ_CONFIG%\"\r\n" +
		"echo.\r\n" +
		"echo SopsHQ has stopped.\r\n" +
		"pause\r\n"
}
