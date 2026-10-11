package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	"sopshq/internal/update"
)

// updateOptions holds `sopshq update`'s flags.
type updateOptions struct {
	Check      bool   // --check: report the running and newest published version, change nothing
	Rollback   bool   // --rollback: restore the newest backup
	From       string // --from DIR: install from a local folder holding the release files
	Prefix     string // --prefix: the install prefix holding the binary (<prefix>/sopshq)
	RuntimeDir string // --runtime-dir: the folder holding the unlock status socket
	Config     string // --config: config.jsonc path (default: auto-discovered)
	Yes        bool   // --yes: do not ask before stopping a stray serve process
}

// parseUpdateFlags parses the update subcommand's flags and rejects combinations that
// have no meaning, so a typo never turns a read-only check into an install.
func parseUpdateFlags(args []string) (updateOptions, error) {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	check := fs.Bool("check", false, "print the running and the newest published version; change nothing (runs as any user)")
	rollback := fs.Bool("rollback", false, "restore the newest backup of the binary (root)")
	from := fs.String("from", "", "install from this folder holding the release files, instead of downloading (root)")
	prefix := fs.String("prefix", setupPrefixDefault, "install prefix holding the binary (<prefix>/sopshq)")
	runtimeDir := fs.String("runtime-dir", defaultRuntimeDir(), "directory holding the unlock socket")
	cfgPath := fs.String("config", "", "config file path (default: auto-discovered)")
	yes := fs.Bool("yes", false, "do not ask before stopping a stray SopsHQ serve process")
	if err := fs.Parse(normalizeFlagArgs(args)); err != nil {
		return updateOptions{}, err
	}
	if fs.NArg() > 0 {
		return updateOptions{}, fmt.Errorf("update takes no arguments, got %q", fs.Arg(0))
	}
	applyTrailingQuoteFix("from", from)
	applyTrailingQuoteFix("prefix", prefix)
	applyTrailingQuoteFix("runtime-dir", runtimeDir)
	applyTrailingQuoteFix("config", cfgPath)
	opts := updateOptions{
		Check: *check, Rollback: *rollback, From: *from, Prefix: *prefix,
		RuntimeDir: *runtimeDir, Config: *cfgPath, Yes: *yes,
	}
	switch {
	case opts.Check && (opts.Rollback || opts.From != ""):
		return updateOptions{}, errors.New("--check cannot be combined with --rollback or --from")
	case opts.Rollback && opts.From != "":
		return updateOptions{}, errors.New("--rollback cannot be combined with --from")
	}
	return opts, nil
}

// cmdUpdate is `sopshq update`: replace the installed binary with a newer, verified
// release, keeping a backup and rolling back on its own if the new build will not start.
// Only Linux is supported; elsewhere it prints the manual steps and fails, changing
// nothing.
func cmdUpdate(args []string) error {
	if runtime.GOOS != "linux" {
		printManualUpdateSteps(os.Stderr)
		return errors.New("sopshq update is only supported on Linux; follow the manual steps above")
	}
	opts, err := parseUpdateFlags(args)
	if err != nil {
		return err
	}
	return runUpdate(opts)
}

// printManualUpdateSteps tells an operator on a platform without `sopshq update` how to
// update by hand: stop, replace the file, start.
func printManualUpdateSteps(w io.Writer) {
	fmt.Fprintf(w, `sopshq update is not available on this operating system. To update by hand:

  1. Stop SopsHQ: close its console window, or run "sopshq stop".
  2. Download %s, SHA256SUMS and SHA256SUMS.sig from the release page.
     Compare the SHA-256 of the binary with its line in SHA256SUMS.
  3. Keep a copy of the current sopshq.exe, then replace it with the downloaded file
     (a running .exe cannot be overwritten but can be renamed: rename it first).
  4. Start SopsHQ again and type the vault key as usual.

`, update.AssetName("windows", "amd64"))
}
