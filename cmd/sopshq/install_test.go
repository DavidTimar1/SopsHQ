package main

import (
	"strings"
	"testing"
)

// TestParseWindowsInstallFlags covers `sopshq install`'s Windows flag parsing: it
// accepts the same flag set as init (dir/config/name/set-default/keys) and resolves
// into the fields runWindowsInstall needs.
func TestParseWindowsInstallFlags(t *testing.T) {
	opts, err := parseWindowsInstallFlags([]string{
		"-dir", `C:\SopsHQ`, "-config", `C:\SopsHQ\config.jsonc`, "-name", "my-box",
		"-set-default", "-keys", `D:\SopsHQKeys`,
	})
	if err != nil {
		t.Fatalf("parseWindowsInstallFlags: %v", err)
	}
	if opts.Dir != `C:\SopsHQ` || opts.ConfigPath != `C:\SopsHQ\config.jsonc` ||
		opts.Name != "my-box" || !opts.SetDefault || opts.KeysDir != `D:\SopsHQKeys` {
		t.Fatalf("unexpected opts: %+v", opts)
	}
}

// TestParseWindowsInstallFlagsDefaults covers the zero-flag case: SetDefault is false
// and every path field is empty except Dir, which falls back to defaultDir().
func TestParseWindowsInstallFlagsDefaults(t *testing.T) {
	opts, err := parseWindowsInstallFlags(nil)
	if err != nil {
		t.Fatalf("parseWindowsInstallFlags: %v", err)
	}
	if opts.Dir == "" {
		t.Fatalf("Dir should default to defaultDir(), got empty")
	}
	if opts.ConfigPath != "" || opts.Name != "" || opts.SetDefault || opts.KeysDir != "" {
		t.Fatalf("unexpected non-empty defaults: %+v", opts)
	}
}

// TestCmdInstallDispatchesByGOOS documents (and locks in) install's OS branching: it
// is a plain dispatch, not two copies of installer logic. We can only actually exercise
// the branch matching the host GOOS here (calling the other would hit the "wrong OS"
// guard in cmdSetup/cmdInstallWindows), but that guard message itself proves the
// dispatch reached the right function.
func TestCmdInstallDispatchesByGOOS(t *testing.T) {
	// An unparseable flag on the "install" argv should surface as a flag-parsing error
	// from whichever OS branch cmdInstall dispatched to, not a panic or a silent no-op -
	// proving cmdInstall actually forwarded args into a real flag.FlagSet.
	err := cmdInstall([]string{"-not-a-real-flag"})
	if err == nil {
		t.Fatalf("expected an error for an unrecognized flag, got nil")
	}
	if !strings.Contains(err.Error(), "not-a-real-flag") && !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("unexpected error shape: %v", err)
	}
}
