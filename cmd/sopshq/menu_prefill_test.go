package main

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

// TestPromptMenuInstallPrefillsHostname covers the install prompt's node-name
// default: a blank answer must resolve to this machine's hostname (the same
// fallback runInit applies), so the prompt shows the name that will actually be
// used instead of "(blank)".
func TestPromptMenuInstallPrefillsHostname(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("the Linux install path prompts inside cmdSetup, not the menu")
	}
	sandboxUserConfigDir(t)
	scriptStdin(t, "", "", "", "", "") // dir, config, name, set-default, keys: accept every default

	got, err := promptMenuInstall()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	host, _ := os.Hostname()
	want := buildWindowsInstallArgv(defaultDir(), filepath.Join(defaultDir(), "config.jsonc"), host, false, "")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("promptMenuInstall() = %#v, want %#v", got, want)
	}
}
