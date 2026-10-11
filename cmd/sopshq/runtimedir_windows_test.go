//go:build windows

package main

import (
	"path/filepath"
	"testing"
)

// TestDefaultRuntimeDirWindows covers the Windows runtime-directory resolution: it
// resolves under %LOCALAPPDATA% (never the roaming %AppData% that defaultDir uses), in a
// "sopshq\run" subfolder. It runs only on Windows.
func TestDefaultRuntimeDirWindows(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("LocalAppData", dir)
	want := filepath.Join(dir, "sopshq", "run")
	if got := defaultRuntimeDir(); got != want {
		t.Fatalf("defaultRuntimeDir() = %q, want %q", got, want)
	}
}
