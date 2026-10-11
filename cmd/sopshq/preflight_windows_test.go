//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sopshq/internal/config"
)

// TestRunPreflightWindows checks the real Windows path preflight: an existing writable
// data dir passes (which also exercises the runtime-dir probe, created lazily under an
// isolated %LOCALAPPDATA%), a missing data dir fails naming the path, and a configured
// but missing keybase root fails naming it. It runs only on Windows.
func TestRunPreflightWindows(t *testing.T) {
	base := t.TempDir()
	// Isolate the runtime-dir probe from the real user profile so the healthy case does
	// not depend on this machine's actual %LOCALAPPDATA% being writable.
	t.Setenv("LocalAppData", t.TempDir())

	// Healthy: data dir exists and is writable, no keybase root configured.
	okCfg := &config.Config{DataDir: base}
	if err := runPreflight(okCfg); err != nil {
		t.Fatalf("healthy data dir should pass preflight, got %v", err)
	}

	// Missing data dir: fails, naming the path.
	missing := filepath.Join(base, "does-not-exist")
	missCfg := &config.Config{DataDir: missing}
	err := runPreflight(missCfg)
	if err == nil || !strings.Contains(err.Error(), missing) {
		t.Fatalf("missing data dir should fail naming the path, got %v", err)
	}

	// Configured but missing keybase root: fails, naming it.
	kbMissing := filepath.Join(base, "keybase-missing")
	kbCfg := &config.Config{DataDir: base, KeybaseRoot: kbMissing}
	err = runPreflight(kbCfg)
	if err == nil || !strings.Contains(err.Error(), kbMissing) {
		t.Fatalf("missing keybase root should fail naming the path, got %v", err)
	}
}

// TestProbeRuntimeDirWindows covers the runtime-dir probe directly: a not-yet-created
// directory is created and passes (the normal first-run case, since serve creates the
// runtime dir lazily rather than the operator pre-creating it), and a path that collides
// with an existing FILE (so os.MkdirAll cannot create the directory) fails naming the
// path. It runs only on Windows.
func TestProbeRuntimeDirWindows(t *testing.T) {
	base := t.TempDir()

	notYetCreated := filepath.Join(base, "run")
	if err := probeRuntimeDir(notYetCreated); err != nil {
		t.Fatalf("a not-yet-created runtime dir should be created and pass, got %v", err)
	}

	blocked := filepath.Join(base, "blocked-file", "run")
	if err := os.WriteFile(filepath.Join(base, "blocked-file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := probeRuntimeDir(blocked); err == nil || !strings.Contains(err.Error(), blocked) {
		t.Fatalf("a runtime dir path blocked by a file should fail naming the path, got %v", err)
	}
}
