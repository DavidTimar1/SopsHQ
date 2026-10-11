//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallAndUninstallLauncherScript exercises the real Windows Startup-folder
// read/write paths against a SANDBOXED %AppData% (t.Setenv, auto-restored), so the
// test never touches the operator's actual Startup folder. It covers install (creates
// the folder + script, referencing the given binary and config path), then uninstall
// (removes exactly that file and reports it), then a second uninstall (a clean no-op).
func TestInstallAndUninstallLauncherScript(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("APPDATA", tmp)

	const bin = `C:\SopsHQ\sopshq.exe`
	const cfg = `C:\SopsHQ\config.jsonc`

	scriptPath, err := installLauncherScript(bin, cfg)
	if err != nil {
		t.Fatalf("installLauncherScript: %v", err)
	}
	wantDir := filepath.Join(tmp, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	if filepath.Dir(scriptPath) != wantDir {
		t.Fatalf("script dir = %s, want %s", filepath.Dir(scriptPath), wantDir)
	}
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}
	if !strings.Contains(string(data), bin) || !strings.Contains(string(data), cfg) {
		t.Fatalf("script does not reference bin/config: %s", data)
	}

	path, removed, err := uninstallLauncherScript()
	if err != nil {
		t.Fatalf("uninstallLauncherScript: %v", err)
	}
	if !removed || path != scriptPath {
		t.Fatalf("uninstall = (%s,%v); want (%s,true)", path, removed, scriptPath)
	}
	if _, err := os.Stat(scriptPath); !os.IsNotExist(err) {
		t.Fatalf("script still exists after uninstall")
	}

	path2, removed2, err := uninstallLauncherScript()
	if err != nil {
		t.Fatalf("second uninstallLauncherScript: %v", err)
	}
	if removed2 || path2 != scriptPath {
		t.Fatalf("second uninstall = (%s,%v); want (%s,false)", path2, removed2, scriptPath)
	}
}
