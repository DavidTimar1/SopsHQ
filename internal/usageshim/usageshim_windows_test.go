//go:build windows

package usageshim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallUninstallWindows drives Install/Uninstall with in-memory registry
// editors injected, so the test never touches the real HKCU\Environment.
func TestInstallUninstallWindows(t *testing.T) {
	fakePath := `C:\existing`
	vars := map[string]string{}
	regReadUserPath = func() (string, error) { return fakePath, nil }
	regWriteUserPath = func(v string) error { fakePath = v; return nil }
	regSetUserVar = func(n, v string) error { vars[n] = v; return nil }
	regDeleteUserVar = func(n string) error { delete(vars, n); return nil }
	defer func() {
		regReadUserPath = realReadUserPath
		regWriteUserPath = realWriteUserPath
		regSetUserVar = realSetUserVar
		regDeleteUserVar = realDeleteUserVar
	}()

	data := t.TempDir()
	token := filepath.Join(data, "ingest.token")
	dir := Dir(data)

	st, err := Install(data, "http://127.0.0.1:8770", token)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !st.Installed {
		t.Fatal("expected Installed")
	}
	for _, f := range []string{"sops.cmd", "sops-wrapper.ps1"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
	}
	if !strings.HasPrefix(fakePath, dir) {
		t.Fatalf("shim dir not prepended to PATH: %q", fakePath)
	}
	if !strings.Contains(fakePath, `C:\existing`) {
		t.Fatalf("existing PATH lost: %q", fakePath)
	}
	if vars["SOPSHQ_PANEL_URL"] != "http://127.0.0.1:8770" || vars["SOPSHQ_INGEST_TOKEN_FILE"] != token {
		t.Fatalf("env vars not set correctly: %v", vars)
	}
	if !Stat(data).Installed {
		t.Fatal("Stat should report installed")
	}

	// Idempotent: a second install must not duplicate the PATH entry.
	if _, err := Install(data, "http://127.0.0.1:8770", token); err != nil {
		t.Fatalf("re-Install: %v", err)
	}
	if strings.Count(fakePath, dir) != 1 {
		t.Fatalf("shim dir should appear once on PATH: %q", fakePath)
	}

	if err := Uninstall(data); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if strings.Contains(fakePath, dir) {
		t.Fatalf("PATH not reverted: %q", fakePath)
	}
	if len(vars) != 0 {
		t.Fatalf("env vars not cleared: %v", vars)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("managed dir not removed")
	}
	if Stat(data).Installed {
		t.Fatal("Stat should report not installed after uninstall")
	}
}
