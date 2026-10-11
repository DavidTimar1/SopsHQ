//go:build windows

package usageshim

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"sopshq/shims"
)

// caseInsensitivePaths reports that Windows PATH entries compare case-insensitively.
const caseInsensitivePaths = true

// User-environment editors, isolated so tests can inject fakes and never touch the
// real registry. They operate on HKCU\Environment (per-user, no admin).
var (
	regReadUserPath  = realReadUserPath
	regWriteUserPath = realWriteUserPath
	regSetUserVar    = realSetUserVar
	regDeleteUserVar = realDeleteUserVar
)

func install(dir, panelURL, tokenFile string) (Status, error) {
	if err := writeScripts(dir); err != nil {
		return Status{}, err
	}
	cur, err := regReadUserPath()
	if err != nil {
		return Status{}, err
	}
	if err := regWriteUserPath(prependPath(cur, dir)); err != nil {
		return Status{}, err
	}
	if err := regSetUserVar("SOPSHQ_PANEL_URL", panelURL); err != nil {
		return Status{}, err
	}
	if err := regSetUserVar("SOPSHQ_INGEST_TOKEN_FILE", tokenFile); err != nil {
		return Status{}, err
	}
	return Status{Installed: true, Dir: dir,
		Note: "Open a new terminal so the updated PATH takes effect."}, nil
}

func uninstall(dir string) error {
	if cur, err := regReadUserPath(); err == nil {
		_ = regWriteUserPath(removePathEntry(cur, dir))
	}
	_ = regDeleteUserVar("SOPSHQ_PANEL_URL")
	_ = regDeleteUserVar("SOPSHQ_INGEST_TOKEN_FILE")
	return os.RemoveAll(dir)
}

func status(dir string) Status {
	st := Status{Dir: dir}
	if _, err := os.Stat(filepath.Join(dir, shims.LauncherCmd)); err != nil {
		return st
	}
	cur, _ := regReadUserPath()
	for _, e := range pathEntries(cur) {
		if samePathEntry(e, dir) {
			st.Installed = true
			break
		}
	}
	return st
}

// writeScripts materializes the launcher + PowerShell wrapper into dir.
func writeScripts(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("usageshim: mkdir %s: %w", dir, err)
	}
	if err := extract(dir, shims.LauncherCmd, 0o755); err != nil {
		return err
	}
	return extract(dir, shims.WrapperPS1, 0o755)
}

// ---- real registry editors (HKCU\Environment via reg.exe; never setx, which
// truncates PATH at 1024 chars) -------------------------------------------------

func realReadUserPath() (string, error) {
	out, err := exec.Command("reg", "query", `HKCU\Environment`, "/v", "Path").CombinedOutput()
	if err != nil {
		return "", nil // not set -> treat as empty, not an error
	}
	return parseRegValue(string(out), "Path"), nil
}

func realWriteUserPath(value string) error {
	return runReg("add", `HKCU\Environment`, "/v", "Path", "/t", "REG_EXPAND_SZ", "/d", value, "/f")
}

func realSetUserVar(name, value string) error {
	return runReg("add", `HKCU\Environment`, "/v", name, "/t", "REG_SZ", "/d", value, "/f")
}

func realDeleteUserVar(name string) error {
	_ = runReg("delete", `HKCU\Environment`, "/v", name, "/f") // ignore "not found"
	return nil
}

func runReg(args ...string) error {
	out, err := exec.Command("reg", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("usageshim: reg %v: %w: %s", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// parseRegValue extracts a value from `reg query` output. Lines look like:
//
//	Path    REG_EXPAND_SZ    C:\a;C:\b
//
// The value is everything after the REG_* type token, so values with spaces survive.
func parseRegValue(out, name string) string {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 3 && strings.EqualFold(fields[0], name) && strings.HasPrefix(fields[1], "REG_") {
			idx := strings.Index(line, fields[1]) + len(fields[1])
			return strings.TrimSpace(line[idx:])
		}
	}
	return ""
}
