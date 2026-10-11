//go:build linux

package usageshim

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sopshq/shims"
)

// caseInsensitivePaths reports that Linux PATH entries compare case-sensitively.
const caseInsensitivePaths = false

// profilePath is the shell rc file the managed block lives in. Overridable in tests
// so they write to a temp HOME and never touch the real ~/.bashrc.
var profilePath = defaultProfilePath

func defaultProfilePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".bashrc"
	}
	return filepath.Join(home, ".bashrc")
}

func install(dir, panelURL, tokenFile string) (Status, error) {
	if err := writeScripts(dir); err != nil {
		return Status{}, err
	}
	rc := profilePath()
	content, err := os.ReadFile(rc)
	if err != nil && !os.IsNotExist(err) {
		return Status{}, fmt.Errorf("usageshim: read %s: %w", rc, err)
	}
	updated := upsertBlock(string(content), shimBody(dir, panelURL, tokenFile))
	if err := os.WriteFile(rc, []byte(updated), 0o644); err != nil {
		return Status{}, fmt.Errorf("usageshim: write %s: %w", rc, err)
	}
	return Status{Installed: true, Dir: dir,
		Note: "Open a new shell, or run: source " + rc}, nil
}

func uninstall(dir string) error {
	rc := profilePath()
	if content, err := os.ReadFile(rc); err == nil {
		_ = os.WriteFile(rc, []byte(removeBlock(string(content))), 0o644)
	}
	return os.RemoveAll(dir)
}

func status(dir string) Status {
	st := Status{Dir: dir}
	if _, err := os.Stat(filepath.Join(dir, "sops")); err != nil {
		return st
	}
	if content, err := os.ReadFile(profilePath()); err == nil && strings.Contains(string(content), blockBegin) {
		st.Installed = true
	}
	return st
}

// writeScripts installs the wrapper AS `sops` (executable) in dir, since on Linux a
// bare script can be invoked directly by name.
func writeScripts(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("usageshim: mkdir %s: %w", dir, err)
	}
	data, err := shims.FS.ReadFile(shims.WrapperSh)
	if err != nil {
		return fmt.Errorf("usageshim: read embedded wrapper: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sops"), data, 0o755); err != nil {
		return fmt.Errorf("usageshim: write sops wrapper: %w", err)
	}
	return nil
}

// shimBody is the exported PATH + helper vars written into the managed rc block.
func shimBody(dir, panelURL, tokenFile string) string {
	return fmt.Sprintf("export PATH=%q:\"$PATH\"\nexport SOPSHQ_PANEL_URL=%q\nexport SOPSHQ_INGEST_TOKEN_FILE=%q",
		dir, panelURL, tokenFile)
}
