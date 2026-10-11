// Package usageshim installs and removes the optional "sops" usage-reporter shim
// for the CURRENT user on this machine, straight from the panel - no manual steps.
//
// What it does: it materializes the embedded wrapper scripts (see package shims)
// into a managed directory under the data dir, then wires discovery so a bare
// `sops` command resolves to the wrapper - on Windows by prepending the directory
// to the User PATH and setting two helper variables in HKCU\Environment; on Linux by
// writing an executable `sops` wrapper and managing a single marked block in the
// user's ~/.bashrc. Uninstall reverses every step and deletes the directory.
//
// It is per-user and needs NO admin rights; it never edits machine/system scope. The
// shim only reports usage to the panel and then runs the real sops - it carries no
// key material.
//
// SAFETY: the OS-specific environment edits are isolated so they are idempotent
// (installing twice leaves one PATH entry) and fully reversible. Unit tests inject
// fakes for those edits, so running the tests never touches the real PATH, registry,
// or shell profile.
package usageshim

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sopshq/shims"
)

// Block markers delimit the section usageshim manages in a shell profile (Linux).
const (
	blockBegin = "# >>> sopshq usage shim >>>"
	blockEnd   = "# <<< sopshq usage shim <<<"
)

// Status reports whether the shim is installed for the current user on this machine.
type Status struct {
	Installed bool   // managed scripts present AND discovery wired
	Dir       string // the managed install directory
	Note      string // a short human note after install (e.g. "open a new terminal")
}

// Dir is the managed install directory for the shim, under the data dir.
func Dir(dataDir string) string { return filepath.Join(dataDir, "shim") }

// Install writes the shim scripts and wires PATH + helper env vars for the current
// user. It is idempotent.
func Install(dataDir, panelURL, tokenFile string) (Status, error) {
	return install(Dir(dataDir), panelURL, tokenFile)
}

// Uninstall removes the PATH/env wiring and deletes the managed directory. It is a
// no-op-safe if the shim is not installed.
func Uninstall(dataDir string) error { return uninstall(Dir(dataDir)) }

// Stat reports the current install status without changing anything.
func Stat(dataDir string) Status { return status(Dir(dataDir)) }

// extract writes one embedded script to dir/name with the given mode.
func extract(dir, name string, mode os.FileMode) error {
	data, err := shims.FS.ReadFile(name)
	if err != nil {
		return fmt.Errorf("usageshim: read embedded %s: %w", name, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, mode); err != nil {
		return fmt.Errorf("usageshim: write %s: %w", name, err)
	}
	return nil
}

// pathEntries splits a PATH-style string on the OS list separator, dropping empties.
func pathEntries(p string) []string {
	var out []string
	for _, e := range strings.Split(p, string(os.PathListSeparator)) {
		if strings.TrimSpace(e) != "" {
			out = append(out, e)
		}
	}
	return out
}

// samePathEntry reports whether two PATH entries refer to the same directory
// (case-insensitively on Windows).
func samePathEntry(a, b string) bool {
	ca, cb := filepath.Clean(a), filepath.Clean(b)
	if caseInsensitivePaths {
		return strings.EqualFold(ca, cb)
	}
	return ca == cb
}

// prependPath returns p with dir at the front and any existing copy removed, so it
// is idempotent (no duplicate entries).
func prependPath(p, dir string) string {
	out := []string{dir}
	for _, e := range pathEntries(p) {
		if !samePathEntry(e, dir) {
			out = append(out, e)
		}
	}
	return strings.Join(out, string(os.PathListSeparator))
}

// removePathEntry returns p with dir removed.
func removePathEntry(p, dir string) string {
	out := []string{}
	for _, e := range pathEntries(p) {
		if !samePathEntry(e, dir) {
			out = append(out, e)
		}
	}
	return strings.Join(out, string(os.PathListSeparator))
}

// upsertBlock replaces the marked block in content with body between the markers, or
// appends a fresh block if none exists. Idempotent for a given body.
func upsertBlock(content, body string) string {
	block := blockBegin + "\n" + strings.TrimRight(body, "\n") + "\n" + blockEnd
	lines := strings.Split(content, "\n")
	start, end := blockBounds(lines)
	if start >= 0 && end >= start {
		out := append([]string{}, lines[:start]...)
		out = append(out, block)
		out = append(out, lines[end+1:]...)
		return strings.Join(out, "\n")
	}
	c := content
	if c != "" && !strings.HasSuffix(c, "\n") {
		c += "\n"
	}
	if c != "" {
		c += "\n" // a blank line before our block
	}
	return c + block + "\n"
}

// removeBlock strips the marked block (and one trailing blank line) from content.
func removeBlock(content string) string {
	lines := strings.Split(content, "\n")
	start, end := blockBounds(lines)
	if start < 0 || end < start {
		return content
	}
	out := append([]string{}, lines[:start]...)
	rest := lines[end+1:]
	if len(rest) > 0 && strings.TrimSpace(rest[0]) == "" {
		rest = rest[1:] // drop the blank line we inserted before the block
	}
	out = append(out, rest...)
	return strings.Join(out, "\n")
}

// blockBounds returns the line indexes of the begin and end markers, or -1, -1.
func blockBounds(lines []string) (int, int) {
	start, end := -1, -1
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == blockBegin {
			start = i
		} else if t == blockEnd && start >= 0 {
			end = i
			break
		}
	}
	return start, end
}
