//go:build linux

package place

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// envName is the environment variable sops reads to locate the key file.
const envName = "SOPS_AGE_KEY_FILE"

// bashrcMarker tags the ~/.bashrc line SopsHQ owns, so a re-run rewrites that one line
// instead of appending a duplicate.
const bashrcMarker = "# sopshq:sops-age"

// caseInsensitiveFS reports that Linux paths compare case-sensitively.
const caseInsensitiveFS = false

// readKeyFile reads a key-store file with a size cap (the 0600 mode does not block the
// owning process from reading). The cap keeps a KeyBase pointed at a huge file from
// being loaded whole on the render-path scan.
func readKeyFile(path string) ([]byte, error) { return ReadCappedFile(path) }

// currentEnvKeyFile returns SOPS_AGE_KEY_FILE as the running process sees it.
//
// On Linux the operator's persisted value lives in ~/.bashrc under the
// "# sopshq:sops-age" marker, which only interactive shells load; a service
// process may not have it exported. We therefore report only what the process
// actually has in its environment. The bashrc line itself is managed idempotently
// by setBashrcExport (it rewrites its OWN marked line and leaves others alone), so
// SopsHQ never clobbers an unrelated export there. Non-destructive read.
func currentEnvKeyFile() string {
	return strings.TrimSpace(os.Getenv("SOPS_AGE_KEY_FILE"))
}

// restrictKeyFile re-asserts mode 0600 on keys.txt (owner read/write only).
func restrictKeyFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod 600: %w", err)
	}
	return nil
}

// configureDiscovery wires sops discovery on Linux:
//
//   - export SOPS_AGE_KEY_FILE="<base>/keys.txt" under the marker in ~/.bashrc
//     (for interactive shells), and
//   - symlink ~/.config/sops/age/keys.txt -> the key (for non-interactive
//     contexts: cron, systemd, ssh 'cmd', which never read ~/.bashrc).
//
// The target user's home (where ~/.bashrc and ~/.config/sops/age live) is derived
// from Username; with no Username it falls back to the home of the process user (the
// common local case where the panel already runs as that account). If Username is set
// and the process is root, ownership of the created files is handed to that user.
func configureDiscovery(o Opts) error {
	if effectsDisabled {
		return nil
	}
	home, err := resolveHome(o.Username)
	if err != nil {
		return fmt.Errorf("place: resolve home: %w", err)
	}
	keyFile := KeyFile(o.Base)
	if err := setBashrcExport(home, keyFile); err != nil {
		return err
	}
	if err := linkDefaultPath(home, keyFile); err != nil {
		return err
	}
	if o.Username != "" && os.Geteuid() == 0 {
		return chownToUser(o)
	}
	return nil
}

// EnsureDiscovery repairs ONLY the sops-discovery artifacts that are missing or
// broken for one keystore, and never clobbers a deliberate different setup:
//
//   - the SOPS_AGE_KEY_FILE export under the marker in ~/.bashrc, and
//   - the ~/.config/sops/age/keys.txt symlink.
//
// It is idempotent and safe to call repeatedly, including in the reuse/adopt path
// where the operator may have kept a custom pointer (a conflict is left in place and
// reported, not overwritten). It uses only o.Base and o.Username (no key material).
//
// For a cross-user shared-root keystore (the target is not the process user) it returns a
// benign "not applicable" report WITHOUT reading the target user's home: that user reaches
// their key through a POSIX ACL, not a home export/symlink. The base is still validated
// first, so an unsafe base is refused regardless of who the target is.
func EnsureDiscovery(o Opts) DiscoveryReport {
	if err := discoveryBaseOK(o.Base); err != nil {
		return refusedReport(err)
	}
	if self, serr := isSelfPlacement(o); serr != nil || !self {
		return notApplicableReport()
	}
	home, env, link, err := gatherDiscoveryFacts(o)
	if err != nil {
		return DiscoveryReport{Items: []DiscoveryItem{{Artifact: "discovery", State: DiscoveryError, Detail: err.Error()}}}
	}
	keyFile := KeyFile(o.Base)
	eff := discoveryEffects{
		envName:  envName,
		linkKind: "symlink",
		setEnv: func(v string) error {
			if effectsDisabled {
				return nil
			}
			return setBashrcExport(home, v)
		},
		setLink: func() error {
			if effectsDisabled {
				return nil
			}
			return linkDefaultPath(home, keyFile)
		},
	}
	return applyEnsure(env, link, eff)
}

// InspectDiscovery reports how sops discovery is currently wired for a keystore,
// WITHOUT changing anything. It is the read-only view behind the panel's discovery
// status line.
//
// For a cross-user shared-root keystore (the target is not the process user) it reports
// "not applicable" WITHOUT reading the target user's home: that user reaches their key
// through a POSIX ACL, so there is no home export/symlink to inspect.
func InspectDiscovery(o Opts) DiscoveryStatus {
	if self, err := isSelfPlacement(o); err != nil || !self {
		return notApplicableStatus(envName, "symlink")
	}
	st := DiscoveryStatus{EnvName: envName, LinkKind: "symlink"}
	_, env, link, err := gatherDiscoveryFacts(o)
	if err != nil {
		st.Verdict = VerdictNotWired
		return st
	}
	return fillStatus(st, env, link)
}

// gatherDiscoveryFacts reads the current, non-destructive state of both discovery
// artifacts for a keystore. On Linux the authoritative SOPS_AGE_KEY_FILE value is
// the one persisted under the marker in ~/.bashrc (interactive shells load it);
// the symlink lives at ~/.config/sops/age/keys.txt.
func gatherDiscoveryFacts(o Opts) (home string, env envFacts, link linkFacts, err error) {
	home, err = resolveHome(o.Username)
	if err != nil {
		return "", envFacts{}, linkFacts{}, fmt.Errorf("place: resolve home: %w", err)
	}
	keyFile := KeyFile(o.Base)

	env = envFacts{current: readBashrcExport(home), want: keyFile}
	env.currentExists = fileExists(env.current)

	linkPath := filepath.Join(home, ".config", "sops", "age", "keys.txt")
	link = linkFacts{want: keyFile, path: linkPath}
	if samePath(linkPath, keyFile) {
		link.selfSame = true
		return home, env, link, nil
	}
	if _, lerr := os.Lstat(linkPath); lerr == nil {
		link.exists = true
		if tgt, rerr := os.Readlink(linkPath); rerr == nil {
			link.target = tgt
		}
		if _, serr := os.Stat(linkPath); serr == nil {
			link.targetExists = true
		}
	}
	return home, env, link, nil
}

// readBashrcExport returns the SOPS_AGE_KEY_FILE value persisted under the marker in
// <home>/.bashrc, or "" when the marked export is absent. It mirrors the shape
// setBashrcExport writes (export SOPS_AGE_KEY_FILE=%q on the line after the marker).
func readBashrcExport(home string) string {
	data, err := os.ReadFile(filepath.Join(home, ".bashrc"))
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	const prefix = "export " + envName + "="
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != bashrcMarker || i+1 >= len(lines) {
			continue
		}
		next := strings.TrimSpace(lines[i+1])
		if !strings.HasPrefix(next, prefix) {
			return ""
		}
		raw := strings.TrimPrefix(next, prefix)
		if uq, uerr := strconv.Unquote(raw); uerr == nil {
			return uq
		}
		return strings.Trim(raw, `"`)
	}
	return ""
}

// resolveHome returns username's home directory, or the process user's home when
// username is empty (a local placement for the account SopsHQ already runs as).
func resolveHome(username string) (string, error) {
	if username != "" {
		u, err := user.Lookup(username)
		if err != nil {
			return "", fmt.Errorf("lookup user %s: %w", username, err)
		}
		return u.HomeDir, nil
	}
	return os.UserHomeDir()
}

// setBashrcExport appends or updates the SOPS_AGE_KEY_FILE export under the
// marker in <home>/.bashrc.
func setBashrcExport(home, keyFile string) error {
	bashrc := filepath.Join(home, ".bashrc")
	exportLine := fmt.Sprintf("export SOPS_AGE_KEY_FILE=%q", keyFile)

	data, err := os.ReadFile(bashrc)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read .bashrc: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	out := make([]string, 0, len(lines)+2)
	replaced := false
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == bashrcMarker {
			out = append(out, lines[i])
			// The next line is our managed export; replace it.
			out = append(out, exportLine)
			replaced = true
			if i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "export SOPS_AGE_KEY_FILE=") {
				i++ // skip the old export
			}
			continue
		}
		out = append(out, lines[i])
	}
	if !replaced {
		if len(out) > 0 && out[len(out)-1] != "" {
			out = append(out, "")
		}
		out = append(out, bashrcMarker, exportLine)
	}
	if err := os.WriteFile(bashrc, []byte(strings.Join(out, "\n")), 0o644); err != nil {
		return fmt.Errorf("write .bashrc: %w", err)
	}
	return nil
}

// linkDefaultPath symlinks ~/.config/sops/age/keys.txt -> keyFile.
func linkDefaultPath(home, keyFile string) error {
	dir := filepath.Join(home, ".config", "sops", "age")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir sops config: %w", err)
	}
	link := filepath.Join(dir, "keys.txt")
	if keyFile == link {
		return nil
	}
	_ = os.Remove(link) // replace any stale link
	if err := os.Symlink(keyFile, link); err != nil {
		return fmt.Errorf("symlink default path: %w", err)
	}
	return nil
}

// chownToUser hands the key store and config link to the target user (root only).
func chownToUser(o Opts) error {
	u, err := user.Lookup(o.Username)
	if err != nil {
		return fmt.Errorf("lookup user %s: %w", o.Username, err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	for _, p := range []string{o.Base, KeyFile(o.Base), PubFile(o.Base)} {
		if err := os.Chown(p, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", p, err)
		}
	}
	return nil
}
