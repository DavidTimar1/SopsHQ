// Package config loads SopsHQ's on-disk configuration and node identity.
//
// The config file is JSONC (JSON with // and /* */ comments) because SopsHQ
// authors and reads it itself, and inline comments keep the operator oriented.
// Comments are stripped before the standard library json parser sees the bytes.
//
// "Node identity" is the stable id that distinguishes this machine from its peer
// in the multi-master cluster. It is generated once (crypto/rand) on first run
// and then persisted in the config, so a machine keeps the same id across
// restarts and its oplog/HLC stamps stay attributable.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"sopshq/internal/store"
)

// configHeader is prepended to every written config so the operator can see, in
// the file itself, which fields to edit (notably the ports). The loader strips
// comments, so this round-trips. Comments a user adds by hand are NOT preserved
// when SopsHQ rewrites the file.
const configHeader = `// SopsHQ configuration (JSONC: // and /* */ comments are allowed).
//
// To change the PORTS, edit these two fields and restart SopsHQ:
//   "panel_listen" - the web admin panel        (default 127.0.0.1:8770)
//   "agent_listen" - the machine-to-machine agent + replication (default 127.0.0.1:8443)
// Each is a "host:port". The panel is served over plain HTTP - reach it on
// loopback via an SSH tunnel, or over Tailscale. When "panel_listen"/"agent_listen"
// is left on loopback (127.0.0.1) and this host is on Tailscale, the listener binds
// the host's Tailscale address automatically (tailnet-only, WireGuard-encrypted,
// never a public interface), so other machines reach it at the host's stable Tailscale
// IP, http://100.x.y.z:<port>. Do NOT bind 0.0.0.0 on a host with a public
// IP - that would expose it publicly. The agent serves plain HTTP too, authenticated
// by the shared transfer key set in the panel (stored sealed below).
//
// "node_id" is generated - do not edit. "local_machine_id" is set from the panel.
//
// "release_repo" is the GitHub repository ("OWNER/REPO") that "sopshq update" downloads
// releases from. It is optional: the SOPSHQ_RELEASE_REPO environment variable
// outranks it, and "sopshq update" asks for it once when neither is set.
//
// Backups (schedule, destinations, filename, the sealed backup password) are
// configured in the panel under Settings, not here.
//
// "audit_retention" caps how long the audit log is kept on THIS machine:
//   "days_to_keep" - remove entries older than this many days (0 = keep forever).
//   "action"       - "export_then_purge" (archive removed entries first, then delete)
//                    or "purge" (delete outright). Set it in the panel under Settings.
//
// "permission_map" controls the Linux filesystem permission auditor (off by default):
//   "enabled"   - master switch; enabling it in the panel first checks the scan user.
//   "scan_user" - a dedicated, locked-down Linux user the read-only scan runs as.
//   "roots"     - the directory roots to scan. Manage all of this in the panel.
//
// "keybase_root" is an OPTIONAL absolute directory (an encrypted volume is
// recommended) under which each OS user's key store lives at
// "<keybase_root>/<username>/keys.txt", on Linux and Windows alike. When set, an OS
// user created with a BLANK keystore path is stored with no key_base of its own and
// its store is derived from this root. On Linux the root is owned by the SopsHQ
// service account and SopsHQ grants each user read on their own key via POSIX ACLs
// (setfacl), never letting one user read another's; SopsHQ never creates the
// directory - create it once as root (0711 = traverse only):
//   sudo mkdir -p <keybase_root> && sudo chown <sopshq-user> <keybase_root> && sudo chmod 0711 <keybase_root>
// On Windows no ACLs are applied (the one SopsHQ account owns the subtree); create
// the folder before serving. It is MACHINE-LOCAL (never replicated), so each machine
// may use a different root. Empty = keys live under each user's home (the default).
// Must be an absolute path, distinct from "data_dir". Set it at install time with
// ` + "`sopshq install -keys <path>`" + ` (Windows) or during ` + "`sopshq setup`" + ` (Linux).
`

// Audit-retention actions. AuditActionExportThenPurge archives the entries that
// will be removed to a timestamped file before deleting them; AuditActionPurge
// deletes them outright. An empty action is treated as the safer export-then-purge.
const (
	AuditActionPurge           = "purge"
	AuditActionExportThenPurge = "export_then_purge"
)

// AuditRetention is this machine's policy for trimming the audit log. It is a
// per-machine setting (each machine keeps its own history), so it lives in the
// config file rather than the replicated store.
type AuditRetention struct {
	// DaysToKeep removes audit entries older than this many days. 0 keeps the log
	// forever (no automatic removal).
	DaysToKeep int `json:"days_to_keep"`
	// Action chooses what happens to entries past the limit: AuditActionPurge or
	// AuditActionExportThenPurge. Empty is treated as export-then-purge.
	Action string `json:"action"`
}

// DefaultPermMapRoots is the proposed default set of directory roots for the
// permission map: the places a SopsHQ operator most likely keeps user data,
// service config, web roots, and locally-installed software. Pseudo-filesystems
// (/proc, /sys, /dev, /run, /tmp), container layers, and snap mounts are
// deliberately omitted - they are noisy and not operator-owned.
var DefaultPermMapRoots = []string{
	"/home", "/etc", "/srv", "/opt", "/var/www", "/usr/local", "/root",
}

// DefaultScanUser is the suggested name for the dedicated, locked-down Linux user
// the permission scan runs as (no login, no SSH, sudo limited to the read-only
// collectors). The operator may rename it; this is only the panel's default.
const DefaultScanUser = "sopshq-scan"

// PermMap is this machine's configuration for the read-only filesystem permission
// auditor. It is a per-machine setting (the scan and its data are machine-local
// and never replicated), so it lives in the config file rather than the store.
//
// The feature is OFF by default. Enabling it requires a dedicated, locked-down
// Linux user (ScanUser) that the scan runs as via sudo; the panel checks that the
// user exists and can run the collectors before it lets Enabled become true.
type PermMap struct {
	// Enabled is the master switch. When false, no scan runs and the panel page
	// shows the setup instructions instead of any map data.
	Enabled bool `json:"enabled"`
	// ScanUser is the dedicated Linux user the read-only scan runs as (sudo -u).
	// It must exist and be permitted (via a tight sudoers rule) to run find,
	// getfacl, and getcap before the feature can be enabled.
	ScanUser string `json:"scan_user"`
	// Roots are the directory roots to scan. Empty means DefaultPermMapRoots.
	Roots []string `json:"roots"`
}

// EffectiveRoots returns the configured roots, or DefaultPermMapRoots when none
// are set, so a freshly-enabled feature scans a sensible default.
func (p PermMap) EffectiveRoots() []string {
	if len(p.Roots) == 0 {
		return DefaultPermMapRoots
	}
	return p.Roots
}

// Config is the full on-disk configuration. Paths default sensibly per OS and
// may be overridden by the operator.
type Config struct {
	// NodeID is the stable, generated identity for this machine. Do not edit.
	NodeID string `json:"node_id"`
	// NodeName is a human label for this machine; defaults to the hostname.
	NodeName string `json:"node_name"`
	// LocalMachineID links this running node to a Machine record in the store, so
	// the key engine knows which placements/projects are "local". Set from the
	// panel (Machines -> "this is the local machine"). Empty until designated.
	LocalMachineID string `json:"local_machine_id"`
	// DataDir holds the JSON store, oplog, and audit log. An encrypted volume is
	// recommended for at-rest protection of the (already-sealed) blobs.
	DataDir string `json:"data_dir"`
	// VaultDir holds the vault metadata (salt, iterations, verifier). Usually the
	// same as DataDir; separated for flexibility.
	VaultDir string `json:"vault_dir"`
	// KeybaseRoot is an OPTIONAL absolute directory under which each OS user's key
	// store lives at "<keybase_root>/<username>/keys.txt". A local OS user with no
	// explicit keystore path of their own resolves here. On Linux the root is owned
	// by the SopsHQ service account and SopsHQ applies POSIX ACLs so each user - and
	// only that user - can read their own key. On Windows no ACLs are applied (a
	// single-user keys root); the folder must exist. Empty (the default) keeps keys
	// under each user's home. It is MACHINE-LOCAL and never replicated, so each
	// machine may use a different root. When set it must be an absolute path,
	// distinct from data_dir.
	KeybaseRoot string `json:"keybase_root"`
	// PanelListen is the address the web admin panel binds (e.g. "127.0.0.1:8770").
	// The panel is served over plain HTTP; a loopback value auto-binds the host's
	// Tailscale address when present (tailnet-only). Reach it via an SSH tunnel or
	// over Tailscale - do not bind 0.0.0.0 on a host with a public IP.
	PanelListen string `json:"panel_listen"`
	// AgentListen is the address the agent + replication endpoints bind. Should be
	// a Tailscale-only address in production.
	AgentListen string `json:"agent_listen"`
	// AuditRetention is this machine's audit-log trimming policy (per-machine, so it
	// stays in the config rather than the replicated store).
	AuditRetention AuditRetention `json:"audit_retention"`
	// PermissionMap is this machine's filesystem permission auditor configuration
	// (per-machine, machine-local data, so it stays in the config rather than the
	// replicated store). Off by default.
	PermissionMap PermMap `json:"permission_map"`
	// TransferKeySealed is the VAULT-SEALED ciphertext of the cluster transfer key -
	// the shared secret that authenticates machine-to-machine sync. It is set from
	// the panel (the same key on every machine), unsealed in memory at serve, and
	// never stored or logged in the clear. Empty until set (then no peer sync).
	TransferKeySealed string `json:"transfer_key_sealed,omitempty"`
	// ReleaseRepo is the GitHub repository ("OWNER/REPO") `sopshq update` downloads
	// releases from. Machine-local. Empty until set; the SOPSHQ_RELEASE_REPO
	// environment variable outranks it.
	ReleaseRepo string `json:"release_repo,omitempty"`

	// path is where this config was loaded from / will be saved to.
	path string
}

// ErrNotFound indicates no config file exists at the given path yet.
var ErrNotFound = errors.New("config: file not found")

// Load reads and parses the JSONC config at path. It returns ErrNotFound if the
// file does not exist (the caller can then call Default + Save to scaffold one).
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("config: read: %w", err)
	}
	var c Config
	if err := json.Unmarshal(stripJSONC(raw), &c); err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}
	c.path = path
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Default builds a config with generated identity and OS-appropriate defaults,
// rooted at dir for its data and vault. It does not write anything; call Save.
func Default(path, dir, hostname string) *Config {
	if hostname == "" {
		hostname = "sopshq-node"
	}
	return &Config{
		NodeID:      store.NewID(),
		NodeName:    hostname,
		DataDir:     filepath.Join(dir, "data"),
		VaultDir:    filepath.Join(dir, "data"),
		PanelListen: "127.0.0.1:8770",
		AgentListen: "127.0.0.1:8443",
		// Keep the audit log forever by default; export-then-purge is the safer
		// action once the operator sets a day limit in the panel.
		AuditRetention: AuditRetention{DaysToKeep: 0, Action: AuditActionExportThenPurge},
		// The permission auditor is off until the operator enables it (and provisions
		// the dedicated scan user). The scan-user name and roots default sensibly.
		PermissionMap: PermMap{Enabled: false, ScanUser: DefaultScanUser},
		path:          path,
	}
}

// Save writes the config back to its path as commented JSONC (0600). The header
// (configHeader) documents the editable fields; comments a user adds by hand are
// not preserved across a Save.
func (c *Config) Save() error {
	if c.path == "" {
		return errors.New("config: no path set")
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return fmt.Errorf("config: mkdir: %w", err)
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	doc := append([]byte(configHeader), b...)
	doc = append(doc, '\n')
	return writeAtomic(c.path, doc)
}

// writeAtomic writes doc to path through a sibling temp file and a rename. The temp file
// is created exclusively after removing whatever stood at its name, and a symlink there
// is removed rather than followed: the config folder belongs to the unprivileged service
// account, so a root caller (sopshq update saving release_repo) must never write through
// a link that account planted. The new file takes the owner of the file it replaces, so
// a root caller does not lock the service account out of its own config.
func writeAtomic(path string, doc []byte) error {
	// A config that is a symlink or any other non-regular file is never replaced: the
	// rename would swap that link for a plain file the operator did not expect.
	existing, lerr := os.Lstat(path)
	if lerr == nil && !existing.Mode().IsRegular() {
		return fmt.Errorf("config: %s is not a regular file; refusing to replace it", path)
	}
	if lerr != nil && !os.IsNotExist(lerr) {
		return fmt.Errorf("config: stat %s: %w", path, lerr)
	}
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("config: clear %s: %w", tmp, err)
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("config: write: %w", err)
	}
	if lerr == nil {
		matchOwner(f, existing)
	}
	_, werr := f.Write(doc)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(tmp)
		return fmt.Errorf("config: write: %w", werr)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("config: rename: %w", err)
	}
	return nil
}

// Path returns where the config lives on disk.
func (c *Config) Path() string { return c.path }

// validate checks the invariants the rest of the program relies on, including
// that the listen addresses are well-formed "host:port" so a typo'd port is
// caught at load with a clear message rather than as a confusing bind failure.
func (c *Config) validate() error {
	switch {
	case c.NodeID == "":
		return errors.New("config: missing node_id")
	case c.DataDir == "":
		return errors.New("config: missing data_dir")
	case c.VaultDir == "":
		return errors.New("config: missing vault_dir")
	case c.PanelListen == "":
		return errors.New("config: missing panel_listen")
	case c.AgentListen == "":
		return errors.New("config: missing agent_listen")
	}
	if err := validateListen("panel_listen", c.PanelListen); err != nil {
		return err
	}
	if err := validateListen("agent_listen", c.AgentListen); err != nil {
		return err
	}
	if c.AuditRetention.DaysToKeep < 0 {
		return fmt.Errorf("config: audit_retention.days_to_keep %d must be >= 0", c.AuditRetention.DaysToKeep)
	}
	switch c.AuditRetention.Action {
	case "", AuditActionPurge, AuditActionExportThenPurge:
	default:
		return fmt.Errorf("config: audit_retention.action %q must be %q or %q",
			c.AuditRetention.Action, AuditActionPurge, AuditActionExportThenPurge)
	}
	if c.PermissionMap.Enabled && c.PermissionMap.ScanUser == "" {
		return errors.New("config: permission_map.enabled requires permission_map.scan_user")
	}
	if c.KeybaseRoot != "" {
		if !filepath.IsAbs(c.KeybaseRoot) {
			return fmt.Errorf("config: keybase_root %q must be an absolute path", c.KeybaseRoot)
		}
		if c.KeybaseRoot == c.DataDir {
			return errors.New("config: keybase_root must be a DIFFERENT path than data_dir")
		}
	}
	return nil
}

// validateListen checks that addr is a "host:port" with a valid port (1-65535).
// An empty host is allowed (binds all interfaces). Field is the config key, used
// in the error so the operator knows which line to fix.
func validateListen(field, addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("config: %s %q must be \"host:port\" (e.g. 127.0.0.1:8770): %w", field, addr, err)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("config: %s has an invalid port %q (must be 1-65535)", field, port)
	}
	return nil
}

// stripJSONC removes // line comments and /* */ block comments while preserving
// their bytes inside string literals, so JSONC parses as JSON. It is a small,
// dependency-free scanner; it does not validate JSON (the json package does).
func stripJSONC(in []byte) []byte {
	out := make([]byte, 0, len(in))
	var inStr, esc, lineComment, blockComment bool
	for i := 0; i < len(in); i++ {
		ch := in[i]
		switch {
		case lineComment:
			if ch == '\n' {
				lineComment = false
				out = append(out, ch)
			}
		case blockComment:
			if ch == '*' && i+1 < len(in) && in[i+1] == '/' {
				blockComment = false
				i++
			}
		case inStr:
			out = append(out, ch)
			switch {
			case esc:
				esc = false
			case ch == '\\':
				esc = true
			case ch == '"':
				inStr = false
			}
		case ch == '"':
			inStr = true
			out = append(out, ch)
		case ch == '/' && i+1 < len(in) && in[i+1] == '/':
			lineComment = true
			i++
		case ch == '/' && i+1 < len(in) && in[i+1] == '*':
			blockComment = true
			i++
		default:
			out = append(out, ch)
		}
	}
	return out
}
