package web

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"sopshq/internal/auth"
	"sopshq/internal/keysvc"
)

// dashData drives the dashboard: the resource counts, the cached pending-changes
// state (drives the red Apply buttons and the pending list), and the most recent
// apply/sync result this session (rendered as the detailed results panel).
type dashData struct {
	Machines, OSUsers, Projects, Keys, Users int
	Generated                                int // keys that have an age keypair
	Pending                                  keysvc.PendingState
	HasPending                               bool
	Import                                   importAlert     // on-disk keys not yet in the database
	MissingFolders                           []missingFolder // local project folders that no longer exist on disk
	LastAction                               lastActionState
	HasLastAction                            bool
	Conflicts                                int // duplicate records awaiting a resolve decision
}

// keyBaseRow is one local OS user's key-store base, for the paths panel.
type keyBaseRow struct {
	Username string
	KeyBase  string
}

// pathsInfo is every folder/file and address this machine uses, shown on the
// dashboard so the operator never has to guess where things live. It lists paths
// only - never any file's contents.
type pathsInfo struct {
	NodeName    string
	ConfigPath  string
	DataDir     string
	VaultDir    string
	AuditPath   string
	PointerPath string // per-user file under the user config dir that records where the data lives
	// PointerWritten reports whether the per-user pointer actually exists on disk. A Linux
	// system install runs `init` as a service account whose HOME is the data base, so the
	// per-user pointer would land on the (locked) data volume and is deliberately skipped;
	// discovery then uses the machine-wide pointer below.
	PointerWritten     bool
	MachinePointerPath string // Linux machine-wide pointer (/etc/sopshq/location), when present; "" otherwise
	PanelListen        string
	AgentListen        string
	SopsBinary         string
	AgeBinary          string
	EnvKeyFile         string // current SOPS_AGE_KEY_FILE (a path, not a secret)
	SopsDefault        string // sops's zero-config key location for this OS
	LocalBases         []keyBaseRow
}

func (s *Server) getDashboard(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	// Visiting the dashboard nudges a fresh (background) drift check so the buttons
	// reflect reality soon after the operator lands here.
	s.refreshPendingAsync()

	d := dashData{
		Machines: len(s.store.Machines.List()),
		OSUsers:  len(s.store.OSUsers.List()),
		Projects: len(s.store.Projects.List()),
		Keys:     len(s.store.Keys.List()),
		Users:    s.userCount(),
	}
	for _, k := range s.store.Keys.List() {
		if k.Recipient != "" {
			d.Generated++
		}
	}
	// Local drift is recomputed fresh (cheap, no network); peer drift comes from the
	// background cache. A stale local entry (e.g. a just-deleted project) is gone here
	// without a manual Sync.
	st := s.livePending(r)
	d.Pending = st
	d.HasPending = st.Any()
	d.Import = s.importAlertState()
	d.MissingFolders = s.missingLocalFolders()
	d.Conflicts = s.keys.ConflictCount() + s.keys.FieldConflictCount()
	s.lastActionMu.Lock()
	la := s.lastAction
	s.lastActionMu.Unlock()
	if la.When != 0 {
		d.LastAction = la
		d.HasLastAction = true
	}
	s.render(w, r, "dashboard", sess, "Dashboard", d, http.StatusOK)
}

// pathsInfo gathers the folders and addresses this machine uses.
func (s *Server) pathsInfo() pathsInfo {
	p := pathsInfo{
		NodeName:    s.nodeName,
		ConfigPath:  s.cfg.Path(),
		DataDir:     s.cfg.DataDir,
		VaultDir:    s.cfg.VaultDir,
		AuditPath:   s.audit.Path(),
		PanelListen: s.cfg.PanelListen,
		AgentListen: s.cfg.AgentListen,
		EnvKeyFile:  strings.TrimSpace(os.Getenv("SOPS_AGE_KEY_FILE")),
		SopsDefault: sopsDefaultKeyPath(),
		SopsBinary:  lookPathOr("sops"),
		AgeBinary:   lookPathOr("age-keygen"),
	}
	perUser := userConfigPointerPath()
	p.PointerPath = perUser
	p.PointerWritten = fileExists(perUser)
	if m := machinePointerPath(); fileExists(m) {
		p.MachinePointerPath = m
	}
	localID := s.keys.LocalMachine()
	for _, u := range s.store.OSUsers.List() {
		if u.MachineID == localID {
			p.LocalBases = append(p.LocalBases, keyBaseRow{Username: u.Username, KeyBase: s.keys.UserKeyBase(u)})
		}
	}
	return p
}

// userConfigPointerPath is the per-user file that records where the data lives (so a
// later run finds the install even when the data sits on a locked encrypted volume). It
// mirrors cmd/sopshq's pointerFile(): <user config dir>/sopshq/location (e.g.
// %AppData%\sopshq\location on Windows, ~/.config/sopshq/location on Linux). Empty if the
// user config dir is unknown. It is only WRITTEN when it lands outside the data base; a
// Linux system install skips it (see PointerWritten) and relies on machinePointerPath.
func userConfigPointerPath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "sopshq", "location")
	}
	return ""
}

// machinePointerPath is the fixed machine-wide install pointer a Linux system install
// writes (via `sopshq setup`), so a bare run finds the install regardless of which
// user's home the per-user pointer landed in. It mirrors cmd/sopshq's machinePointerFile.
// Empty on non-Linux, which has no machine-wide pointer.
func machinePointerPath() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return "/etc/sopshq/location"
}

// fileExists reports whether p names an existing file. An empty path is not a file.
func fileExists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

// sopsDefaultKeyPath is where sops looks for an age key with no env var set:
// %AppData%\sops\age\keys.txt on Windows, ~/.config/sops/age/keys.txt on Linux.
func sopsDefaultKeyPath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "sops", "age", "keys.txt")
	}
	return ""
}

// lookPathOr returns the resolved path of a binary, or a clear "not found" note.
func lookPathOr(bin string) string {
	if p, err := exec.LookPath(bin); err == nil {
		return p
	}
	return "(not found on PATH)"
}
