package web

import (
	"errors"
	"fmt"
	"net/http"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"time"

	"sopshq/internal/audit"
	"sopshq/internal/auth"
	"sopshq/internal/keysetup"
	"sopshq/internal/keysvc"
	"sopshq/internal/model"
	"sopshq/internal/place"
	"sopshq/internal/store"
	"sopshq/internal/transport"
)

// guardPost validates CSRF for a mutating request; on failure it redirects back.
func (s *Server) guardPost(w http.ResponseWriter, r *http.Request, sess auth.Session, back string) bool {
	if err := r.ParseForm(); err != nil {
		redirect(w, r, back, "Bad form data.", true)
		return false
	}
	if !s.checkCSRF(r, sess) {
		s.audit.Record(sess.Username, "csrf_reject", r.URL.Path, audit.Denied, "")
		redirect(w, r, back, "Security check failed; please retry.", true)
		return false
	}
	return true
}

// machineNames maps machine UUID -> display name for cross-referencing.
func (s *Server) machineNames() map[string]string {
	m := map[string]string{}
	for _, mc := range s.store.Machines.List() {
		m[mc.M.UUID] = mc.Name
	}
	return m
}

// ---- machines -------------------------------------------------------------

// PeerStatus is one peer's live reachability plus its last replication-pull
// outcome, shown per row on the Machines page. It carries no secret.
type PeerStatus struct {
	MachineID    string // which machine this describes
	Reachable    bool   // the peer agent answered a ping
	Version      string // peer-reported version (when reachable)
	LastSyncUnix int64  // last pull attempt time (0 = none this run)
	Applied      int    // records applied on the last pull
	Conflicts    int    // last-writer-wins conflicts on the last pull
	Err          string // why the peer is not syncing (unreachable, no address, ...)
}

func (s *Server) listMachines(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	status := map[string]PeerStatus{}
	if s.peerStatusFn != nil {
		for _, ps := range s.peerStatusFn() {
			status[ps.MachineID] = ps
		}
	}
	// Reinstall candidates for a Pending peer: the confirmed, non-local peers it
	// could be a reinstall of. Empty when there is only one such peer choice.
	candidates := s.keys.ReinstallCandidates("")
	data := struct {
		Machines       []*model.Machine
		LocalID        string
		ThisAgentURL   string
		TransferKeySet bool
		Status         map[string]PeerStatus
		Candidates     []*model.Machine
	}{s.store.Machines.List(), s.keys.LocalMachine(), thisAgentURL(s.cfg.AgentListen), s.cfg.TransferKeySealed != "", status, candidates}
	s.render(w, r, "machines", sess, "Machines", data, http.StatusOK)
}

// confirmNewPeer accepts a Pending peer as a distinct new machine (not a reinstall).
func (s *Server) confirmNewPeer(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/machines") {
		return
	}
	id := r.PathValue("id")
	if err := s.keys.ConfirmNewPeer(id, sess.Username); err != nil {
		redirect(w, r, "/machines", "Peer not found.", true)
		return
	}
	s.reconcileCluster()
	s.refreshPendingAsync()
	redirect(w, r, "/machines", "Peer confirmed as a new machine.", false)
}

// confirmReinstallPeer resolves a Pending peer as a reinstall of an existing,
// confirmed, non-local peer: the new install is merged into that peer's identity.
func (s *Server) confirmReinstallPeer(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/machines") {
		return
	}
	id := r.PathValue("id")
	target := strings.TrimSpace(r.FormValue("target"))
	if target == "" {
		redirect(w, r, "/machines", "Choose which existing peer this is a reinstall of.", true)
		return
	}
	if err := s.keys.ConfirmReinstallPeer(id, target, sess.Username); err != nil {
		if errors.Is(err, keysvc.ErrReinstallTargetInvalid) {
			redirect(w, r, "/machines", "Choose an existing, confirmed, non-local peer to adopt.", true)
			return
		}
		redirect(w, r, "/machines", "Peer not found.", true)
		return
	}
	s.reconcileCluster()
	s.refreshPendingAsync()
	redirect(w, r, "/machines", "Peer merged into the existing machine it reinstalls.", false)
}

func (s *Server) createMachine(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/machines") {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	os := model.OS(r.FormValue("os"))
	if name == "" || (os != model.OSLinux && os != model.OSWindows) {
		redirect(w, r, "/machines", "Name and a valid OS are required.", true)
		return
	}
	// A machine NAME is the cluster-wide identity operators refer to, so a peer add
	// must never mint a second record for one that already exists: reject a duplicate
	// (case-insensitive) rather than create a confusing second node.
	for _, existing := range s.store.Machines.List() {
		if strings.EqualFold(strings.TrimSpace(existing.Name), name) {
			redirect(w, r, "/machines", fmt.Sprintf("A peer named %q already exists.", name), true)
			return
		}
	}
	port, _ := strconv.Atoi(r.FormValue("agent_port"))
	// The host field accepts a bare host or IP; operators often paste the panel's
	// "this machine's address" (a full URL) here, so normalize away any scheme,
	// path, or embedded port before storing a bare host the URL builder can reuse.
	host := strings.TrimSpace(r.FormValue("tailscale_host"))
	if host != "" {
		h, p, err := transport.NormalizeAgentHost(host, port)
		if err != nil {
			redirect(w, r, "/machines", "Enter a valid host or IP (not a full URL) in the host field.", true)
			return
		}
		host, port = h, p
	}
	mc := &model.Machine{
		M:             model.Meta{UUID: store.NewID()},
		Name:          name,
		OS:            os,
		TailscaleHost: host,
		AgentPort:     port,
	}
	if err := s.store.Machines.Put(mc); err != nil {
		s.renderError(w, r, sess, "Could not save peer.", http.StatusInternalServerError)
		return
	}
	s.audit.Record(sess.Username, "machine_create", name, audit.OK, string(os))
	// Run the reconcile now so that, when another confirmed peer already exists, this
	// new peer is immediately held Pending for the new-vs-reinstall decision instead
	// of silently becoming a distinct machine.
	s.reconcileCluster()
	msg := "Peer added."
	if mc, err := s.store.Machines.Get(mc.M.UUID); err == nil && mc.Pending {
		msg = "Peer added. Confirm below whether it is a new peer or a reinstall of an existing one."
	}
	// A shared advertised address is allowed (the name is the identity) but usually a
	// mistake, so note it without blocking.
	if host != "" {
		for _, existing := range s.store.Machines.List() {
			if existing.M.UUID != mc.M.UUID && existing.TailscaleHost == host {
				msg += " Note: " + existing.Name + " already advertises the same address."
				break
			}
		}
	}
	redirect(w, r, "/machines", msg, false)
}

func (s *Server) deleteMachine(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/machines") {
		return
	}
	id := r.PathValue("id")
	if err := s.store.Machines.Delete(id); err != nil {
		redirect(w, r, "/machines", "Machine not found.", true)
		return
	}
	s.audit.Record(sess.Username, "machine_delete", id, audit.OK, "")
	s.refreshPendingAsync()
	redirect(w, r, "/machines", "Machine removed.", false)
}

// ---- OS users -------------------------------------------------------------

type osUserRow struct {
	*model.OSUser
	MachineName string
	// Setup is the live keystore-readiness guidance for an account on THIS machine
	// (nil for accounts on another machine, which SopsHQ cannot inspect from here).
	Setup *keysetup.Plan
	// Discovery is the live sops-discovery status for an account on THIS machine with
	// a keystore base (nil otherwise). It says whether sops can actually FIND this
	// key (SOPS_AGE_KEY_FILE + junction/symlink), and backs the "Fix discovery" button.
	Discovery *place.DiscoveryStatus
}

func (s *Server) listOSUsers(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	names := s.machineNames()
	localID := s.keys.LocalMachine()
	proc := processUsername()
	var rows []osUserRow
	for _, u := range s.store.OSUsers.List() {
		row := osUserRow{OSUser: u, MachineName: names[u.MachineID]}
		if u.MachineID == localID {
			// Resolve the real store base: a root-derived user has an empty KeyBase but
			// its store is "<keybase_root>/<username>", so use the resolver, not the raw
			// field, or the setup + discovery rows would render as if it had no keystore.
			base := s.keys.UserKeyBase(u)
			own := proc != "" && strings.EqualFold(u.Username, proc)
			p := keysetup.Compute(u.Username, base, own)
			row.Setup = &p
			if base != "" {
				d := s.keys.DiscoveryStatusForOSUser(u)
				row.Discovery = &d
			}
		}
		rows = append(rows, row)
	}
	data := struct {
		Rows           []osUserRow
		Machines       []*model.Machine
		LocalID        string
		DefaultKeyBase string
		Import         importAlert
	}{rows, s.store.Machines.List(), localID, keysetup.DefaultKeyBase, s.importAlertState()}
	s.render(w, r, "osusers", sess, "OS users", data, http.StatusOK)
}

// processUsername is the bare account name SopsHQ runs as (no DOMAIN\ or path
// prefix), used to decide whether it can prepare an account's keystore itself
// (its own home) or must print the sudo commands for the operator.
func processUsername() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	name := u.Username
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// resolveKeyBase turns the OS-users form's keystore choice into a stored KeyBase.
// A "secure drive" tick replaces the keystore with the encrypted-drive folder (the
// real keys.txt lives there; the default sops location symlinks to it on placement).
// For an account on THIS machine it fills the blank default and expands a leading "~"
// using the account's real home (read unprivileged via getent); for a remote/Windows
// account it keeps what was entered. A still-unresolved "~..." is dropped so
// placement never creates a literal "~" folder - the page then prompts for a real one.
// errBadKeystorePath rejects a keystore path that could carry a shell payload into
// the printed Mode-A sudo commands (a metacharacter, control character, or leading
// dash). It is turned into a clear redirect error by createOSUser.
var errBadKeystorePath = errors.New("web: keystore path contains unsafe characters")

func (s *Server) resolveKeyBase(machineID, username, keyBaseField, secureDir string, useSecure bool) (string, error) {
	kb := strings.TrimSpace(keyBaseField)
	if useSecure {
		if sd := strings.TrimSpace(secureDir); sd != "" {
			kb = sd
		}
	}
	// Reject an unsafe path at the boundary: the value is later interpolated into a
	// sudo command the operator copies into a root shell.
	if !keysetup.ValidKeystorePath(kb) {
		return "", errBadKeystorePath
	}
	if machineID == s.keys.LocalMachine() {
		// With a shared keybase root configured, a BLANK keystore path means a
		// root-derived user: store an empty KeyBase (nothing machine-local replicates)
		// and let the resolver derive "<keybase_root>/<username>/keys.txt". Do not fill
		// the per-home default.
		if kb == "" && s.keys.KeybaseRoot() != "" {
			return "", nil
		}
		if a := keysetup.LookupAccount(username); a.Supported && a.HasHome {
			if kb == "" {
				kb = keysetup.DefaultFor(a.Home)
			} else {
				kb = keysetup.ExpandHome(kb, a.Home)
			}
		}
	}
	if strings.HasPrefix(kb, "~") {
		kb = ""
	}
	// Re-check after home expansion (the resolved path must be safe too).
	if !keysetup.ValidKeystorePath(kb) {
		return "", errBadKeystorePath
	}
	return kb, nil
}

func (s *Server) createOSUser(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/osusers") {
		return
	}
	machineID := r.FormValue("machine_id")
	username := strings.TrimSpace(r.FormValue("os_username"))
	if machineID == "" || username == "" {
		redirect(w, r, "/osusers", "Machine and username are required.", true)
		return
	}
	// The username is shown verbatim in the Mode-A sudo command block, so it must be
	// a real account name and never a shell payload.
	if !keysetup.ValidUsername(username) {
		redirect(w, r, "/osusers", "Username must be a valid account name (letters, digits, '_', '.', '-', optional trailing '$'; max 32; no spaces or symbols).", true)
		return
	}
	mc, err := s.store.Machines.Get(machineID)
	if err != nil {
		redirect(w, r, "/osusers", "Unknown machine.", true)
		return
	}
	// One OS-account record per machine: the same username on the same machine is the
	// same real account, so reject a duplicate rather than create a second row that
	// would split its keys and assignments. The comparison is OS-aware - Windows
	// account names are case-insensitive, so "Dev" and "dev" are the same account,
	// while Linux names are case-sensitive. The STORED casing is never changed (Linux
	// user.Lookup and Windows icacls both need the operator's original spelling); only
	// the duplicate check folds case.
	sameName := func(a, b string) bool {
		if mc.OS == model.OSWindows {
			return strings.EqualFold(a, b)
		}
		return a == b
	}
	for _, existing := range s.store.OSUsers.List() {
		if existing.MachineID == machineID && sameName(existing.Username, username) {
			redirect(w, r, "/osusers", fmt.Sprintf("An OS user %q already exists on this machine.", existing.Username), true)
			return
		}
	}
	keyBase, err := s.resolveKeyBase(machineID, username, r.FormValue("key_base"), r.FormValue("secure_dir"), r.FormValue("use_secure") != "")
	if err != nil {
		redirect(w, r, "/osusers", "Keystore path must be a plain folder path (no shell characters, control characters, or leading dash).", true)
		return
	}
	u := &model.OSUser{
		M:         model.Meta{UUID: store.NewID()},
		MachineID: machineID,
		Username:  username,
		KeyBase:   keyBase,
	}
	if err := s.store.OSUsers.Put(u); err != nil {
		s.renderError(w, r, sess, "Could not save OS user.", http.StatusInternalServerError)
		return
	}
	s.audit.Record(sess.Username, "osuser_create", username, audit.OK, "")

	// System-wide adopt: if this account's keystore on THIS machine already holds a
	// key.txt and the account has no key in custody yet, import that on-disk key so it
	// appears on the Keys page and is usable at once (the on-disk file is not changed).
	msg := "OS user added."
	name, count, aerr := s.keys.AdoptExistingKeyForOSUser(u.M.UUID, sess.Username)
	switch {
	case aerr != nil:
		msg += " An existing key was found but could not be imported: " + aerr.Error()
	case count == 1:
		msg += " Imported the existing key for " + username + " (" + name + ")."
	case count > 1:
		msg += " Imported " + strconv.Itoa(count) + " existing keys for " + username + "."
	}
	redirect(w, r, "/osusers", msg, aerr != nil)
}

// fixDiscovery repairs the sops-discovery artifacts (SOPS_AGE_KEY_FILE + the
// junction/symlink) for one local OS user's keystore, so apps can actually FIND the
// key. Repair-only: a deliberate different pointer is reported as a conflict, never
// overwritten. Same auth level (any logged-in user) and CSRF guard as wire/place.
func (s *Server) fixDiscovery(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/osusers") {
		return
	}
	rep, err := s.keys.EnsureDiscoveryForOSUser(r.PathValue("id"), sess.Username)
	if err != nil {
		redirect(w, r, "/osusers", secretErr("Could not fix discovery", err), true)
		return
	}
	redirect(w, r, "/osusers", discoveryFlash(rep), rep.HasConflict() || rep.HasError())
}

// discoveryFlash renders a one-line, non-secret summary of what fixing discovery did
// to each artifact (created / already ok / conflict / error).
func discoveryFlash(rep place.DiscoveryReport) string {
	if len(rep.Items) == 0 {
		return "Discovery: nothing to repair."
	}
	parts := make([]string, 0, len(rep.Items))
	for _, it := range rep.Items {
		parts = append(parts, it.Artifact+": "+it.State)
	}
	return "Discovery: " + strings.Join(parts, "; ") + "."
}

func (s *Server) deleteOSUser(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/osusers") {
		return
	}
	id := r.PathValue("id")
	if err := s.store.OSUsers.Delete(id); err != nil {
		redirect(w, r, "/osusers", "OS user not found.", true)
		return
	}
	s.audit.Record(sess.Username, "osuser_delete", id, audit.OK, "")
	// Cascade: tombstone this account's assignments - a key grant is meaningless
	// without the account that would hold the key. Other accounts' assignments are
	// untouched.
	s.keys.CascadeDeleteOSUserAssignments(id, sess.Username)
	s.refreshPendingAsync()
	redirect(w, r, "/osusers", "OS user removed.", false)
}

// importKeys imports every on-disk key at one local OS user's keystore that SopsHQ
// does not yet track, using the dedup-safe adopt path (never duplicating a key that
// already has the same public key). It is the panel's "Import" button behind the
// on-disk-key-discovery alert. The on-disk file is only read, never modified. "back"
// returns the operator to the page they clicked from (Keys or OS users).
func (s *Server) importKeys(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	back := r.FormValue("back")
	if back != "/keys" && back != "/" {
		back = "/osusers"
	}
	if !s.guardPost(w, r, sess, back) {
		return
	}
	name, count, err := s.keys.AdoptExistingKeyForOSUser(r.PathValue("id"), sess.Username)
	if err != nil {
		redirect(w, r, back, secretErr("Could not import on-disk keys", err), true)
		return
	}
	s.refreshPendingAsync()
	switch {
	case count == 0:
		redirect(w, r, back, "No new keys to import.", false)
	case count == 1:
		redirect(w, r, back, "Imported the on-disk key ("+name+").", false)
	default:
		redirect(w, r, back, "Imported "+strconv.Itoa(count)+" on-disk keys.", false)
	}
}

// ---- projects -------------------------------------------------------------

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	missing := map[string]bool{}
	for _, m := range s.missingLocalFolders() {
		missing[m.ProjectID] = true
	}
	data := struct {
		Projects []*model.Project
		Missing  map[string]bool // project ids whose local folder is gone from disk
	}{s.store.Projects.List(), missing}
	s.render(w, r, "projects", sess, "Projects", data, http.StatusOK)
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/projects") {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirect(w, r, "/projects", "Project name is required.", true)
		return
	}
	if _, err := s.keys.CreateProject(name, r.FormValue("note"), sess.Username); err != nil {
		if errors.Is(err, keysvc.ErrProjectExists) {
			redirect(w, r, "/projects", fmt.Sprintf("A project named %q already exists.", name), true)
			return
		}
		s.renderError(w, r, sess, "Could not save project.", http.StatusInternalServerError)
		return
	}
	redirect(w, r, "/projects", "Project added.", false)
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/projects") {
		return
	}
	id := r.PathValue("id")
	if err := s.store.Projects.Delete(id); err != nil {
		redirect(w, r, "/projects", "Project not found.", true)
		return
	}
	s.audit.Record(sess.Username, "project_delete", id, audit.OK, "")
	// Cascade: tombstone this project's assignments so they do not dangle (which
	// would keep their key looking used and block its removal). Other projects'
	// assignments and project-less user placements are untouched.
	s.keys.CascadeDeleteProjectAssignments(id, sess.Username)
	s.refreshPendingAsync()
	redirect(w, r, "/projects", "Project removed.", false)
}

// ---- keys -----------------------------------------------------------------
//
// A key starts as metadata only (name, type, note). Generating it fills in the
// age keypair (Recipient/PrivSealed/Generation); placement happens on Apply.

// keyPlacement is one "machine -> user -> private-key file" pairing for a key, shown
// on the Keys page so the operator can see WHERE a key's private half lives, ON WHICH
// MACHINE, and WHO holds it. A shared key placed for the same-named account on two
// machines has one placement per machine (so both paths are visible, no duplicate row).
type keyPlacement struct {
	MachineName string
	Username    string
	Path        string // <KeyBase>/keys.txt, or "" when the account has no keystore set
}

type keyRow struct {
	*model.Key
	UseCount   int
	LastUsed   int64
	Placements []keyPlacement
	// Lifecycle is a loud, plain-language line for a key that is not placed anywhere,
	// so an unused or ungenerated key is unmistakable in the table. It is empty when
	// the key has placements (the Placements list is shown instead).
	Lifecycle string
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	localID := s.keys.LocalMachine()
	users := map[string]*model.OSUser{}
	for _, u := range s.store.OSUsers.List() {
		users[u.M.UUID] = u
	}
	machineNames := map[string]string{}
	for _, m := range s.store.Machines.List() {
		machineNames[m.M.UUID] = m.Name
	}
	var rows []keyRow
	for _, k := range s.store.Keys.List() {
		use := s.keys.UsageForKey(k.M.UUID)
		row := keyRow{Key: k, UseCount: use.Count, LastUsed: use.Last}
		seen := map[string]bool{}
		for _, a := range s.store.Assignments.List() {
			if a.KeyID != k.M.UUID {
				continue
			}
			ou := users[a.OSUserID]
			if ou == nil {
				continue
			}
			pl := keyPlacement{MachineName: machineNames[ou.MachineID], Username: ou.Username}
			// For a LOCAL user resolve the real base (a root-derived user has an empty
			// KeyBase but a store under keybase_root); for a REMOTE user only its stored
			// KeyBase is meaningful here (its root lives on its own machine), so keep that.
			base := ou.KeyBase
			if ou.MachineID == localID {
				base = s.keys.UserKeyBase(ou)
			}
			if base != "" {
				pl.Path = place.KeyFile(base)
			}
			dedup := pl.MachineName + "\x00" + pl.Username + "\x00" + pl.Path
			if seen[dedup] {
				continue
			}
			seen[dedup] = true
			row.Placements = append(row.Placements, pl)
		}
		// Loud lifecycle status for a key that is not placed anywhere: distinguish a
		// defined key with no keypair and no use yet from a generated key that just has
		// not been placed. A placed key shows its Placements list instead.
		switch {
		case len(row.Placements) > 0:
			// placed - the Placements list is the status
		case k.Recipient == "":
			row.Lifecycle = "Unused - no keypair or key files yet"
		default:
			row.Lifecycle = "Keypair created; not placed on any machine yet"
		}
		rows = append(rows, row)
	}
	// Local OS users offered as the owner of a new per_user key (owner is who reads a
	// global set built from that key). Only accounts on this machine can own a key here.
	var localUsers []*model.OSUser
	for _, u := range s.store.OSUsers.List() {
		if u.MachineID == localID {
			localUsers = append(localUsers, u)
		}
	}
	sort.Slice(localUsers, func(i, j int) bool { return localUsers[i].Username < localUsers[j].Username })
	data := struct {
		Rows    []keyRow
		OSUsers []*model.OSUser
		Import  importAlert
	}{rows, localUsers, s.importAlertState()}
	s.render(w, r, "keys", sess, "Keys", data, http.StatusOK)
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/keys") {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	kt := model.KeyType(r.FormValue("type"))
	if name == "" || (kt != model.KeyShared && kt != model.KeyPerUser) {
		redirect(w, r, "/keys", "Name and a valid type are required.", true)
		return
	}
	// Owner is meaningful only for a per_user key: it names the single OS user that
	// owns the key and, once a global set is built from it, reads that set with their
	// own key. A shared key has no owner. When given, the owner must be a real OS user
	// on THIS machine (owned keys are placed into a local keystore).
	detail := string(kt)
	ownerUserID := ""
	if kt == model.KeyPerUser {
		if id := strings.TrimSpace(r.FormValue("owner_user_id")); id != "" {
			u, err := s.store.OSUsers.Get(id)
			if err != nil || u.MachineID != s.keys.LocalMachine() {
				redirect(w, r, "/keys", "Owner must be an OS user on this machine.", true)
				return
			}
			ownerUserID = id
			detail += " owner=" + u.Username
		}
	}
	now := time.Now().Unix()
	k := &model.Key{
		M:           model.Meta{UUID: store.NewID()},
		Name:        name,
		Type:        kt,
		Note:        strings.TrimSpace(r.FormValue("note")),
		Status:      model.KeyActive,
		OwnerUserID: ownerUserID,
		CreatedAt:   now,
		EditedAt:    now,
	}
	if err := s.store.Keys.Put(k); err != nil {
		s.renderError(w, r, sess, "Could not save key.", http.StatusInternalServerError)
		return
	}
	s.audit.Record(sess.Username, "key_create", name, audit.OK, detail)
	redirect(w, r, "/keys", "Key defined. Its keypair is generated automatically the first time you use it (assign it to a project or add it to a shared set), or Generate it now.", false)
}

func (s *Server) deleteKey(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/keys") {
		return
	}
	id := r.PathValue("id")
	// A key can be SHARED: dedup makes one adopted/reused key back both a user's
	// placement and every reused project assignment. Deleting it while a LIVE
	// assignment still points at it would silently orphan those projects (the next
	// Apply writes no .sops.yaml and re-keys nothing). Block the delete and tell the
	// operator what still uses it; never cascade-delete. Only LIVE assignments count
	// - one whose project or user was already deleted is dangling and never blocks.
	uses := s.keys.LiveKeyAssignments(id)
	if uses > 0 {
		redirect(w, r, "/keys", fmt.Sprintf("This key is used by %d assignment(s) (projects/users); remove those first.", uses), true)
		return
	}
	if err := s.store.Keys.Delete(id); err != nil {
		redirect(w, r, "/keys", "Key not found.", true)
		return
	}
	s.audit.Record(sess.Username, "key_delete", id, audit.OK, "")
	s.refreshPendingAsync()
	redirect(w, r, "/keys", "Key removed.", false)
}

// renameKey changes a key's display name (a label only; the age keypair is
// unchanged). It rejects an empty or duplicate name with a clear flash. The new
// name lands in .sops.yaml as a per-line comment on the next Apply.
func (s *Server) renameKey(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/keys") {
		return
	}
	id := r.PathValue("id")
	name := strings.TrimSpace(r.FormValue("name"))
	if err := s.keys.RenameKey(id, name, sess.Username); err != nil {
		switch {
		case errors.Is(err, keysvc.ErrKeyNameEmpty):
			redirect(w, r, "/keys", "Key name is required.", true)
		case errors.Is(err, keysvc.ErrKeyNameTaken):
			redirect(w, r, "/keys", fmt.Sprintf("A key named %q already exists.", name), true)
		default:
			redirect(w, r, "/keys", "Key not found.", true)
		}
		return
	}
	redirect(w, r, "/keys", fmt.Sprintf("Key renamed to %q.", name), false)
}
