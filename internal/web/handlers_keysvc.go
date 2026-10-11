package web

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"sopshq/internal/audit"
	"sopshq/internal/auth"
	"sopshq/internal/keysvc"
	"sopshq/internal/model"
	"sopshq/internal/store"
)

// lastActionState is the most recent apply/sync result, shown on the dashboard's
// detailed results panel. It carries names, paths, counts, and status only - never
// a secret value. Kind distinguishes "apply" (Report carries the per-item Actions)
// from "sync" (Report is zero; Summary holds the peers/applied/conflicts line).
type lastActionState struct {
	When    int64  // Unix seconds; 0 means "no action this session"
	Scope   string // headline label: "Local", "Force re-apply", "All machines", "Sync"
	Dry     bool   // a dry run: actions describe what WOULD happen
	Kind    string // "apply" or "sync"
	Report  keysvc.ApplyReport
	Summary string // the one-line headline (same text as the flash)
}

// recordAction stores one apply/sync result for the dashboard results panel,
// stamping the time. Guarded by the lastAction mutex.
func (s *Server) recordAction(la lastActionState) {
	la.When = time.Now().Unix()
	s.lastActionMu.Lock()
	s.lastAction = la
	s.lastActionMu.Unlock()
}

// ---- key generation / rotation -------------------------------------------

func (s *Server) generateKey(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/keys") {
		return
	}
	id := r.PathValue("id")
	if err := s.keys.Generate(id, sess.Username); err != nil {
		redirect(w, r, "/keys", "Generate failed: "+err.Error(), true)
		return
	}
	s.refreshPendingAsync()
	s.notifier.Notify(model.EventKeyGenerated, "key generated: "+s.keyName(id))
	redirect(w, r, "/keys", "Keypair generated.", false)
}

func (s *Server) rotateKey(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/keys") {
		return
	}
	if s.keys.LocalMachine() == "" {
		redirect(w, r, "/keys", "Designate this machine first (Machines -> this machine).", true)
		return
	}
	id := r.PathValue("id")
	if err := s.keys.RotateLocal(id, sess.Username); err != nil {
		redirect(w, r, "/keys", "Rotate failed: "+err.Error(), true)
		return
	}
	s.refreshPendingAsync()
	s.notifier.Notify(model.EventRotation, "key rotated: "+s.keyName(id))
	redirect(w, r, "/keys", "Key rotated; secrets re-encrypted to the new key.", false)
}

// keyName returns a key's human name for an event message, falling back to its id
// when the record cannot be read.
func (s *Server) keyName(id string) string {
	if k, err := s.store.Keys.Get(id); err == nil && k.Name != "" {
		return k.Name
	}
	return id
}

// ---- local machine designation -------------------------------------------

func (s *Server) setLocalMachine(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/machines") {
		return
	}
	id := r.PathValue("id")
	mc, err := s.store.Machines.Get(id)
	if err != nil {
		redirect(w, r, "/machines", "Machine not found.", true)
		return
	}
	s.cfg.LocalMachineID = id
	if err := s.cfg.Save(); err != nil {
		redirect(w, r, "/machines", "Could not persist config: "+err.Error(), true)
		return
	}
	s.keys.SetLocalMachine(id)
	s.audit.Record(sess.Username, "set_local_machine", mc.Name, audit.OK, "")
	// Reconcile now that this node has a designated machine: mark its record
	// canonical and settle the acknowledged-peers baseline before any peer is added.
	s.reconcileCluster()
	s.refreshPendingAsync()
	redirect(w, r, "/machines", "This node is now linked to "+mc.Name+".", false)
}

// ---- project detail: paths + assignments ---------------------------------

type projectDetailData struct {
	Project     *model.Project
	Machines    []*model.Machine
	Keys        []*model.Key
	OSUsers     []*model.OSUser
	Assignments []assignmentRow
	MachineName map[string]string
	LocalID     string

	// Secrets editor state.
	HasLocalMachine bool // a local machine is designated
	HasLocalPath    bool // the project has a folder on the local machine
	// LocalFolderMissing is true when the project has a local-machine path but that
	// folder does not exist on disk (moved or deleted). LocalFolderPath is the path.
	LocalFolderMissing bool
	LocalFolderPath    string
	HasLocalOSUser     bool        // an OS user is recorded on the local machine (wiring needs one)
	WiredLocally       bool        // a generated key is assigned locally (records present)
	AppliedLocally     bool        // .sops.yaml is written on disk too (editor is usable)
	ImportOnDisk       bool        // the local folder already has SOPS state to adopt (offer Import, not Generate)
	SecretNames        []string    // names only - never values
	SecretErr          string      // a non-fatal note (e.g. sops missing) for the editor
	Edit               *secretEdit // non-nil when prefilling the form to edit one secret

	// SopsMismatch is true when the project's on-disk .sops.yaml lists different public
	// keys than the project's desired set (a public-key mismatch, not a missing file).
	// The page shows a "Match to the on-disk keys" call to action that routes to the
	// drift reconcile, instead of a bare Apply that could drop an on-disk reader.
	SopsMismatch       bool
	SopsMismatchDetail string   // the account-aware plain-language description
	SopsMismatchDrop   []string // keys added-but-not-applied that Match removes (named)
}

type assignmentRow struct {
	*model.Assignment
	KeyName     string
	MachineName string
	UserName    string
}

// secretEdit prefills the add/edit form with one secret's NAME and decrypted
// VALUE. It exists only for the duration of one rendered response and is never
// stored or logged. Elsewhere (admin only) lists OTHER places that hold the exact
// same (name, value), so the form can offer to update them all.
type secretEdit struct {
	Name      string
	Value     string
	Elsewhere []keysvc.SecretOccurrence
}

func (s *Server) projectDetail(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	s.renderProjectDetail(w, r, sess, r.PathValue("id"), nil)
}

// renderProjectDetail builds and renders the project page, including the secrets
// editor state. edit is non-nil only when re-rendering with one secret's value
// prefilled for editing (a POST flow that keeps the value out of any URL).
func (s *Server) renderProjectDetail(w http.ResponseWriter, r *http.Request, sess auth.Session, id string, edit *secretEdit) {
	p, err := s.store.Projects.Get(id)
	if err != nil {
		s.renderError(w, r, sess, "Project not found.", http.StatusNotFound)
		return
	}
	names := s.machineNames()
	keyNames := map[string]string{}
	for _, k := range s.store.Keys.List() {
		keyNames[k.M.UUID] = k.Name
	}
	userNames := map[string]string{}
	for _, u := range s.store.OSUsers.List() {
		userNames[u.M.UUID] = u.Username
	}
	var rows []assignmentRow
	for _, a := range s.store.Assignments.List() {
		if a.ProjectID != p.M.UUID {
			continue
		}
		rows = append(rows, assignmentRow{
			Assignment:  a,
			KeyName:     keyNames[a.KeyID],
			MachineName: names[a.MachineID],
			UserName:    userNames[a.OSUserID],
		})
	}
	localID := s.keys.LocalMachine()
	hasLocalPath := false
	localPath := ""
	for _, pp := range p.Paths {
		if pp.MachineID == localID {
			hasLocalPath = true
			localPath = strings.TrimSpace(pp.Path)
			break
		}
	}
	// A configured local folder that is gone from disk (moved or deleted) gets a
	// proactive flag on the page. Read-only stat; nothing is changed.
	localFolderMissing := false
	if localPath != "" {
		if fi, err := os.Stat(localPath); (err != nil && os.IsNotExist(err)) || (err == nil && !fi.IsDir()) {
			localFolderMissing = true
		}
	}
	hasLocalOSUser := false
	for _, u := range s.store.OSUsers.List() {
		if u.MachineID == localID {
			hasLocalOSUser = true
			break
		}
	}
	wired := s.keys.ProjectWiredLocally(id)
	applied := s.keys.ProjectAppliedLocally(id)
	// When the project is not yet wired, notice pre-existing on-disk SOPS state so the
	// page can offer "Import the existing setup" (adopt) rather than only "generate".
	importOnDisk := false
	if !wired && hasLocalPath && hasLocalOSUser && localID != "" {
		importOnDisk = s.keys.ProjectHasImportableState(id)
	}
	data := projectDetailData{
		Project:            p,
		Machines:           s.store.Machines.List(),
		Keys:               s.store.Keys.List(),
		OSUsers:            s.store.OSUsers.List(),
		Assignments:        rows,
		MachineName:        names,
		LocalID:            localID,
		HasLocalMachine:    localID != "",
		HasLocalPath:       hasLocalPath,
		LocalFolderMissing: localFolderMissing,
		LocalFolderPath:    localPath,
		HasLocalOSUser:     hasLocalOSUser,
		WiredLocally:       wired,
		AppliedLocally:     applied,
		ImportOnDisk:       importOnDisk,
		Edit:               edit,
	}
	// When the .sops.yaml exists but its public keys differ from the project's desired
	// set, surface a targeted reconcile CTA (Match to the on-disk keys) rather than the
	// generic Apply, which could rewrite the file and drop an on-disk reader.
	if applied {
		if item, drift := s.keys.ProjectSopsDrift(id); drift && !item.Missing {
			data.SopsMismatch = true
			data.SopsMismatchDetail = item.Detail
			data.SopsMismatchDrop = item.DesiredOnly
		}
	}
	if applied {
		if secretNames, err := s.keys.ListSecrets(id); err != nil {
			// Show the editor but explain why the list could not be read (e.g. sops
			// missing). The error never carries a secret value.
			data.SecretErr = secretErr("Could not list secrets", err)
		} else {
			data.SecretNames = secretNames
		}
	}
	s.render(w, r, "project_detail", sess, "Project: "+p.Name, data, http.StatusOK)
}

func (s *Server) addProjectPath(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	back := "/projects/" + r.PathValue("id")
	if !s.guardPost(w, r, sess, back) {
		return
	}
	p, err := s.store.Projects.Get(r.PathValue("id"))
	if err != nil {
		redirect(w, r, "/projects", "Project not found.", true)
		return
	}
	machineID := r.FormValue("machine_id")
	path := strings.TrimSpace(r.FormValue("path"))
	if machineID == "" || path == "" {
		redirect(w, r, back, "Machine and path are required.", true)
		return
	}
	// Find the machine's current path, if any.
	oldPath := ""
	for _, pp := range p.Paths {
		if pp.MachineID == machineID {
			oldPath = pp.Path
			break
		}
	}
	localID := s.keys.LocalMachine()

	// Changing an already-set folder to a DIFFERENT one is a MOVE, not just a
	// re-point: the SopsHQ-managed files must follow, so the old folder is not left
	// with a stranded .sops.yaml.
	changed := oldPath != "" && oldPath != path
	if changed && machineID == localID {
		// The move touches the local filesystem: confirm first, then perform it so the
		// managed files move old -> new and the old folder is left clean.
		if r.FormValue("confirm_move") != "1" {
			s.renderMoveConfirm(w, r, sess, p, machineID, path)
			return
		}
		if err := s.keys.MoveLocalPath(p.M.UUID, path, sess.Username); err != nil {
			if s.handleExternalChange(w, r, sess, err) {
				return
			}
			redirect(w, r, back, "Could not move the project folder: "+err.Error(), true)
			return
		}
		s.refreshPendingAsync()
		redirect(w, r, back, "Folder changed and the managed files moved to the new location.", false)
		return
	}
	if changed && machineID != localID {
		// A PEER machine's path: SopsHQ can only touch the local filesystem, so it just
		// records the new path. That machine moves its own managed files when it next
		// applies or reconciles.
		for i := range p.Paths {
			if p.Paths[i].MachineID == machineID {
				p.Paths[i].Path = path
			}
		}
		if err := s.store.Projects.Put(p); err != nil {
			redirect(w, r, back, "Could not save path.", true)
			return
		}
		s.audit.Record(sess.Username, "project_path_set", p.Name, audit.OK, path)
		s.refreshPendingAsync()
		redirect(w, r, back, "Path saved. That machine will move its managed files on its next apply or reconcile.", false)
		return
	}

	// New path for this machine (append), or the same path re-submitted (no-op save).
	replaced := false
	for i := range p.Paths {
		if p.Paths[i].MachineID == machineID {
			p.Paths[i].Path = path
			replaced = true
			break
		}
	}
	if !replaced {
		p.Paths = append(p.Paths, model.ProjectPath{MachineID: machineID, Path: path})
	}
	if err := s.store.Projects.Put(p); err != nil {
		redirect(w, r, back, "Could not save path.", true)
		return
	}
	s.audit.Record(sess.Username, "project_path_set", p.Name, audit.OK, path)
	s.refreshPendingAsync()
	redirect(w, r, back, "Path saved.", false)
}

// moveConfirmData drives the folder-move confirm screen: the plan (what moves, what
// is left in place) plus the machine the path belongs to, so the confirm form can
// re-post the exact change.
type moveConfirmData struct {
	Plan        keysvc.MovePlan
	MachineID   string
	MachineName string
}

// renderMoveConfirm shows the operator exactly what changing a project's local folder
// will do - old -> new, which managed files move, and which hand-authored files are
// left in place - and asks them to confirm before anything is moved.
func (s *Server) renderMoveConfirm(w http.ResponseWriter, r *http.Request, sess auth.Session, p *model.Project, machineID, newPath string) {
	plan, err := s.keys.PlanLocalMove(p.M.UUID, newPath)
	if err != nil {
		s.renderError(w, r, sess, "Could not plan the folder change: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "path_move", sess, "Move project folder: "+p.Name,
		moveConfirmData{Plan: plan, MachineID: machineID, MachineName: s.machineNames()[machineID]}, http.StatusOK)
}

// resolveDrift applies a per-row resolve action from the Drift view for a project's
// .sops.yaml. It is CSRF-protected and requires a logged-in session (the same level
// as Apply and Wire). Each action delegates to the key service, which audits it and
// re-stamps the file so the fresh DriftLocal recomputes the row as clear.
func (s *Server) resolveDrift(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/drift") {
		return
	}
	projectID := r.FormValue("project_id")
	action := r.FormValue("action")
	var err error
	var msg string
	switch action {
	case "adopt-readers":
		// Adopt readers imports an unknown on-disk PRIVATE key into the vault, the same
		// custody-sensitive step as the external-change reconcile - so it is admin-only,
		// even though the rest of /drift/resolve matches Apply's login level.
		if sess.Role != model.RoleAdmin {
			redirect(w, r, "/drift", "Adopt readers is admin-only (it imports a key into custody). Ask an admin, or use Re-key to desired.", true)
			return
		}
		err = s.keys.AdoptReaders(projectID, sess.Username)
		msg = "Adopted the extra public keys into the project; everyone who could read the secrets still can."
	case "match-disk":
		// Matching the project to the on-disk public keys imports a key into custody ONLY
		// when an on-disk key is not already held; gate just that custody-sensitive case on
		// admin, so the common same-account identity match stays at the Apply login level.
		if s.keys.MatchProjectToDiskImportsKey(projectID) && sess.Role != model.RoleAdmin {
			redirect(w, r, "/drift", "Matching here would import a key into custody, which is admin-only. Ask an admin, or use Re-key to desired.", true)
			return
		}
		err = s.keys.MatchProjectToDisk(projectID, sess.Username)
		msg = "Matched the project to the on-disk public keys; nobody who could read the secrets lost access."
	case "rekey-desired":
		err = s.keys.RekeyToDesired(projectID, sess.Username)
		msg = "Re-keyed the secrets config to this project's public keys; the extra public keys were dropped."
	case "apply-sops":
		err = s.keys.WriteProjectSopsYAML(projectID, sess.Username)
		msg = "Wrote the secrets config for this project."
	default:
		redirect(w, r, "/drift", "Choose a resolve action.", true)
		return
	}
	if err != nil {
		if s.handleExternalChange(w, r, sess, err) {
			return
		}
		redirect(w, r, "/drift", "Could not resolve: "+err.Error(), true)
		return
	}
	s.refreshPendingAsync()
	redirect(w, r, "/drift", msg, false)
}

func (s *Server) deleteProjectPath(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	back := "/projects/" + r.PathValue("id")
	if !s.guardPost(w, r, sess, back) {
		return
	}
	p, err := s.store.Projects.Get(r.PathValue("id"))
	if err != nil {
		redirect(w, r, "/projects", "Project not found.", true)
		return
	}
	machineID := r.FormValue("machine_id")
	out := p.Paths[:0]
	for _, pp := range p.Paths {
		if pp.MachineID != machineID {
			out = append(out, pp)
		}
	}
	p.Paths = out
	if err := s.store.Projects.Put(p); err != nil {
		redirect(w, r, back, "Could not remove path.", true)
		return
	}
	s.audit.Record(sess.Username, "project_path_delete", p.Name, audit.OK, "")
	s.refreshPendingAsync()
	redirect(w, r, back, "Path removed.", false)
}

// ---- assignments ----------------------------------------------------------

func (s *Server) createAssignment(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	projectID := r.FormValue("project_id")
	back := "/projects/" + projectID
	if !s.guardPost(w, r, sess, back) {
		return
	}
	keyID := r.FormValue("key_id")
	machineID := r.FormValue("machine_id")
	osUserID := r.FormValue("os_user_id")
	if projectID == "" || keyID == "" || machineID == "" || osUserID == "" {
		redirect(w, r, back, "Key, machine, and OS user are all required.", true)
		return
	}
	// Validate references exist.
	if _, err := s.store.Keys.Get(keyID); err != nil {
		redirect(w, r, back, "Unknown key.", true)
		return
	}
	if _, err := s.store.OSUsers.Get(osUserID); err != nil {
		redirect(w, r, back, "Unknown OS user.", true)
		return
	}
	// Idempotent: the same key + project + machine + OS user must never produce a
	// second identical assignment row.
	if s.keys.HasAssignment(keyID, projectID, machineID, osUserID) {
		redirect(w, r, back, "That key is already assigned for this machine and OS user.", false)
		return
	}
	// Generate on first use: a key gets its age keypair the moment it is assigned, so
	// the operator never has to pre-generate. Idempotent (an already-generated key is
	// untouched). Fail before creating the assignment so no half-state is left behind.
	if err := s.keys.EnsureGenerated(keyID, sess.Username); err != nil {
		redirect(w, r, back, "Could not generate the key's keypair: "+err.Error(), true)
		return
	}
	a := &model.Assignment{
		M:         model.Meta{UUID: store.NewID()},
		KeyID:     keyID,
		ProjectID: projectID,
		MachineID: machineID,
		OSUserID:  osUserID,
	}
	if err := s.store.Assignments.Put(a); err != nil {
		redirect(w, r, back, "Could not save assignment.", true)
		return
	}
	s.audit.Record(sess.Username, "assignment_create", projectID, audit.OK, "")
	s.refreshPendingAsync()
	redirect(w, r, back, "Assignment added.", false)
}

func (s *Server) deleteAssignment(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	id := r.PathValue("id")
	a, err := s.store.Assignments.Get(id)
	back := "/projects"
	if err == nil {
		back = "/projects/" + a.ProjectID
	}
	if !s.guardPost(w, r, sess, back) {
		return
	}
	if err != nil {
		redirect(w, r, back, "Assignment not found.", true)
		return
	}
	if err := s.store.Assignments.Delete(id); err != nil {
		redirect(w, r, back, "Could not delete assignment.", true)
		return
	}
	s.audit.Record(sess.Username, "assignment_delete", a.ProjectID, audit.OK, "")
	s.refreshPendingAsync()
	redirect(w, r, back, "Assignment removed.", false)
}

// ---- apply ----------------------------------------------------------------

func (s *Server) applyLocal(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/") {
		return
	}
	// An optional "back" returns the operator to where they triggered Apply (e.g.
	// a project page). Restrict it to an internal path to avoid an open redirect.
	back := strings.TrimSpace(r.FormValue("back"))
	if !strings.HasPrefix(back, "/") {
		back = "/"
	}
	if s.keys.LocalMachine() == "" {
		redirect(w, r, "/machines", "Designate this machine first (Machines -> this machine).", true)
		return
	}
	dry := r.FormValue("dry") == "1"
	// ApplyLocal is already a full reconcile (it rewrites each user's key store and
	// every local .sops.yaml from the database); "force" is the same action exposed
	// as an explicit always-available button, with clearer wording.
	force := r.FormValue("force") == "1"
	rep, err := s.keys.ApplyLocal(sess.Username, dry)
	if err != nil {
		if s.handleExternalChange(w, r, sess, err) {
			return
		}
		redirect(w, r, back, "Apply failed: "+err.Error(), true)
		return
	}
	if !dry {
		s.refreshPendingAsync()
	}
	scope := "Local"
	if force {
		scope = "Force re-apply"
	}
	msg := applyMessage(scope, dry, rep)
	s.recordAction(lastActionState{Scope: scope, Dry: dry, Kind: "apply", Report: rep, Summary: msg})
	if !dry {
		s.notifier.Notify(model.EventApply, msg)
	}
	redirect(w, r, back, msg, len(rep.Skipped) > 0)
}

// applyAll pushes desired state to every machine (local in-process, remote over
// the agent channel: plain HTTP over Tailscale, authenticated by the transfer key).
func (s *Server) applyAll(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/") {
		return
	}
	if s.keys.LocalMachine() == "" {
		redirect(w, r, "/machines", "Designate this machine first (Machines -> this machine).", true)
		return
	}
	dry := r.FormValue("dry") == "1"
	rep, err := s.keys.ApplyAll(sess.Username, dry)
	if err != nil {
		redirect(w, r, "/", "Apply-all failed: "+err.Error(), true)
		return
	}
	if !dry {
		s.refreshPendingAsync()
	}
	msg := applyMessage("All machines", dry, rep)
	s.recordAction(lastActionState{Scope: "All machines", Dry: dry, Kind: "apply", Report: rep, Summary: msg})
	if !dry {
		s.notifier.Notify(model.EventApply, msg)
	}
	redirect(w, r, "/", msg, len(rep.Skipped) > 0)
}

// getDrift shows discrepancies between desired state and on-disk reality.
func (s *Server) getDrift(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if s.keys.LocalMachine() == "" {
		s.render(w, r, "drift", sess, "Drift", nil, http.StatusOK)
		return
	}
	items, err := s.keys.DriftLocal()
	if err != nil {
		s.renderError(w, r, sess, "Drift check failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "drift", sess, "Drift", items, http.StatusOK)
}

// syncNow triggers one replication pull from all enrolled peers. It returns to the
// page it was triggered from ("back" form field; defaults to the dashboard).
func (s *Server) syncNow(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	back := "/"
	if b := r.FormValue("back"); b == "/machines" {
		back = b
	}
	if !s.guardPost(w, r, sess, back) {
		return
	}
	if s.syncFn == nil {
		redirect(w, r, back, "Replication is not running.", true)
		return
	}
	peers, applied, conflicts := s.syncFn()
	s.audit.Record(sess.Username, "sync_now", "", audit.OK,
		strconv.Itoa(applied)+" applied, "+strconv.Itoa(conflicts)+" conflicts")
	s.refreshPendingAsync()
	msg := "Synced " + strconv.Itoa(peers) + " peer(s): " + strconv.Itoa(applied) +
		" change(s) applied, " + strconv.Itoa(conflicts) + " conflict(s)."
	s.recordAction(lastActionState{Scope: "Sync", Kind: "sync", Summary: msg})
	redirect(w, r, back, msg, conflicts > 0)
}

// applyMessage formats an ApplyReport into a flash message.
func applyMessage(scope string, dry bool, rep keysvc.ApplyReport) string {
	verb := scope + " apply"
	if dry {
		verb = scope + " dry run"
	}
	msg := verb + ": " + strconv.Itoa(rep.KeysPlaced) + " keys placed, " +
		strconv.Itoa(rep.ProjectsWired) + " projects wired, " +
		strconv.Itoa(rep.FilesRekeyed) + " files re-keyed."
	if len(rep.Skipped) > 0 {
		msg += " Skipped: " + strings.Join(rep.Skipped, "; ")
	}
	return msg
}
