package web

import (
	"net/http"

	"sopshq/internal/auth"
	"sopshq/internal/model"
)

// dbData backs the read-only "DB" browse page: one table per record type. It
// carries names and non-sensitive metadata only - never a key, passphrase, TOTP
// secret, or decrypted secret value. The admin-only Users and Secrets sections
// are populated only when the viewer is an admin (the handler leaves them empty
// for a developer, and the template hides their tabs).
type dbData struct {
	Keys        []keyRow
	Projects    []*model.Project
	Machines    []*model.Machine
	LocalID     string
	OSUsers     []osUserRow
	Assignments []dbAssignmentRow

	// Admin-only sections (empty for non-admins).
	Users   []*model.PanelUser
	Secrets secretsCatalogData
}

// dbAssignmentRow flattens one assignment across all projects into display names
// for the Assignments tab.
type dbAssignmentRow struct {
	ProjectName string
	KeyName     string
	MachineName string
	UserName    string
}

// getDB renders the DB browse view. It is login-gated; the Users and Secrets
// data are gathered ONLY for an admin so they never reach a developer's page.
func (s *Server) getDB(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	machineNames := s.machineNames()
	keyNames := map[string]string{}
	for _, k := range s.store.Keys.List() {
		keyNames[k.M.UUID] = k.Name
	}
	userNames := map[string]string{}
	for _, u := range s.store.OSUsers.List() {
		userNames[u.M.UUID] = u.Username
	}
	projectNames := map[string]string{}
	for _, p := range s.store.Projects.List() {
		projectNames[p.M.UUID] = p.Name
	}

	var keyRows []keyRow
	for _, k := range s.store.Keys.List() {
		u := s.keys.UsageForKey(k.M.UUID)
		keyRows = append(keyRows, keyRow{Key: k, UseCount: u.Count, LastUsed: u.Last})
	}

	var osRows []osUserRow
	for _, u := range s.store.OSUsers.List() {
		osRows = append(osRows, osUserRow{OSUser: u, MachineName: machineNames[u.MachineID]})
	}

	var asgRows []dbAssignmentRow
	for _, a := range s.store.Assignments.List() {
		asgRows = append(asgRows, dbAssignmentRow{
			ProjectName: projectNames[a.ProjectID],
			KeyName:     keyNames[a.KeyID],
			MachineName: machineNames[a.MachineID],
			UserName:    userNames[a.OSUserID],
		})
	}

	data := dbData{
		Keys:        keyRows,
		Projects:    s.store.Projects.List(),
		Machines:    s.store.Machines.List(),
		LocalID:     s.keys.LocalMachine(),
		OSUsers:     osRows,
		Assignments: asgRows,
	}

	if sess.Role == model.RoleAdmin {
		data.Users = s.store.PanelUsers.List()
		if groups, err := s.keys.SecretsCatalog(sess.Username); err != nil {
			data.Secrets.Err = secretErr("Could not build the secrets catalog", err)
		} else {
			data.Secrets.Groups = groups
		}
	}

	s.render(w, r, "db", sess, "DB", data, http.StatusOK)
}
