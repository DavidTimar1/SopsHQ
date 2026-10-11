package web

import (
	"net/http"
	"strings"

	"sopshq/internal/audit"
	"sopshq/internal/auth"
	"sopshq/internal/keysvc"
)

type idName struct{ ID, Name string }

type idNameKey struct {
	ID, Name string
	HasKey   bool
}

type quickAddData struct {
	HasLocalMachine bool
	Projects        []idName
	Users           []idNameKey
	Sets            []idName
	In              keysvc.QuickAddInput // echoed back to repopulate the form
	Picked          map[string]bool      // selected user IDs, for re-checking checkboxes
	Alerts          []keysvc.QuickAddAlert
	Result          *keysvc.QuickAddResult
	Done            bool
}

// gatherQuickAdd builds the form's option lists (local projects, OS users, sets).
func (s *Server) gatherQuickAdd() quickAddData {
	localID := s.keys.LocalMachine()
	d := quickAddData{HasLocalMachine: localID != ""}
	for _, p := range s.store.Projects.List() {
		d.Projects = append(d.Projects, idName{p.M.UUID, p.Name})
	}
	for _, u := range s.store.OSUsers.List() {
		if u.MachineID != localID {
			continue
		}
		d.Users = append(d.Users, idNameKey{u.M.UUID, u.Username, s.keys.OSUserHasKey(u.M.UUID)})
	}
	for _, set := range s.keys.GlobalSets() {
		d.Sets = append(d.Sets, idName{set.M.UUID, set.Name})
	}
	return d
}

// getQuickAdd renders the empty wizard.
func (s *Server) getQuickAdd(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	d := s.gatherQuickAdd()
	d.Picked = map[string]bool{}
	s.render(w, r, "quick_add", sess, "Quick add", d, http.StatusOK)
}

// postQuickAdd validates and (on "Set it up") runs the wizard, rendering alerts or
// the result in place.
func (s *Server) postQuickAdd(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, sess, "Bad form data.", http.StatusBadRequest)
		return
	}
	d := s.gatherQuickAdd()
	if !s.checkCSRF(r, sess) {
		s.audit.Record(sess.Username, "csrf_reject", r.URL.Path, audit.Denied, "")
		d.Picked = map[string]bool{}
		d.Alerts = []keysvc.QuickAddAlert{{Level: "block", Text: "Security check failed; reload the page and try again."}}
		s.render(w, r, "quick_add", sess, "Quick add", d, http.StatusOK)
		return
	}

	in := keysvc.QuickAddInput{
		Name:           strings.TrimSpace(r.FormValue("name")),
		Value:          r.FormValue("value"),
		Scope:          r.FormValue("scope"),
		ProjectID:      r.FormValue("project_id"),
		NewProjectName: strings.TrimSpace(r.FormValue("new_project_name")),
		ProjectPath:    strings.TrimSpace(r.FormValue("project_path")),
		GlobalSetID:    r.FormValue("global_set_id"),
		NewSetName:     strings.TrimSpace(r.FormValue("new_set_name")),
		UserIDs:        r.Form["user"],
	}
	d.In = in
	d.Picked = map[string]bool{}
	for _, uid := range in.UserIDs {
		d.Picked[uid] = true
	}
	d.Alerts = s.keys.ValidateQuickAdd(in)

	if r.FormValue("action") == "run" && !blocked(d.Alerts) {
		res, err := s.keys.RunQuickAdd(in, sess.Username)
		if err != nil {
			d.Alerts = append(d.Alerts, keysvc.QuickAddAlert{Level: "block", Text: err.Error()})
		} else {
			d.Result = &res
			d.Done = true
		}
	}
	s.render(w, r, "quick_add", sess, "Quick add", d, http.StatusOK)
}

// blocked reports whether any alert is a blocker.
func blocked(alerts []keysvc.QuickAddAlert) bool {
	for _, a := range alerts {
		if a.Level == "block" {
			return true
		}
	}
	return false
}
