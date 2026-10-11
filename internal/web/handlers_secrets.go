package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"sopshq/internal/audit"
	"sopshq/internal/auth"
	"sopshq/internal/keys"
	"sopshq/internal/keysvc"
	"sopshq/internal/model"
)

// addSecret sets (creates or overwrites) a project secret name=value, then
// re-encrypts the project's secrets file. The VALUE is taken from the form and
// passed straight to keysvc.SetSecret, which never logs or audits it; only the
// NAME is recorded. CSRF is enforced.
func (s *Server) addSecret(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	id := r.PathValue("id")
	back := "/projects/" + id
	if !s.guardPost(w, r, sess, back) {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	value := r.FormValue("value")
	origName := strings.TrimSpace(r.FormValue("orig_name"))
	if name == "" {
		redirect(w, r, back, "Secret name is required.", true)
		return
	}
	if !keys.ValidSecretName(name) {
		redirect(w, r, back, "Secret names may use only letters, digits, '_', '-', '.'.", true)
		return
	}

	// Plain add (or overwrite a same-named secret in this project).
	if origName == "" {
		if err := s.keys.SetSecret(id, name, value, sess.Username); err != nil {
			if s.handleExternalChange(w, r, sess, err) {
				return
			}
			redirect(w, r, back, secretErr("Could not save secret", err), true)
			return
		}
		redirect(w, r, back, "Secret saved: "+name+".", false)
		return
	}

	// Editing an existing secret. If an admin ticked "update everywhere", propagate to
	// every place holding the exact (origName, old value); otherwise just this project.
	if r.FormValue("propagate") == "all" && sess.Role == "admin" {
		oldValue, err := s.keys.GetSecretValue(id, origName)
		if err != nil {
			redirect(w, r, back, secretErr("Could not read secret", err), true)
			return
		}
		occ := s.keys.FindSecretOccurrences(origName, oldValue) // includes this project
		ok := 0
		for _, res := range s.keys.MassUpdateSecret(occ, origName, name, value, sess.Username) {
			if res.OK {
				ok++
			}
		}
		redirect(w, r, back, fmt.Sprintf("Updated %q in %d place(s).", name, ok), false)
		return
	}

	if err := s.keys.SetSecret(id, name, value, sess.Username); err != nil {
		if s.handleExternalChange(w, r, sess, err) {
			return
		}
		redirect(w, r, back, secretErr("Could not save secret", err), true)
		return
	}
	if name != origName {
		_ = s.keys.DeleteSecret(id, origName, sess.Username) // renamed: drop the old name
	}
	redirect(w, r, back, "Secret updated: "+name+".", false)
}

// deleteSecret removes a project secret by name and re-encrypts the file.
func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	back := "/projects/" + r.PathValue("id")
	if !s.guardPost(w, r, sess, back) {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirect(w, r, back, "Secret name is required.", true)
		return
	}
	if err := s.keys.DeleteSecret(r.PathValue("id"), name, sess.Username); err != nil {
		if s.handleExternalChange(w, r, sess, err) {
			return
		}
		redirect(w, r, back, secretErr("Could not delete secret", err), true)
		return
	}
	redirect(w, r, back, "Secret removed: "+name+".", false)
}

// editSecret re-renders the project page with one secret's value prefilled in
// the add/edit form. It is a POST (not a GET) so the decrypted value travels in
// the response BODY to the already-authenticated admin and never lands in a URL,
// a browser history entry, or an access log. The panel is served over plain HTTP
// by default on loopback; front it with a TLS terminator before binding it
// off-loopback. The value is never flashed (flashes ride the query string) and
// never audited.
func (s *Server) editSecret(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	id := r.PathValue("id")
	back := "/projects/" + id
	if !s.guardPost(w, r, sess, back) {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirect(w, r, back, "Secret name is required.", true)
		return
	}
	value, err := s.keys.GetSecretValue(id, name)
	if err != nil {
		redirect(w, r, back, secretErr("Could not read secret", err), true)
		return
	}
	edit := &secretEdit{Name: name, Value: value}
	// Admins see whether this exact (name, value) is used elsewhere, so the form can
	// offer to update every place at once. Computing this decrypts other projects/sets
	// (a mass-decrypt), so it is admin-only.
	if sess.Role == "admin" {
		for _, o := range s.keys.FindSecretOccurrences(name, value) {
			if o.Kind == "project" && o.ID == id {
				continue // exclude the project being edited
			}
			edit.Elsewhere = append(edit.Elsewhere, o)
		}
	}
	s.renderProjectDetail(w, r, sess, id, edit)
}

// revealSecret decrypts ONE secret value and returns it as JSON for the per-row
// "Show" toggle. It is a POST (CSRF-protected) so the value rides the response BODY
// and never lands in a URL, browser history, or an access log. The panel is served
// over plain HTTP by default on loopback; front it with a TLS terminator before
// binding it off-loopback. The value is never cached; the reveal is audited by
// secret NAME only (in keysvc).
func (s *Server) revealSecret(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if err := r.ParseForm(); err != nil {
		writeSecretJSON(w, http.StatusBadRequest, "", "Bad form data.")
		return
	}
	if !s.checkCSRF(r, sess) {
		s.audit.Record(sess.Username, "csrf_reject", r.URL.Path, audit.Denied, "")
		writeSecretJSON(w, http.StatusForbidden, "", "Security check failed; reload the page.")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		writeSecretJSON(w, http.StatusBadRequest, "", "Secret name is required.")
		return
	}
	value, err := s.keys.RevealSecret(r.PathValue("id"), name, sess.Username)
	if err != nil {
		writeSecretJSON(w, http.StatusOK, "", secretErr("Could not read secret", err))
		return
	}
	s.notifier.Notify(model.EventSecretReveal, "secret revealed: "+name)
	writeSecretJSON(w, http.StatusOK, value, "")
}

// writeSecretJSON writes the reveal response. Exactly one of value/errMsg is set.
// Cache-Control:no-store keeps a decrypted value out of any intermediary cache.
func writeSecretJSON(w http.ResponseWriter, status int, value, errMsg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Value string `json:"value,omitempty"`
		Error string `json:"error,omitempty"`
	}{value, errMsg})
}

// wireProject runs the onboarding glue: generate + assign + apply a shared key so
// the project becomes editable on this machine in one click.
//
// SAFETY: if the project already has SOPS/age state that wiring would overwrite (a
// non-empty keys.txt, a SOPS_AGE_KEY_FILE pointing elsewhere, an existing
// .sops.yaml, or an existing assigned key), EnsureProjectWired refuses with
// keysvc.ErrWiringConflict. We then show the reuse/re-create review screen instead
// of clobbering anything.
func (s *Server) wireProject(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	id := r.PathValue("id")
	back := "/projects/" + id
	if !s.guardPost(w, r, sess, back) {
		return
	}
	err := s.keys.EnsureProjectWired(id, sess.Username)
	if errors.Is(err, keysvc.ErrWiringConflict) {
		s.renderWiringReview(w, r, sess, id)
		return
	}
	if err != nil {
		redirect(w, r, back, secretErr("Could not wire project", err), true)
		return
	}
	s.refreshPendingAsync()
	s.notifier.Notify(model.EventProjectWired, "project wired: "+s.projectName(id))
	redirect(w, r, back, "Project wired: key generated, assigned, and placed. You can add secrets now.", false)
}

// projectName returns a project's human name for an event message, falling back
// to its id when the record cannot be read.
func (s *Server) projectName(id string) string {
	if p, err := s.store.Projects.Get(id); err == nil && p.Name != "" {
		return p.Name
	}
	return id
}

// wiringReviewData drives the reuse/re-create screen shown when wiring would
// touch pre-existing state. It carries only non-secret facts (paths, public
// recipients, presence flags).
type wiringReviewData struct {
	Insp keysvc.WiringInspection
}

// renderWiringReview shows the operator exactly what already exists at the wiring
// target and asks, per artifact, whether to REUSE it (adopt) or RE-CREATE it
// (overwrite). It re-inspects (read-only) to build the screen.
func (s *Server) renderWiringReview(w http.ResponseWriter, r *http.Request, sess auth.Session, id string) {
	insp, err := s.keys.InspectWiring(id)
	if err != nil {
		s.renderError(w, r, sess, secretErr("Could not inspect project", err), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "wiring_review", sess, "Review wiring: "+insp.ProjectName,
		wiringReviewData{Insp: insp}, http.StatusOK)
}

// resolveWiring applies the operator's explicit reuse/re-create decisions from the
// review screen. Each choice defaults to REUSE (the safe, non-destructive option)
// unless the form value is exactly "recreate".
func (s *Server) resolveWiring(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	id := r.PathValue("id")
	back := "/projects/" + id
	if !s.guardPost(w, r, sess, back) {
		return
	}
	choices := keysvc.WiringChoices{
		Key:        decision(r.FormValue("key")),
		SopsYAML:   decision(r.FormValue("sops_yaml")),
		EnvKeyFile: decision(r.FormValue("env_key_file")),
	}
	if err := s.keys.WireProjectResolved(id, choices, sess.Username); err != nil {
		redirect(w, r, back, secretErr("Could not wire project", err), true)
		return
	}
	s.refreshPendingAsync()
	redirect(w, r, back, "Project wired with your choices. You can add secrets now.", false)
}

// decision maps a form value to a WiringDecision. Anything other than the literal
// "recreate" is treated as REUSE, so the destructive choice must be selected
// explicitly.
func decision(v string) keysvc.WiringDecision {
	if v == "recreate" {
		return keysvc.DecideRecreate
	}
	return keysvc.DecideReuse
}

// secretErr turns a keysvc/keys error into a friendly flash message. It never
// includes a secret value (the underlying errors never carry one).
func secretErr(prefix string, err error) string {
	switch {
	case errors.Is(err, keys.ErrSecretNotFound):
		return "That secret no longer exists."
	case errors.Is(err, keys.ErrBadSecretName):
		return "Secret names may use only letters, digits, '_', '-', '.'."
	case errors.Is(err, keysvc.ErrNoLocalMachine):
		return "Designate this machine first (Machines -> this machine)."
	case errors.Is(err, keysvc.ErrProjectNoLocalPath):
		return "Set this project's folder path on the local machine first."
	case errors.Is(err, keysvc.ErrProjectNotWired):
		return "Wire this project first (it has no key on this machine yet)."
	case errors.Is(err, keysvc.ErrNoLocalOSUser):
		return "Create an OS user on this machine first (OS users -> Add), then wire the project."
	case errors.Is(err, keysvc.ErrWiringConflict):
		return "This project already has SOPS/age state - choose reuse or re-create."
	case errors.Is(err, keys.ErrSopsMissing):
		return "sops is not installed on this machine (install sops)."
	default:
		return prefix + ": " + err.Error()
	}
}
