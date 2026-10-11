package web

import (
	"errors"
	"net/http"
	"strings"

	"sopshq/internal/auth"
	"sopshq/internal/keys"
	"sopshq/internal/keysvc"
	"sopshq/internal/model"
)

// globalSetView is one shared set on the /global page.
type globalSetView struct {
	ID         string
	Name       string
	Recipients []keysvc.GlobalRecipient // username + consume path
	Names      []string                 // secret NAMES only - never values
	Err        string                   // non-fatal note (e.g. a recipient lost their key)
}

type globalCandidate struct {
	KeyID string
	Label string // "key name (owner username)"
}

type globalData struct {
	HasLocalMachine bool
	Sets            []globalSetView
	Candidates      []globalCandidate // per_user keys owned by a local OS user
}

// getGlobal renders the Global (shared) secrets page: named sets, each encrypted to
// one or more OS users who can each decrypt with their own key.
func (s *Server) getGlobal(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	localID := s.keys.LocalMachine()
	data := globalData{HasLocalMachine: localID != ""}
	for _, set := range s.keys.GlobalSets() {
		v := globalSetView{ID: set.M.UUID, Name: set.Name, Recipients: s.keys.GlobalSetRecipients(set)}
		if names, err := s.keys.ListGlobalSecrets(set.M.UUID); err != nil {
			v.Err = globalMsg(err)
		} else {
			v.Names = names
		}
		data.Sets = append(data.Sets, v)
	}
	for _, c := range s.keys.GlobalKeyCandidates() {
		data.Candidates = append(data.Candidates, globalCandidate{KeyID: c.KeyID, Label: c.KeyName + " (" + c.OwnerUsername + ")"})
	}
	s.render(w, r, "global", sess, "Global secrets", data, http.StatusOK)
}

// createGlobalSet creates a named shared set with the chosen recipient OS users.
func (s *Server) createGlobalSet(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	back := "/global"
	if !s.guardPost(w, r, sess, back) {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	keyIDs := r.Form["key"]
	if _, err := s.keys.CreateGlobalSet(name, keyIDs, sess.Username); err != nil {
		redirect(w, r, back, globalMsg(err), true)
		return
	}
	redirect(w, r, back, "Shared set created: "+name+".", false)
}

// deleteGlobalSet removes a set and its on-disk copies.
func (s *Server) deleteGlobalSet(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	back := "/global"
	if !s.guardPost(w, r, sess, back) {
		return
	}
	if err := s.keys.DeleteGlobalSet(r.PathValue("id"), sess.Username); err != nil {
		redirect(w, r, back, globalMsg(err), true)
		return
	}
	redirect(w, r, back, "Shared set deleted.", false)
}

// addGlobalSecret sets a secret name=value in a shared set.
func (s *Server) addGlobalSecret(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	back := "/global"
	if !s.guardPost(w, r, sess, back) {
		return
	}
	id := r.PathValue("id")
	name := strings.TrimSpace(r.FormValue("name"))
	value := r.FormValue("value")
	if name == "" {
		redirect(w, r, back, "Secret name is required.", true)
		return
	}
	if !keys.ValidSecretName(name) {
		redirect(w, r, back, "Secret names may use only letters, digits, '_', '-', '.'.", true)
		return
	}
	if err := s.keys.SetGlobalSecret(id, name, value, sess.Username); err != nil {
		redirect(w, r, back, globalMsg(err), true)
		return
	}
	redirect(w, r, back, "Global secret saved: "+name+".", false)
}

// deleteGlobalSecret removes a secret from a shared set.
func (s *Server) deleteGlobalSecret(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	back := "/global"
	if !s.guardPost(w, r, sess, back) {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirect(w, r, back, "Secret name is required.", true)
		return
	}
	if err := s.keys.DeleteGlobalSecret(r.PathValue("id"), name, sess.Username); err != nil {
		redirect(w, r, back, globalMsg(err), true)
		return
	}
	redirect(w, r, back, "Global secret removed: "+name+".", false)
}

// revealGlobalSecret decrypts ONE value from a set and returns it as JSON for the
// per-row "Show" toggle (audited by NAME only in keysvc).
func (s *Server) revealGlobalSecret(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if err := r.ParseForm(); err != nil {
		writeSecretJSON(w, http.StatusBadRequest, "", "Bad form data.")
		return
	}
	if !s.checkCSRF(r, sess) {
		writeSecretJSON(w, http.StatusForbidden, "", "Security check failed; reload the page.")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		writeSecretJSON(w, http.StatusBadRequest, "", "Secret name is required.")
		return
	}
	value, err := s.keys.RevealGlobalSecret(r.PathValue("id"), name, sess.Username)
	if err != nil {
		writeSecretJSON(w, http.StatusOK, "", globalMsg(err))
		return
	}
	s.notifier.Notify(model.EventSecretReveal, "secret revealed: "+name)
	writeSecretJSON(w, http.StatusOK, value, "")
}

// globalMsg maps a keysvc global-secrets error to a friendly message.
func globalMsg(err error) string {
	switch {
	case errors.Is(err, keysvc.ErrBadSetName):
		return "Set name may use only letters, digits, '_' and '-'."
	case errors.Is(err, keysvc.ErrNoRecipients):
		return "Choose at least one per-user key."
	case errors.Is(err, keysvc.ErrSetExists):
		return "A shared set with that name already exists."
	case errors.Is(err, keysvc.ErrKeyNotPerUser):
		return "A selected key is not a per-user key - only per-user keys can build a set."
	case errors.Is(err, keysvc.ErrKeyNoOwner):
		return "A selected per-user key has no owner - set its owner on the Keys page first."
	case errors.Is(err, keysvc.ErrNoUserKey):
		return "An owner OS user owns no generated per-user key."
	case errors.Is(err, keysvc.ErrNoUserKeyBase):
		return "An owner OS user has no key-store base set."
	case errors.Is(err, keysvc.ErrGlobalNotLocal):
		return "Global secrets can only be managed for OS users on this machine."
	case errors.Is(err, keysvc.ErrNoLocalMachine):
		return "Designate this machine first (Machines -> this machine)."
	default:
		return secretErr("Global secrets error", err)
	}
}
