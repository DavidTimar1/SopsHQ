package web

import (
	"net/http"
	"strings"

	"sopshq/internal/audit"
	"sopshq/internal/auth"
	"sopshq/internal/model"
	"sopshq/internal/store"
	"sopshq/internal/totp"
)

// panelUserRow is a panel user plus the human name of the machine its record
// originated on (Meta.Origin), resolved for display. A "-" means no machine
// record matches that origin id.
type panelUserRow struct {
	*model.PanelUser
	MachineName string
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	names := s.machineNames()
	users := s.store.PanelUsers.List()
	rows := make([]panelUserRow, 0, len(users))
	for _, u := range users {
		name := names[u.M.Origin]
		if name == "" {
			name = "-"
		}
		rows = append(rows, panelUserRow{PanelUser: u, MachineName: name})
	}
	s.render(w, r, "users", sess, "Panel users", rows, http.StatusOK)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/users") {
		return
	}
	username := strings.TrimSpace(r.FormValue("new_user_name"))
	password := r.FormValue("new_user_secret")
	role := model.Role(r.FormValue("role"))
	if username == "" || len(password) < 8 || (role != model.RoleAdmin && role != model.RoleDeveloper) {
		redirect(w, r, "/users", "Username, an 8+ char password, and a valid role are required.", true)
		return
	}
	if _, exists := s.userByName(username); exists {
		redirect(w, r, "/users", "That username already exists.", true)
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		s.renderError(w, r, sess, "Could not hash password.", http.StatusInternalServerError)
		return
	}
	secret, err := totp.NewSecret()
	if err != nil {
		s.renderError(w, r, sess, "Could not generate TOTP secret.", http.StatusInternalServerError)
		return
	}
	sealed, err := s.vault.Seal([]byte(secret))
	if err != nil {
		s.renderError(w, r, sess, "Vault is locked.", http.StatusInternalServerError)
		return
	}
	u := &model.PanelUser{
		M:           model.Meta{UUID: store.NewID()},
		Username:    username,
		PassHash:    hash,
		TOTPSealed:  sealed,
		TOTPEnabled: false, // the user enrolls their authenticator at first login
		Role:        role,
		Enabled:     true,
	}
	if err := s.store.PanelUsers.Put(u); err != nil {
		s.renderError(w, r, sess, "Could not save user.", http.StatusInternalServerError)
		return
	}
	s.audit.Record(sess.Username, "user_create", username, audit.OK, string(role))
	redirect(w, r, "/users", "User created. They enroll their authenticator at first login.", false)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/users") {
		return
	}
	id := r.PathValue("id")
	u, err := s.store.PanelUsers.Get(id)
	if err != nil {
		redirect(w, r, "/users", "User not found.", true)
		return
	}
	if u.M.UUID == sess.UserID {
		redirect(w, r, "/users", "You cannot delete your own account.", true)
		return
	}
	if u.Role == model.RoleAdmin && s.adminCount() <= 1 {
		redirect(w, r, "/users", "Cannot delete the last admin.", true)
		return
	}
	if err := s.store.PanelUsers.Delete(id); err != nil {
		redirect(w, r, "/users", "Could not delete user.", true)
		return
	}
	s.sessions.DeleteUser(u.Username)
	s.audit.Record(sess.Username, "user_delete", u.Username, audit.OK, "")
	redirect(w, r, "/users", "User deleted.", false)
}

// resetUserTOTP clears another user's 2FA so they re-enroll at next login. It
// rotates the TOTP secret (so the old authenticator is dead) and clears the
// recovery codes. The login flow already routes un-enrolled users to enrollment.
// Audited; never touches the operator's own account (use Account -> Re-enroll for
// that, which verifies a new code before replacing).
func (s *Server) resetUserTOTP(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/users") {
		return
	}
	id := r.PathValue("id")
	u, err := s.store.PanelUsers.Get(id)
	if err != nil {
		redirect(w, r, "/users", "User not found.", true)
		return
	}
	if u.M.UUID == sess.UserID {
		redirect(w, r, "/users", "Use Account -> Re-enroll to reset your own 2FA.", true)
		return
	}
	secret, err := totp.NewSecret()
	if err != nil {
		s.renderError(w, r, sess, "Could not generate TOTP secret.", http.StatusInternalServerError)
		return
	}
	sealed, err := s.vault.Seal([]byte(secret))
	if err != nil {
		s.renderError(w, r, sess, "Vault is locked.", http.StatusInternalServerError)
		return
	}
	u.TOTPSealed = sealed
	u.TOTPEnabled = false
	u.RecoveryCodes = nil
	if err := s.store.PanelUsers.Put(u); err != nil {
		s.renderError(w, r, sess, "Could not save user.", http.StatusInternalServerError)
		return
	}
	s.sessions.DeleteUser(u.Username) // force re-login + re-enrollment
	s.audit.Record(sess.Username, "reset_2fa_admin", u.Username, audit.OK, "")
	redirect(w, r, "/users", "2FA reset. "+u.Username+" will enroll a new authenticator at next login.", false)
}

// adminCount counts enabled admin panel users.
func (s *Server) adminCount() int {
	n := 0
	for _, u := range s.store.PanelUsers.List() {
		if u.Role == model.RoleAdmin {
			n++
		}
	}
	return n
}

// ---- audit ----------------------------------------------------------------

func (s *Server) getAudit(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	entries, err := s.audit.Recent(500)
	if err != nil {
		s.renderError(w, r, sess, "Could not read audit log.", http.StatusInternalServerError)
		return
	}
	s.render(w, r, "audit", sess, "Audit log", entries, http.StatusOK)
}
