package web

import (
	"net/http"

	"sopshq/internal/audit"
	"sopshq/internal/auth"
	"sopshq/internal/totp"
)

// accountData feeds the account/security page.
type accountData struct {
	Username     string
	Role         string
	RecoveryLeft int
	TOTPEnabled  bool
}

// getAccount shows the logged-in user's security page: 2FA status, how many
// recovery codes remain, and the controls to re-enroll their authenticator.
func (s *Server) getAccount(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	u, ok := s.userByName(sess.Username)
	if !ok {
		s.renderError(w, r, sess, "Your account was not found.", http.StatusInternalServerError)
		return
	}
	d := accountData{
		Username:     u.Username,
		Role:         string(u.Role),
		RecoveryLeft: len(u.RecoveryCodes),
		TOTPEnabled:  u.TOTPEnabled,
	}
	s.render(w, r, "account", sess, "Account security", d, http.StatusOK)
}

// reenrollTOTP starts a self re-enrollment: it generates a brand-new TOTP secret,
// re-seals it onto the user, disables 2FA until the new secret is verified, and
// hands off to the shared enrollment page (which issues a fresh recovery-code set
// and shows the QR). The old authenticator and old recovery codes are invalidated
// the moment the new secret is sealed. If the operator abandons the flow they are
// simply un-enrolled and the login flow routes them back to enrollment next time.
func (s *Server) reenrollTOTP(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/account") {
		return
	}
	u, ok := s.userByName(sess.Username)
	if !ok {
		s.renderError(w, r, sess, "Your account was not found.", http.StatusInternalServerError)
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
	u.RecoveryCodes = nil // invalidate the old set immediately; a fresh set is issued at enrollment
	if err := s.store.PanelUsers.Put(u); err != nil {
		s.renderError(w, r, sess, "Could not save user.", http.StatusInternalServerError)
		return
	}
	s.audit.Record(sess.Username, "totp_reenroll_start", sess.Username, audit.OK, "")
	// Mark this browser as mid-enrollment and hand off to the shared enrollment page.
	http.SetCookie(w, &http.Cookie{
		Name: setupCookie, Value: u.M.UUID, Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 900,
	})
	http.Redirect(w, r, "/setup/totp", http.StatusSeeOther)
}
