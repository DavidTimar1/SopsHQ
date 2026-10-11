package web

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"rsc.io/qr"

	"sopshq/internal/audit"
	"sopshq/internal/auth"
	"sopshq/internal/model"
	"sopshq/internal/store"
	"sopshq/internal/totp"
)

const setupCookie = "sopshq_setup"

// userByName finds an enabled-or-not panel user by username.
func (s *Server) userByName(name string) (*model.PanelUser, bool) {
	u, err := s.store.PanelUsers.Find(func(u *model.PanelUser) bool { return u.Username == name })
	if err != nil {
		return nil, false
	}
	return u, true
}

func (s *Server) userCount() int { return len(s.store.PanelUsers.List()) }

// ---- first-run setup ------------------------------------------------------

func (s *Server) getSetup(w http.ResponseWriter, r *http.Request) {
	if s.userCount() > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, "setup", auth.Session{}, "Set up SopsHQ", nil, http.StatusOK)
}

func (s *Server) postSetup(w http.ResponseWriter, r *http.Request) {
	if s.userCount() > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username == "" || len(password) < 8 {
		redirect(w, r, "/setup", "Username required and password must be at least 8 characters.", true)
		return
	}
	if _, exists := s.userByName(username); exists {
		redirect(w, r, "/setup", "That username already exists.", true)
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		s.renderError(w, r, auth.Session{}, "Could not hash password.", http.StatusInternalServerError)
		return
	}
	secret, err := totp.NewSecret()
	if err != nil {
		s.renderError(w, r, auth.Session{}, "Could not generate TOTP secret.", http.StatusInternalServerError)
		return
	}
	sealed, err := s.vault.Seal([]byte(secret))
	if err != nil {
		s.renderError(w, r, auth.Session{}, "Vault is locked.", http.StatusInternalServerError)
		return
	}
	u := &model.PanelUser{
		M:           model.Meta{UUID: store.NewID()},
		Username:    username,
		PassHash:    hash,
		TOTPSealed:  sealed,
		TOTPEnabled: false,
		Role:        model.RoleAdmin, // the first user is always an admin
		Enabled:     true,
	}
	if err := s.store.PanelUsers.Put(u); err != nil {
		s.renderError(w, r, auth.Session{}, "Could not save user.", http.StatusInternalServerError)
		return
	}
	s.audit.Record(username, "setup_create_admin", username, audit.OK, "first admin")
	// Mark this browser as mid-enrollment.
	http.SetCookie(w, &http.Cookie{
		Name: setupCookie, Value: u.M.UUID, Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 900,
	})
	http.Redirect(w, r, "/setup/totp", http.StatusSeeOther)
}

// setupTOTPData feeds the enrollment page.
type setupTOTPData struct {
	Secret string
	URI    string
	// QR is a "data:image/png;base64,..." URI of the otpauth QR, rendered
	// server-side and embedded inline so nothing is logged or fetched. It is
	// empty if QR rendering failed (the page then falls back to the manual key
	// and the otpauth URI). Typed template.URL so html/template does not mangle
	// the data URI in the img src.
	QR template.URL
	// RecoveryCodes are the one-time backup codes in PLAINTEXT, shown exactly once
	// on this page. Only their hashes are stored on the user; they are never
	// re-displayable.
	RecoveryCodes []string
}

// issueRecoveryCodes generates a fresh recovery-code set, persists ONLY the
// hashes on the user (replacing any old set), and returns the plaintext codes for
// one-time display. The plaintext is never stored or logged.
func (s *Server) issueRecoveryCodes(u *model.PanelUser) ([]string, error) {
	plain, hashes, err := auth.GenerateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	u.RecoveryCodes = hashes
	if err := s.store.PanelUsers.Put(u); err != nil {
		return nil, err
	}
	return plain, nil
}

// qrDataURI renders the otpauth URI as a PNG QR and returns it as an inline
// data URI, or empty on error. The input URI carries the TOTP secret, so it is
// never logged here - it is only encoded into the same image already shown on
// the page.
func qrDataURI(uri string) template.URL {
	c, err := qr.Encode(uri, qr.M)
	if err != nil {
		return ""
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(c.PNG()))
}

func (s *Server) getSetupTOTP(w http.ResponseWriter, r *http.Request) {
	u, ok := s.setupUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	secret, err := s.unsealTOTP(u)
	if err != nil {
		s.renderError(w, r, auth.Session{}, "Vault is locked.", http.StatusInternalServerError)
		return
	}
	// Fresh recovery codes are generated and persisted (as hashes) every time the
	// enrollment page is shown, and displayed once here. A refresh issues a new set
	// and invalidates the previous one - acceptable while enrollment is pending.
	codes, err := s.issueRecoveryCodes(u)
	if err != nil {
		s.renderError(w, r, auth.Session{}, "Could not generate recovery codes.", http.StatusInternalServerError)
		return
	}
	uri := totp.ProvisioningURI(secret, u.Username, "SopsHQ")
	data := setupTOTPData{Secret: secret, URI: uri, QR: qrDataURI(uri), RecoveryCodes: codes}
	s.render(w, r, "setup_totp", auth.Session{}, "Enroll authenticator", data, http.StatusOK)
}

func (s *Server) postSetupTOTP(w http.ResponseWriter, r *http.Request) {
	u, ok := s.setupUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	secret, err := s.unsealTOTP(u)
	if err != nil {
		s.renderError(w, r, auth.Session{}, "Vault is locked.", http.StatusInternalServerError)
		return
	}
	if r.FormValue("saved") != "yes" {
		redirect(w, r, "/setup/totp", "Confirm you have saved your recovery codes first.", true)
		return
	}
	if !totp.Verify(secret, r.FormValue("code")) {
		redirect(w, r, "/setup/totp", "That code did not match. Try again.", true)
		return
	}
	u.TOTPEnabled = true
	if err := s.store.PanelUsers.Put(u); err != nil {
		s.renderError(w, r, auth.Session{}, "Could not save user.", http.StatusInternalServerError)
		return
	}
	s.audit.Record(u.Username, "setup_totp_enabled", u.Username, audit.OK, "")
	// Clear the setup cookie and log the admin in.
	http.SetCookie(w, &http.Cookie{Name: setupCookie, Value: "", Path: "/", MaxAge: -1})
	s.startSession(w, r, u)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// setupUser resolves the mid-enrollment user from the setup cookie, but only
// while enrollment is still pending.
func (s *Server) setupUser(r *http.Request) (*model.PanelUser, bool) {
	c, err := r.Cookie(setupCookie)
	if err != nil {
		return nil, false
	}
	u, err := s.store.PanelUsers.Get(c.Value)
	if err != nil || u.TOTPEnabled {
		return nil, false
	}
	return u, true
}

// ---- login / logout -------------------------------------------------------

func (s *Server) getLogin(w http.ResponseWriter, r *http.Request) {
	if s.userCount() == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if _, ok := s.session(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login", auth.Session{}, "Sign in", nil, http.StatusOK)
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	code := r.FormValue("code")

	// Locked-out usernames are rejected up front, WITHOUT consulting the password
	// and WITHOUT revealing whether the username exists. The message is uniform.
	if locked, remaining := s.logins.locked(username); locked {
		secs := int(remaining.Seconds()) + 1
		s.audit.Record(username, "login", username, audit.Denied, "locked out")
		redirect(w, r, "/login", fmt.Sprintf("Too many attempts. Try again in %d seconds.", secs), true)
		return
	}

	fail := func() {
		// Uniform failure: never reveal which factor was wrong.
		s.audit.Record(username, "login", username, audit.Denied, "bad credentials")
		// Alert the operator by username only - never the submitted password.
		s.notifier.Notify(model.EventFailedLogin, "failed login for user "+username)
		// Count this failure; on transition into the locked state, alert once (NAME
		// only, never a password).
		if s.logins.fail(username) {
			s.audit.Record(username, "login_lockout", username, audit.Denied, "too many failed attempts")
			s.notifier.Notify(model.EventLockout, "account locked after repeated failed logins: "+username)
		}
		redirect(w, r, "/login", "Invalid username, password, or code.", true)
	}

	u, ok := s.userByName(username)
	if !ok || !u.Enabled {
		fail()
		return
	}
	pwOK, err := auth.VerifyPassword(u.PassHash, password)
	if err != nil || !pwOK {
		fail()
		return
	}
	// Password is correct. If this user has not yet enrolled an authenticator
	// (admin-created accounts start un-enrolled), send them to self-enrollment
	// rather than asking for a code they cannot have yet.
	if !u.TOTPEnabled {
		// The password cleared and we are progressing to enrollment: reset the slate.
		s.logins.succeed(username)
		http.SetCookie(w, &http.Cookie{
			Name: setupCookie, Value: u.M.UUID, Path: "/", HttpOnly: true,
			Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 900,
		})
		s.audit.Record(u.Username, "login_enroll_required", u.Username, audit.OK, "")
		http.Redirect(w, r, "/setup/totp", http.StatusSeeOther)
		return
	}
	secret, err := s.unsealTOTP(u)
	if err != nil {
		s.renderError(w, r, auth.Session{}, "Vault is locked.", http.StatusInternalServerError)
		return
	}
	if totp.Verify(secret, code) {
		s.logins.succeed(username)
		s.startSession(w, r, u)
		s.audit.Record(u.Username, "login", u.Username, audit.OK, "")
		s.notifier.Notify(model.EventNewSession, "panel session started for "+u.Username)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// Not a valid TOTP code: try the one-time recovery codes. On a match, consume
	// that code (drop its hash and persist) so it can never be reused. The audit
	// row records the event and the remaining count only - never the code value.
	if remaining, matched := auth.ConsumeRecoveryCode(u.RecoveryCodes, code); matched {
		u.RecoveryCodes = remaining
		if err := s.store.PanelUsers.Put(u); err != nil {
			s.renderError(w, r, auth.Session{}, "Could not consume recovery code.", http.StatusInternalServerError)
			return
		}
		left := len(remaining)
		s.logins.succeed(username)
		s.audit.Record(u.Username, "login_recovery_code", u.Username, audit.OK, fmt.Sprintf("%d codes left", left))
		s.startSession(w, r, u)
		msg := fmt.Sprintf("Signed in with a recovery code. %d recovery code(s) left.", left)
		if left == 0 {
			msg = "Signed in with your LAST recovery code. Re-enroll from Account to get a new set."
		} else if left <= 2 {
			msg += " Running low - re-enroll from Account to get a fresh set."
		}
		redirect(w, r, "/", msg, false)
		return
	}
	fail()
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	s.sessions.Delete(sess.Token)
	s.clearSessionCookie(w, r)
	s.audit.Record(sess.Username, "logout", sess.Username, audit.OK, "")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// startSession creates a session and sets the cookie.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u *model.PanelUser) {
	sess, err := s.sessions.Create(u.M.UUID, u.Username, u.Role)
	if err != nil {
		s.renderError(w, r, auth.Session{}, "Could not start session.", http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, r, sess.Token, sess.Expires)
	// On login, refresh the peer-drift cache so the header reflects current reality at
	// once. Local drift and the on-disk key discovery scan are recomputed fresh on the
	// dashboard render the operator lands on, so no explicit scan is needed here.
	s.refreshPendingAsync()
}

// unsealTOTP returns the user's TOTP secret in the clear (for verification or
// one-time enrollment display). The result is never logged.
func (s *Server) unsealTOTP(u *model.PanelUser) (string, error) {
	b, err := s.vault.Open(u.TOTPSealed)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ---- dashboard ------------------------------------------------------------
