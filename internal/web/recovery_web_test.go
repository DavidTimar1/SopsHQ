package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"sopshq/internal/audit"
	"sopshq/internal/config"
	"sopshq/internal/keysvc"
	"sopshq/internal/model"
	"sopshq/internal/place"
	"sopshq/internal/store"
	"sopshq/internal/totp"
	"sopshq/internal/usage"
	"sopshq/internal/vault"
)

var reRecoveryCode = regexp.MustCompile(`<li><code class="mono user-select-all">([^<]+)</code></li>`)

// recoveryServer is testServer but also returns the audit-log path so a test can
// assert no recovery-code plaintext ever lands in an audit row.
func recoveryServer(t *testing.T) (ts *httptest.Server, st *store.Store, auditPath string) {
	t.Helper()
	t.Setenv("SOPS_AGE_KEY_FILE", "")
	dir := t.TempDir()
	v, err := vault.Init(filepath.Join(dir, "vault"), "test-pass")
	if err != nil {
		t.Fatalf("vault init: %v", err)
	}
	st, err = store.Open(filepath.Join(dir, "data"), "test-node", nil)
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	auditPath = filepath.Join(dir, "audit.jsonl")
	a := audit.Open(auditPath, "test-node", nil)
	cfg := config.Default(filepath.Join(dir, "config.jsonc"), dir, "test-node")
	ks := keysvc.New(st, v, a, cfg.LocalMachineID)
	ks.SetPlacer(place.WriteKeyStore)
	ks.SetDiscoverer(hermeticDiscoverer)
	place.DisableEffectsForTest(t)
	ks.SetUsage(usage.Open(filepath.Join(dir, "usage.jsonl")))
	srv, err := NewServer(st, v, a, ks, cfg, "test", time.Hour)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts = httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, st, auditPath
}

// userRecord finds a panel user by name for assertions.
func userRecord(t *testing.T, st *store.Store, name string) *model.PanelUser {
	t.Helper()
	u, err := st.PanelUsers.Find(func(u *model.PanelUser) bool { return u.Username == name })
	if err != nil {
		t.Fatalf("user %q not found: %v", name, err)
	}
	return u
}

// onboardCapturingCodes runs setup -> enrollment and returns the TOTP secret plus
// the plaintext recovery codes shown once on the enrollment page.
func onboardCapturingCodes(t *testing.T, ts *httptest.Server, c *http.Client, username, password string) (secret string, codes []string) {
	t.Helper()
	if _, err := c.PostForm(ts.URL+"/setup", url.Values{"username": {username}, "password": {password}}); err != nil {
		t.Fatalf("post setup: %v", err)
	}
	body := getBody(t, c, ts.URL+"/setup/totp")
	secret = extract(t, reSecret, body, "totp secret")
	for _, m := range reRecoveryCode.FindAllStringSubmatch(body, -1) {
		codes = append(codes, m[1])
	}
	if len(codes) == 0 {
		t.Fatalf("no recovery codes shown on enrollment page")
	}
	code, err := totp.Code(secret)
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	resp, err := c.PostForm(ts.URL+"/setup/totp", url.Values{"code": {code}, "saved": {"yes"}})
	if err != nil {
		t.Fatalf("post setup totp: %v", err)
	}
	resp.Body.Close()
	return secret, codes
}

func logout(t *testing.T, ts *httptest.Server, c *http.Client) {
	t.Helper()
	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/"), "csrf")
	resp, err := c.PostForm(ts.URL+"/logout", url.Values{"csrf": {csrf}})
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	resp.Body.Close()
}

func TestEnrollmentRefusedWithoutSavedConfirmation(t *testing.T) {
	ts, st, _ := recoveryServer(t)
	c := newClient(t)
	if _, err := c.PostForm(ts.URL+"/setup", url.Values{"username": {"admin"}, "password": {"supersecret"}}); err != nil {
		t.Fatalf("post setup: %v", err)
	}
	body := getBody(t, c, ts.URL+"/setup/totp")
	secret := extract(t, reSecret, body, "totp secret")
	code, _ := totp.Code(secret)

	// POST with a valid code but WITHOUT the saved-confirmation: must be refused.
	resp, err := c.PostForm(ts.URL+"/setup/totp", url.Values{"code": {code}})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if userRecord(t, st, "admin").TOTPEnabled {
		t.Fatalf("enrollment completed without the saved-codes confirmation")
	}

	// Now WITH the confirmation: enrollment completes.
	resp, err = c.PostForm(ts.URL+"/setup/totp", url.Values{"code": {code}, "saved": {"yes"}})
	if err != nil {
		t.Fatalf("post2: %v", err)
	}
	resp.Body.Close()
	if !userRecord(t, st, "admin").TOTPEnabled {
		t.Fatalf("enrollment should complete once saved is confirmed")
	}
}

func TestLoginWithRecoveryCodeConsumesIt(t *testing.T) {
	ts, st, auditPath := recoveryServer(t)
	c := newClient(t)
	_, codes := onboardCapturingCodes(t, ts, c, "admin", "supersecret")
	before := userRecord(t, st, "admin")
	if len(before.RecoveryCodes) != len(codes) {
		t.Fatalf("stored %d hashes, shown %d codes", len(before.RecoveryCodes), len(codes))
	}
	wantLeft := len(before.RecoveryCodes) - 1
	logout(t, ts, c)

	// Log in using a recovery code instead of a TOTP code.
	fresh := newClient(t)
	resp, err := fresh.PostForm(ts.URL+"/login", url.Values{
		"username": {"admin"}, "password": {"supersecret"}, "code": {codes[0]},
	})
	if err != nil {
		t.Fatalf("recovery login: %v", err)
	}
	resp.Body.Close()
	if body := getBody(t, fresh, ts.URL+"/"); !strings.Contains(body, "Dashboard") {
		t.Fatalf("recovery-code login did not reach the dashboard")
	}
	if got := len(userRecord(t, st, "admin").RecoveryCodes); got != wantLeft {
		t.Fatalf("recovery code not consumed: got %d remaining, want %d", got, wantLeft)
	}

	// The same code must not work a second time.
	again := newClient(t)
	again.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err = again.PostForm(ts.URL+"/login", url.Values{
		"username": {"admin"}, "password": {"supersecret"}, "code": {codes[0]},
	})
	if err != nil {
		t.Fatalf("second recovery login: %v", err)
	}
	defer resp.Body.Close()
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login") {
		t.Fatalf("reused recovery code should bounce back to /login, got %q", loc)
	}

	// No audit row may ever contain a recovery-code plaintext value.
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	for _, code := range codes {
		if strings.Contains(string(raw), code) {
			t.Fatalf("audit log leaked a recovery code value")
		}
	}
	if !strings.Contains(string(raw), "login_recovery_code") {
		t.Fatalf("expected a login_recovery_code audit event")
	}
}

func TestAdminResetClearsTOTPAndCodes(t *testing.T) {
	ts, st, auditPath := recoveryServer(t)
	admin := newClient(t)
	onboard(t, ts, admin, "admin", "supersecret")

	// Admin creates a developer who then enrolls (so they have codes + TOTPEnabled).
	csrf := extract(t, reCSRF, getBody(t, admin, ts.URL+"/users"), "csrf")
	resp, err := admin.PostForm(ts.URL+"/users", url.Values{
		"csrf": {csrf}, "new_user_name": {"dev"}, "new_user_secret": {"devpassword"}, "role": {"developer"},
	})
	if err != nil {
		t.Fatalf("create dev: %v", err)
	}
	resp.Body.Close()

	dev := newClient(t)
	if _, err := dev.PostForm(ts.URL+"/login", url.Values{"username": {"dev"}, "password": {"devpassword"}}); err != nil {
		t.Fatalf("dev login: %v", err)
	}
	body := getBody(t, dev, ts.URL+"/setup/totp")
	secret := extract(t, reSecret, body, "dev secret")
	var devCodes []string
	for _, m := range reRecoveryCode.FindAllStringSubmatch(body, -1) {
		devCodes = append(devCodes, m[1])
	}
	code, _ := totp.Code(secret)
	resp, _ = dev.PostForm(ts.URL+"/setup/totp", url.Values{"code": {code}, "saved": {"yes"}})
	resp.Body.Close()

	devUser := userRecord(t, st, "dev")
	if !devUser.TOTPEnabled || len(devUser.RecoveryCodes) == 0 {
		t.Fatalf("dev not properly enrolled")
	}

	// Admin resets the developer's 2FA.
	csrf = extract(t, reCSRF, getBody(t, admin, ts.URL+"/users"), "csrf")
	resp, err = admin.PostForm(ts.URL+"/users/"+devUser.M.UUID+"/reset-2fa", url.Values{"csrf": {csrf}})
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	resp.Body.Close()

	after := userRecord(t, st, "dev")
	if after.TOTPEnabled {
		t.Fatalf("admin reset did not clear TOTPEnabled")
	}
	if len(after.RecoveryCodes) != 0 {
		t.Fatalf("admin reset did not clear recovery codes")
	}

	raw, _ := os.ReadFile(auditPath)
	if !strings.Contains(string(raw), "reset_2fa_admin") {
		t.Fatalf("expected reset_2fa_admin audit event")
	}
	for _, dc := range devCodes {
		if strings.Contains(string(raw), dc) {
			t.Fatalf("audit log leaked a recovery code value")
		}
	}
}
