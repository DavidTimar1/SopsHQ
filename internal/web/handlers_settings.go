package web

import (
	"net/http"

	"sopshq/internal/auth"
)

// settingsData drives the Settings page: the on-disk paths this machine uses, the
// self-backup panel (schedule, password state, destinations, last run), and the
// notifications panel (channels, toggles, credential status). All three expose
// names, paths, counts, and status only - never a secret value.
type settingsData struct {
	Paths     pathsInfo
	Backup    backupView
	Notify    notificationView
	Retention retentionView
	Keybase   keybaseRootView
}

// getSettings renders the Settings page (paths + backups + notifications).
// Login-gated; the backup and notification controls inside are admin-only via
// {{if .IsAdmin}} in the template.
func (s *Server) getSettings(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	d := settingsData{
		Paths:     s.pathsInfo(),
		Backup:    s.backupViewData(),
		Notify:    s.notificationViewData(),
		Retention: s.retentionViewData(),
		Keybase:   s.keybaseRootViewData(),
	}
	s.render(w, r, "settings", sess, "Settings", d, http.StatusOK)
}
