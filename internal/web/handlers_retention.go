package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"sopshq/internal/audit"
	"sopshq/internal/auth"
	"sopshq/internal/config"
)

// retentionView is the Settings page "Audit retention" card data: this machine's
// current policy, exposed for the form to pre-fill. It carries no secret value.
type retentionView struct {
	DaysToKeep int    // remove entries older than this many days (0 = keep forever)
	Action     string // config.AuditActionPurge or config.AuditActionExportThenPurge
}

// retentionViewData reads this machine's audit-retention policy from the config,
// normalizing an empty action to the safer export-then-purge default for display.
func (s *Server) retentionViewData() retentionView {
	ret := s.cfg.AuditRetention
	action := ret.Action
	if action == "" {
		action = config.AuditActionExportThenPurge
	}
	return retentionView{DaysToKeep: ret.DaysToKeep, Action: action}
}

// saveRetention stores this machine's audit-retention policy (days to keep + the
// over-limit action) into config.jsonc. Admin-only and CSRF-checked. A negative or
// non-numeric day count is rejected with a flash; an unknown action falls back to
// the safer export-then-purge. The audit row records a non-secret summary only.
func (s *Server) saveRetention(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/settings") {
		return
	}
	days, err := strconv.Atoi(strings.TrimSpace(r.FormValue("days_to_keep")))
	if err != nil || days < 0 {
		redirect(w, r, "/settings", "Days to keep must be a whole number, 0 or more.", true)
		return
	}
	action := r.FormValue("action")
	if action != config.AuditActionPurge && action != config.AuditActionExportThenPurge {
		action = config.AuditActionExportThenPurge
	}
	s.cfg.AuditRetention.DaysToKeep = days
	s.cfg.AuditRetention.Action = action
	if err := s.cfg.Save(); err != nil {
		s.renderError(w, r, sess, "Could not save the retention settings.", http.StatusInternalServerError)
		return
	}
	summary := fmt.Sprintf("days=%d action=%s", days, action)
	s.audit.Record(sess.Username, "audit_retention_config", "config", audit.OK, summary)
	redirect(w, r, "/settings", "Audit retention settings saved.", false)
}
