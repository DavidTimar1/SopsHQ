package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"sopshq/internal/auth"
)

// purgeAllAudit deletes every audit entry. Admin-only and CSRF-checked. The purge
// is itself recorded (actor + count) by PurgeAllBy, so the trail is not silently
// emptied; the removed entries are gone for good.
func (s *Server) purgeAllAudit(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/audit") {
		return
	}
	removed, err := s.audit.PurgeAllBy(sess.Username)
	if err != nil {
		s.renderError(w, r, sess, "Could not purge the audit log.", http.StatusInternalServerError)
		return
	}
	redirect(w, r, "/audit", fmt.Sprintf("Purged all audit entries (%d removed).", removed), false)
}

// purgeAuditBefore deletes audit entries on or before the end of the chosen local
// day. Admin-only and CSRF-checked. The date arrives as "YYYY-MM-DD" from a date
// input; it is parsed in local time and extended to 23:59:59 so the whole chosen
// day is included. The purge is recorded (actor + count + cutoff) by PurgeBeforeBy.
func (s *Server) purgeAuditBefore(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/audit") {
		return
	}
	day := strings.TrimSpace(r.FormValue("date"))
	d, err := time.ParseInLocation("2006-01-02", day, time.Local)
	if err != nil {
		redirect(w, r, "/audit", "Choose a valid date (YYYY-MM-DD).", true)
		return
	}
	cutoff := d.Add(24*time.Hour - time.Second) // end of the chosen local day
	removed, err := s.audit.PurgeBeforeBy(sess.Username, cutoff)
	if err != nil {
		s.renderError(w, r, sess, "Could not purge the audit log.", http.StatusInternalServerError)
		return
	}
	redirect(w, r, "/audit", fmt.Sprintf("Purged %d audit entries on or before %s.", removed, day), false)
}
