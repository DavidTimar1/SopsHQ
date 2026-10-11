package web

import (
	"errors"
	"net/http"

	"sopshq/internal/auth"
	"sopshq/internal/keysvc"
)

// reconcileData drives the external-change reconcile screen. It carries only the
// non-secret diff (paths, recipients, names) built by the key service.
type reconcileData struct {
	Diff keysvc.ChangeDiff
}

// handleExternalChange renders the reconcile screen when err reports that a
// managed file changed outside SopsHQ. It returns true when it handled the error,
// so the caller stops. Any other error returns false for normal handling.
func (s *Server) handleExternalChange(w http.ResponseWriter, r *http.Request, sess auth.Session, err error) bool {
	var ec *keysvc.ExternalChange
	if errors.As(err, &ec) {
		s.render(w, r, "reconcile", sess, "External change detected", reconcileData{Diff: ec.Diff}, http.StatusConflict)
		return true
	}
	return false
}

// postReconcile applies the operator's adopt/overwrite/cancel choice for a managed
// file that changed outside SopsHQ. It is admin-only and CSRF-protected; the key
// service audits each decision by target + action, never a value.
func (s *Server) postReconcile(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	kind := r.FormValue("kind")
	projectID := r.FormValue("project_id")
	osUserID := r.FormValue("os_user_id")
	action := r.FormValue("action")

	back := "/"
	if projectID != "" {
		back = "/projects/" + projectID
	}
	if !s.guardPost(w, r, sess, back) {
		return
	}

	switch action {
	case "cancel":
		redirect(w, r, back, "No changes made.", false)
		return
	case "adopt":
		if err := s.keys.ReconcileAdopt(kind, projectID, osUserID, sess.Username); err != nil {
			redirect(w, r, back, secretErr("Could not adopt the on-disk version", err), true)
			return
		}
		s.refreshPendingAsync()
		redirect(w, r, back, "Adopted the on-disk version; SopsHQ now tracks it.", false)
	case "overwrite":
		if err := s.keys.ReconcileOverwrite(kind, projectID, osUserID, sess.Username); err != nil {
			redirect(w, r, back, secretErr("Could not overwrite with SopsHQ's state", err), true)
			return
		}
		s.refreshPendingAsync()
		redirect(w, r, back, "Overwrote with SopsHQ's desired state.", false)
	default:
		redirect(w, r, back, "Choose adopt, overwrite, or cancel.", true)
	}
}
