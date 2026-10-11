package web

import (
	"bytes"
	"net/http"
	"net/url"

	"sopshq/internal/auth"
)

// viewData is the envelope passed to every template. Page-specific payload goes
// in Data; the rest is chrome the layout needs.
type viewData struct {
	Title    string
	NodeName string
	Version  string
	LoggedIn bool
	Username string
	IsAdmin  bool
	CSRF     string
	Flash    string // transient notice, taken from the ?flash= query param
	FlashErr bool   // true when the flash is an error (?err=1)
	Path     string // the request path, so an in-page form can return to it (Import)
	// Pending drives the header alert: true when there are changes to apply (on this
	// or another machine) or a peer that could not be verified. PendingSummary is the
	// alert's tooltip. Both come from the cached pending state.
	Pending        bool
	PendingSummary string
	Data           any
}

// render executes a page template within the layout. sess may be the zero value
// for unauthenticated pages (login/setup). status is the HTTP status to send.
func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, sess auth.Session, title string, data any, status int) {
	t, ok := s.tmpl[page]
	if !ok {
		http.Error(w, "template not found: "+page, http.StatusInternalServerError)
		return
	}
	vd := viewData{
		Title:    title,
		NodeName: s.nodeName,
		Version:  s.version,
		LoggedIn: sess.Token != "",
		Username: sess.Username,
		IsAdmin:  sess.Role == "admin",
		Flash:    r.URL.Query().Get("flash"),
		FlashErr: r.URL.Query().Get("err") == "1",
		Path:     r.URL.Path,
		Data:     data,
	}
	if sess.Token != "" {
		vd.CSRF = s.csrfToken(sess.Token)
		// LOCAL drift is recomputed fresh here (cheap, no network) so a change the
		// operator just made clears the alert on the next page without a manual Sync;
		// peer drift comes from the background cache.
		if st := s.livePending(r); st.Any() {
			vd.Pending = true
			vd.PendingSummary = pendingSummary(st)
		}
	}
	// Render to a buffer first so a template error does not emit a half page.
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", vd); err != nil {
		http.Error(w, "render error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// renderError shows the error page with a message.
func (s *Server) renderError(w http.ResponseWriter, r *http.Request, sess auth.Session, msg string, status int) {
	s.render(w, r, "error", sess, "Error", msg, status)
}

// redirect is a small helper for POST-redirect-GET with an optional flash.
func redirect(w http.ResponseWriter, r *http.Request, path, flash string, isErr bool) {
	if flash != "" {
		q := "?flash=" + url.QueryEscape(flash)
		if isErr {
			q += "&err=1"
		}
		path += q
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}
