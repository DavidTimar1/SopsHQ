package web

import (
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"

	"sopshq/internal/audit"
	"sopshq/internal/auth"
	"sopshq/internal/usage"
	"sopshq/internal/usageshim"
)

// ingestPayload is the body a usage reporter (e.g. the sops shim) posts.
type ingestPayload struct {
	User   string `json:"user"`
	Path   string `json:"path"`
	KeyID  string `json:"key_id"`
	Source string `json:"source"`
}

// ingestKeyUsed records a best-effort key-usage event. It is NOT session-gated
// (the caller is a shim, not a browser); instead it requires the ingestion token
// in the X-SopsHQ-Token header. It deliberately accepts no key material.
func (s *Server) ingestKeyUsed(w http.ResponseWriter, r *http.Request) {
	if s.ingestToken == "" {
		http.NotFound(w, r)
		return
	}
	tok := r.Header.Get("X-SopsHQ-Token")
	if subtle.ConstantTimeCompare([]byte(tok), []byte(s.ingestToken)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var p ingestPayload
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&p); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	src := strings.TrimSpace(p.Source)
	if src == "" {
		src = "ingest"
	}
	if err := s.keys.RecordUse(strings.TrimSpace(p.User), strings.TrimSpace(p.Path), strings.TrimSpace(p.KeyID), src); err != nil {
		http.Error(w, "record failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// usageRow is one recent usage event with its resolved attribution for display.
type usageRow struct {
	usage.Event
	Keys string // comma-separated key names attributed
}

// usagePageData drives the Usage page: the recent events plus the install state of
// the optional sops usage shim on this machine.
type usagePageData struct {
	Rows []usageRow
	Shim usageshim.Status
}

func (s *Server) getUsage(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	events, err := s.keys.RecentUsage(300)
	if err != nil {
		s.renderError(w, r, sess, "Could not read usage log.", http.StatusInternalServerError)
		return
	}
	keyName := map[string]string{}
	for _, k := range s.store.Keys.List() {
		keyName[k.M.UUID] = k.Name
	}
	var rows []usageRow
	for _, ev := range events {
		var names []string
		for _, id := range s.keys.KeysForEvent(ev) {
			if n := keyName[id]; n != "" {
				names = append(names, n)
			}
		}
		rows = append(rows, usageRow{Event: ev, Keys: strings.Join(names, ", ")})
	}
	data := usagePageData{Rows: rows, Shim: usageshim.Stat(s.cfg.DataDir)}
	s.render(w, r, "usage", sess, "Usage", data, http.StatusOK)
}

// localPanelURL is the address the shim on THIS machine should report to: always
// loopback (the shim runs locally), using the configured panel port.
func (s *Server) localPanelURL() string {
	_, port, err := net.SplitHostPort(s.cfg.PanelListen)
	if err != nil {
		return "http://" + s.cfg.PanelListen
	}
	return "http://127.0.0.1:" + port
}

// installShim installs the optional sops usage shim for the current user on this
// machine (writes the wrapper, wires PATH + helper env vars). Reversible via
// uninstallShim. Audited; CSRF-protected.
func (s *Server) installShim(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/usage") {
		return
	}
	tokenFile := filepath.Join(s.cfg.DataDir, "ingest.token")
	st, err := usageshim.Install(s.cfg.DataDir, s.localPanelURL(), tokenFile)
	if err != nil {
		s.audit.Record(sess.Username, "shim_install", "", audit.Failed, err.Error())
		redirect(w, r, "/usage", "Could not install the usage shim: "+err.Error(), true)
		return
	}
	s.audit.Record(sess.Username, "shim_install", st.Dir, audit.OK, "")
	redirect(w, r, "/usage", "Usage shim installed. "+st.Note, false)
}

// uninstallShim removes the usage shim and reverts the PATH + env changes.
func (s *Server) uninstallShim(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/usage") {
		return
	}
	if err := usageshim.Uninstall(s.cfg.DataDir); err != nil {
		s.audit.Record(sess.Username, "shim_uninstall", "", audit.Failed, err.Error())
		redirect(w, r, "/usage", "Could not remove the usage shim: "+err.Error(), true)
		return
	}
	s.audit.Record(sess.Username, "shim_uninstall", "", audit.OK, "")
	redirect(w, r, "/usage", "Usage shim removed. Open a new terminal so PATH is restored.", false)
}
