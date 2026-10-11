package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"sopshq/internal/auth"
	"sopshq/internal/keys"
	"sopshq/internal/keysvc"
)

// secretsCatalogData is the payload for the cross-project Secrets page. Groups
// carry NO plaintext value (values are revealed on demand via the existing
// per-project reveal endpoint); Err is a friendly note when the sweep could not
// run (e.g. no local machine designated).
type secretsCatalogData struct {
	Groups []keysvc.SecretGroup
	Err    string
}

// getSecretsCatalog renders the cross-project Secrets catalog. It is admin-only
// (a mass-decrypt surface): building it decrypts every locally-readable
// project's secrets in memory to group identical values, then discards the
// plaintext. Values render masked and are revealed one at a time through the
// audited per-project reveal endpoint.
func (s *Server) getSecretsCatalog(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	data := secretsCatalogData{}
	groups, err := s.keys.SecretsCatalog(sess.Username)
	if err != nil {
		data.Err = secretErr("Could not build the secrets catalog", err)
	} else {
		data.Groups = groups
	}
	s.render(w, r, "secrets", sess, "Secrets", data, http.StatusOK)
}

// getSecretsCatalogJSON returns the cross-project catalog as JSON for the reuse
// picker on the project page. Admin-only, like the Secrets page (it triggers the
// same in-memory bulk decrypt). The payload is VALUE-FREE: per value group it
// carries the masked count, a source (project + name) to copy the value from at
// add time, and the usage names/locations - never a plaintext value.
func (s *Server) getSecretsCatalogJSON(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	groups, err := s.keys.SecretsCatalog(sess.Username)
	if err != nil {
		http.Error(w, "catalog unavailable", http.StatusServiceUnavailable)
		return
	}
	type usageJSON struct {
		ProjectID string `json:"project_id"`
		Name      string `json:"name"`
		Project   string `json:"project"`
		Machine   string `json:"machine"`
		User      string `json:"user"`
		Key       string `json:"key"`
		Path      string `json:"path"`
	}
	type groupJSON struct {
		Count  int         `json:"count"`
		Usages []usageJSON `json:"usages"`
	}
	out := make([]groupJSON, 0, len(groups))
	for _, g := range groups {
		gj := groupJSON{Count: g.Count}
		for _, u := range g.Usages {
			if u.SetID != "" {
				continue // global-set secrets have no project path to copy from
			}
			gj.Usages = append(gj.Usages, usageJSON{u.ProjectID, u.Name, u.Project, u.Machine, u.User, u.Key, u.Path})
		}
		if len(gj.Usages) == 0 {
			continue // an all-global value group offers nothing to reuse here
		}
		out = append(out, gj)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// secretEditData backs the cross-project edit page reached from the Secrets
// catalog: it shows the decrypted value (admin only, in the HTTP response body;
// the panel is served over plain HTTP by default on loopback, so front it with a
// TLS terminator before binding it off-loopback) and every place that holds the
// exact same (name, value), which a save updates together.
type secretEditData struct {
	SourceProject string
	Name          string
	Value         string
	Occurrences   []keysvc.SecretOccurrence
}

// getSecretEdit loads the catalog edit form for one secret (project + name from the
// query - both non-secret). Admin-only.
func (s *Server) getSecretEdit(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	proj := r.URL.Query().Get("project")
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	value, err := s.keys.GetSecretValue(proj, name)
	if err != nil {
		s.renderError(w, r, sess, secretErr("Could not read secret", err), http.StatusBadRequest)
		return
	}
	data := secretEditData{
		SourceProject: proj,
		Name:          name,
		Value:         value,
		Occurrences:   s.keys.FindSecretOccurrences(name, value),
	}
	s.render(w, r, "secret_edit", sess, "Edit secret", data, http.StatusOK)
}

// postSecretEdit applies a rename/revalue to EVERY place holding the secret's
// exact (orig name, current value) - the whole point of editing from the catalog.
// Admin-only; CSRF-checked; audited by name.
func (s *Server) postSecretEdit(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/secrets") {
		return
	}
	proj := r.FormValue("source_project")
	origName := strings.TrimSpace(r.FormValue("orig_name"))
	name := strings.TrimSpace(r.FormValue("name"))
	value := r.FormValue("value")
	if name == "" || !keys.ValidSecretName(name) {
		redirect(w, r, "/secrets", "Secret names may use only letters, digits, '_', '-', '.'.", true)
		return
	}
	oldValue, err := s.keys.GetSecretValue(proj, origName)
	if err != nil {
		redirect(w, r, "/secrets", secretErr("Could not read secret", err), true)
		return
	}
	occ := s.keys.FindSecretOccurrences(origName, oldValue)
	ok := 0
	for _, res := range s.keys.MassUpdateSecret(occ, origName, name, value, sess.Username) {
		if res.OK {
			ok++
		}
	}
	redirect(w, r, "/secrets", fmt.Sprintf("Updated %q in %d place(s).", name, ok), false)
}

// bulkAddSecrets copies the operator's picked secrets into this project. Each
// checked picker row submits a "pick" field of the form
// "<source project id>|<secret name>". For each pick, the value is decrypted from the
// source on demand and written into this project (Path 1) under the source name;
// existing names are skipped, never overwritten. CSRF-protected; audited by name.
func (s *Server) bulkAddSecrets(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	id := r.PathValue("id")
	back := "/projects/" + id
	if !s.guardPost(w, r, sess, back) {
		return
	}
	var items []keysvc.ReuseItem
	for _, pick := range r.Form["pick"] {
		src := strings.SplitN(pick, "|", 2)
		if len(src) != 2 || src[0] == "" || src[1] == "" {
			continue
		}
		items = append(items, keysvc.ReuseItem{SourceProjectID: src[0], SourceName: src[1], TargetName: src[1]})
	}
	if len(items) == 0 {
		redirect(w, r, back, "No secrets were selected.", true)
		return
	}
	added, skipped, err := s.keys.BulkReuseSecrets(id, items, sess.Username)
	if err != nil {
		redirect(w, r, back, secretErr("Could not add secrets", err), true)
		return
	}
	msg := bulkAddSummary(added, skipped)
	redirect(w, r, back, msg, len(added) == 0)
}

// bulkAddSummary builds an ASCII flash describing what was added and skipped
// (names only, never values).
func bulkAddSummary(added, skipped []string) string {
	var b strings.Builder
	if len(added) > 0 {
		b.WriteString("Added " + strconv.Itoa(len(added)) + " secret(s): " + strings.Join(added, ", ") + ".")
	} else {
		b.WriteString("No secrets added.")
	}
	if len(skipped) > 0 {
		b.WriteString(" Skipped " + strconv.Itoa(len(skipped)) + " (already present or invalid): " + strings.Join(skipped, ", ") + ".")
	}
	return b.String()
}
