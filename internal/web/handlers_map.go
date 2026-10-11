package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"sopshq/internal/auth"
	"sopshq/internal/mapview"
	"sopshq/internal/model"
	"sopshq/internal/store"
)

// mapViewTab is one selectable view on the Map page (a built-in default or a
// stored custom view).
type mapViewTab struct {
	ID      string
	Name    string
	Custom  bool     // true for a stored (editable/deletable) view
	GroupBy []string // grouping attribute keys (custom views only, for the editor)
	Leaf    string   // leaf attribute key (custom views only, for the editor)
}

// attrOption is one attribute the Map editor offers as a grouping/leaf level.
type attrOption struct {
	Key   string
	Label string
}

// mapData backs the Map page: the selectable views, the active one, and the
// attribute vocabulary the editor orders into a new view.
type mapData struct {
	Views  []mapViewTab
	Active string
	Attrs  []attrOption
}

// getMap renders the Map page: the default + custom view tabs, a two-pane
// tree/detail shell, and the Map editor. The tree itself is loaded as JSON from
// /map/tree by the page-scoped script.
func (s *Server) getMap(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	data := mapData{Attrs: attrOptions()}
	for _, v := range mapview.DefaultViews() {
		data.Views = append(data.Views, mapViewTab{ID: v.ID, Name: v.Name})
	}
	for _, rec := range s.store.MapViews.List() {
		data.Views = append(data.Views, mapViewTab{
			ID: rec.M.UUID, Name: rec.Name, Custom: true, GroupBy: rec.GroupBy, Leaf: rec.Leaf,
		})
	}
	data.Active = r.URL.Query().Get("view")
	if !s.viewExists(data.Active) {
		data.Active = "default-projects"
	}
	s.render(w, r, "map", sess, "Map", data, http.StatusOK)
}

// getMapTree returns the built tree for ?view=<id> as JSON. The response carries
// names and record ids only - never a secret value - so it is safe to log.
func (s *Server) getMapTree(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	view, ok := s.resolveView(r.URL.Query().Get("view"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "unknown view"})
		return
	}
	nodes := mapview.Build(s.gatherMapInput(sess, view), view)
	writeJSON(w, http.StatusOK, map[string]any{
		"view":  view.ID,
		"name":  view.Name,
		"nodes": nodes,
	})
}

// gatherMapInput collects the value-free record snapshot the tree-builder groups.
// It reuses the same store reads the individual pages use; secret NAMES are read
// (never values) only when the view actually groups by SecretName.
func (s *Server) gatherMapInput(sess auth.Session, view mapview.View) mapview.Input {
	in := mapview.Input{
		Projects:    s.store.Projects.List(),
		Machines:    s.store.Machines.List(),
		OSUsers:     s.store.OSUsers.List(),
		Keys:        s.store.Keys.List(),
		Assignments: s.store.Assignments.List(),
		GlobalSets:  s.store.GlobalSets.List(),
	}
	wantSecrets := false
	for _, a := range view.Levels {
		if a == mapview.AttrSecretName {
			wantSecrets = true
			break
		}
	}
	if wantSecrets {
		in.SecretsByProject = map[string][]string{}
		for _, p := range in.Projects {
			if names, err := s.keys.ListSecrets(p.M.UUID); err == nil && len(names) > 0 {
				in.SecretsByProject[p.M.UUID] = names
			}
		}
		in.SecretsBySet = map[string][]string{}
		for _, set := range in.GlobalSets {
			if names, err := s.keys.ListGlobalSecrets(set.M.UUID); err == nil && len(names) > 0 {
				in.SecretsBySet[set.M.UUID] = names
			}
		}
	}
	return in
}

// resolveView turns a view id into a builder View: a built-in default (id starting
// "default-") or a stored custom view (id is a record UUID).
func (s *Server) resolveView(id string) (mapview.View, bool) {
	for _, v := range mapview.DefaultViews() {
		if v.ID == id {
			return v, true
		}
	}
	if rec, err := s.store.MapViews.Get(id); err == nil {
		return mapview.ViewFromRecord(rec), true
	}
	return mapview.View{}, false
}

// viewExists reports whether id names a known view (default or stored).
func (s *Server) viewExists(id string) bool {
	_, ok := s.resolveView(id)
	return ok
}

// createMapView stores a new custom view from the editor form (admin-only, CSRF).
func (s *Server) createMapView(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/map") {
		return
	}
	name, groupBy, leaf, ok := parseMapViewForm(r)
	if !ok {
		redirect(w, r, "/map", "Give the view a name and choose a leaf level.", true)
		return
	}
	rec := &model.MapView{M: model.Meta{UUID: store.NewID()}, Name: name, GroupBy: groupBy, Leaf: leaf}
	if err := s.store.MapViews.Put(rec); err != nil {
		redirect(w, r, "/map", secretErr("Could not save the view", err), true)
		return
	}
	redirect(w, r, "/map?view="+rec.M.UUID, "View created: "+name+".", false)
}

// updateMapView renames/reorders an existing custom view (admin-only, CSRF).
func (s *Server) updateMapView(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/map") {
		return
	}
	id := r.PathValue("id")
	rec, err := s.store.MapViews.Get(id)
	if err != nil {
		redirect(w, r, "/map", "That view no longer exists.", true)
		return
	}
	name, groupBy, leaf, ok := parseMapViewForm(r)
	if !ok {
		redirect(w, r, "/map?view="+id, "Give the view a name and choose a leaf level.", true)
		return
	}
	rec.Name, rec.GroupBy, rec.Leaf = name, groupBy, leaf
	if err := s.store.MapViews.Put(rec); err != nil {
		redirect(w, r, "/map?view="+id, secretErr("Could not save the view", err), true)
		return
	}
	redirect(w, r, "/map?view="+id, "View updated: "+name+".", false)
}

// deleteMapView removes a custom view (admin-only, CSRF).
func (s *Server) deleteMapView(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/map") {
		return
	}
	if err := s.store.MapViews.Delete(r.PathValue("id")); err != nil {
		redirect(w, r, "/map", "That view no longer exists.", true)
		return
	}
	redirect(w, r, "/map", "View deleted.", false)
}

// parseMapViewForm reads and validates the editor fields: a non-empty name, a
// comma-separated ordered "levels" list of grouping attribute keys, and a valid
// "leaf" attribute. Unknown or empty grouping keys (and any duplicate of the leaf)
// are dropped, so an odd submission still yields a usable view.
func parseMapViewForm(r *http.Request) (name string, groupBy []string, leaf string, ok bool) {
	name = strings.TrimSpace(r.FormValue("name"))
	leaf = strings.TrimSpace(r.FormValue("leaf"))
	if name == "" || !mapview.Valid(leaf) {
		return "", nil, "", false
	}
	seen := map[string]bool{}
	for _, key := range strings.Split(r.FormValue("levels"), ",") {
		key = strings.TrimSpace(key)
		if key == "" || key == leaf || seen[key] || !mapview.Valid(key) {
			continue
		}
		seen[key] = true
		groupBy = append(groupBy, key)
	}
	return name, groupBy, leaf, true
}

// attrOptions lists the editor's attribute vocabulary with display labels.
func attrOptions() []attrOption {
	var out []attrOption
	for _, a := range mapview.AllAttrs() {
		out = append(out, attrOption{Key: string(a), Label: mapview.Label(a)})
	}
	return out
}

// writeJSON encodes v as a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
