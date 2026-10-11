package web

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"sopshq/internal/audit"
	"sopshq/internal/auth"
	"sopshq/internal/permmap"
)

// permmapResultLimit caps how many matching entries one /permmap/data response
// returns. A whole-server scan can hold hundreds of thousands of paths; the page
// shows this many and reports the true total so the operator narrows the filter
// or search rather than being silently cut off.
const permmapResultLimit = 2000

// permmapView backs the read-only permission auditor page. It carries the
// feature's state (available, enabled, scan-user readiness) and a summary of the
// latest scan - never the full map (that loads on demand through the data/tree
// endpoints).
type permmapView struct {
	Available    bool                   // true on Linux; false elsewhere (feature shows N/A)
	Enabled      bool                   // config master switch
	ScanUser     string                 // dedicated scan account name
	Roots        []string               // configured (or default) roots
	ScanStatus   permmap.ScanUserStatus // is the scan user provisioned + usable?
	Instructions string                 // copy-paste useradd/sudoers setup commands
	HasScan      bool                   // a latest scan exists
	ScannedAt    int64                  // Unix seconds when the latest scan ran (for fmtTime)
	Counts       permmap.Counts         // per-filter totals of the latest scan
	HasBaseline  bool                   // a baseline has been set
	BaselineAt   int64                  // Unix seconds when the baseline scan ran (for fmtTime)
	RootsText    string                 // roots joined one-per-line for the config textarea
}

// getPermmap renders the permission auditor page. Admin-only (the map reveals the
// whole filesystem layout and who can access what). It reads the latest scan's
// summary if present, but never streams the full map here.
func (s *Server) getPermmap(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	pm := s.cfg.PermissionMap
	roots := pm.EffectiveRoots()
	v := permmapView{
		Available:    runtime.GOOS == "linux",
		Enabled:      pm.Enabled,
		ScanUser:     pm.ScanUser,
		Roots:        roots,
		ScanStatus:   permmap.CheckScanUser(pm.ScanUser),
		Instructions: permmap.EnableInstructions(pm.ScanUser, roots),
		RootsText:    strings.Join(roots, "\n"),
	}
	if s.permmap != nil {
		if snap, err := s.permmap.ReadLatest(); err == nil && snap != nil {
			v.HasScan = true
			v.ScannedAt = snap.ScannedAt.Unix()
			v.Counts = permmap.Summarize(snap.Entries)
		}
		if base, err := s.permmap.ReadBaseline(); err == nil && base != nil {
			v.HasBaseline = true
			v.BaselineAt = base.ScannedAt.Unix()
		}
	}
	s.render(w, r, "permmap", sess, "Permissions", v, http.StatusOK)
}

// getPermmapData streams the filtered flat list of the latest scan as JSON. Query
// params: filter (one of the permmap.Filter keys), q (free-text search). The
// response is capped at permmapResultLimit with the true total reported.
func (s *Server) getPermmapData(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	snap := s.latestScan()
	if snap == nil {
		writeJSON(w, http.StatusOK, map[string]any{"entries": []permmap.Entry{}, "total": 0, "shown": 0, "limit": permmapResultLimit})
		return
	}
	f := permmap.Filter(r.URL.Query().Get("filter"))
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	entries, total := permmap.Query(snap.Entries, f, q, permmapResultLimit)
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"total":   total,
		"shown":   len(entries),
		"limit":   permmapResultLimit,
	})
}

// getPermmapTree returns the immediate children of one path as JSON, backing the
// lazy folder tree. With no path (or "/") it returns the configured roots so the
// tree starts there rather than at the filesystem root.
func (s *Server) getPermmapTree(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	snap := s.latestScan()
	if snap == nil {
		writeJSON(w, http.StatusOK, map[string]any{"nodes": []permmap.Node{}})
		return
	}
	parent := strings.TrimSpace(r.URL.Query().Get("path"))
	if parent == "" {
		writeJSON(w, http.StatusOK, map[string]any{"nodes": rootNodes(snap)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": permmap.Children(snap.Entries, parent)})
}

// rootNodes builds the top-level tree nodes from the scan's roots, so expansion
// starts at the operator's chosen roots.
func rootNodes(snap *permmap.Snapshot) []permmap.Node {
	byPath := make(map[string]permmap.Entry, len(snap.Entries))
	for _, e := range snap.Entries {
		byPath[e.Path] = e
	}
	childCount := map[string]int{}
	for _, e := range snap.Entries {
		childCount[parentDir(e.Path)]++
	}
	var nodes []permmap.Node
	for _, root := range snap.Roots {
		e := byPath[root]
		nodes = append(nodes, permmap.Node{
			Path: root, Name: root, Type: e.Type, IsDir: true,
			HasChildren: childCount[root] > 0,
			Owner:       e.Owner, Group: e.Group, Mode: e.Mode,
			WorldWritable: e.WorldWritable, HasACL: e.HasACL,
			ACLOverride: e.ACLOverride, Dangerous: e.Dangerous,
		})
	}
	return nodes
}

// parentDir returns the parent directory of a slash path, matching how
// permmap.Children keys immediate children.
func parentDir(p string) string {
	if i := strings.LastIndexByte(p, '/'); i > 0 {
		return p[:i]
	}
	return "/"
}

// getPermmapDiff returns the change set of the latest scan versus the baseline as
// JSON (added / removed / changed-with-before-after), backing the "changed since
// baseline" view.
func (s *Server) getPermmapDiff(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if s.permmap == nil {
		writeJSON(w, http.StatusOK, map[string]any{"has_baseline": false})
		return
	}
	base, err := s.permmap.ReadBaseline()
	if err != nil || base == nil {
		writeJSON(w, http.StatusOK, map[string]any{"has_baseline": false})
		return
	}
	latest := s.latestScan()
	if latest == nil {
		writeJSON(w, http.StatusOK, map[string]any{"has_baseline": true, "diff": permmap.Diff{}})
		return
	}
	d := permmap.Compare(base.Entries, latest.Entries)
	writeJSON(w, http.StatusOK, map[string]any{"has_baseline": true, "diff": d})
}

// latestScan reads the latest stored scan, returning nil on any error or when the
// feature has no store wired (so callers can render an empty state).
func (s *Server) latestScan() *permmap.Snapshot {
	if s.permmap == nil {
		return nil
	}
	snap, err := s.permmap.ReadLatest()
	if err != nil {
		return nil
	}
	return snap
}

// runPermScan executes one scan as the configured scan user and stores it as the
// latest. It is the shared body behind the panel "Scan now" button and the daily
// drift ticker. It returns the entry count or an error; it never logs the map.
func (s *Server) runPermScan() (int, error) {
	if s.permmap == nil {
		return 0, fmt.Errorf("permission auditor storage is not available")
	}
	pm := s.cfg.PermissionMap
	entries, err := permmap.Collect(pm.ScanUser, pm.EffectiveRoots())
	if err != nil {
		return 0, err
	}
	snap := &permmap.Snapshot{ScannedAt: time.Now(), Roots: pm.EffectiveRoots(), Entries: entries}
	if err := s.permmap.WriteLatest(snap); err != nil {
		return 0, err
	}
	return len(entries), nil
}

// scanPermmap runs a scan now (admin-only). It is synchronous: a large root set
// can take a while, and the page responds when the scan finishes. The audit row
// records the entry count only, never any path.
func (s *Server) scanPermmap(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/permmap") {
		return
	}
	if !s.cfg.PermissionMap.Enabled {
		redirect(w, r, "/permmap", "Enable the permission auditor before scanning.", true)
		return
	}
	n, err := s.runPermScan()
	if err != nil {
		s.audit.Record(sess.Username, "permmap_scan", "permmap", audit.Failed, err.Error())
		redirect(w, r, "/permmap", "Scan failed: "+err.Error(), true)
		return
	}
	s.audit.Record(sess.Username, "permmap_scan", "permmap", audit.OK, fmt.Sprintf("entries=%d", n))
	redirect(w, r, "/permmap", fmt.Sprintf("Scan complete: %d paths recorded.", n), false)
}

// baselinePermmap promotes the latest scan to the baseline (admin-only), so future
// drift diffs measure against this reference.
func (s *Server) baselinePermmap(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/permmap") {
		return
	}
	if s.permmap == nil {
		redirect(w, r, "/permmap", "Permission auditor storage is not available.", true)
		return
	}
	if err := s.permmap.PromoteLatestToBaseline(); err != nil {
		redirect(w, r, "/permmap", "Could not set the baseline: "+err.Error(), true)
		return
	}
	s.audit.Record(sess.Username, "permmap_baseline", "permmap", audit.OK, "")
	redirect(w, r, "/permmap", "Baseline set to the latest scan.", false)
}

// enablePermmap turns the feature on (admin-only) only after confirming the scan
// user is provisioned and can run the collectors; otherwise it refuses and points
// the operator at the setup instructions.
func (s *Server) enablePermmap(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/permmap") {
		return
	}
	st := permmap.CheckScanUser(s.cfg.PermissionMap.ScanUser)
	if !st.Usable {
		s.audit.Record(sess.Username, "permmap_enable", "permmap", audit.Denied, "scan user not usable")
		redirect(w, r, "/permmap", "Cannot enable: "+st.Detail, true)
		return
	}
	s.cfg.PermissionMap.Enabled = true
	if err := s.cfg.Save(); err != nil {
		s.renderError(w, r, sess, "Could not save the permission auditor setting.", http.StatusInternalServerError)
		return
	}
	s.audit.Record(sess.Username, "permmap_enable", "permmap", audit.OK, "")
	redirect(w, r, "/permmap", "Permission auditor enabled.", false)
}

// disablePermmap turns the feature off (admin-only). Stored scans are left in
// place; nothing new is collected while disabled.
func (s *Server) disablePermmap(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/permmap") {
		return
	}
	s.cfg.PermissionMap.Enabled = false
	if err := s.cfg.Save(); err != nil {
		s.renderError(w, r, sess, "Could not save the permission auditor setting.", http.StatusInternalServerError)
		return
	}
	s.audit.Record(sess.Username, "permmap_disable", "permmap", audit.OK, "")
	redirect(w, r, "/permmap", "Permission auditor disabled.", false)
}

// configPermmap saves the scan user and roots (admin-only). Roots come from a
// textarea, one per line; blanks are dropped. Changing the scan user does not
// enable the feature - the operator re-checks and enables separately.
func (s *Server) configPermmap(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/permmap") {
		return
	}
	scanUser := strings.TrimSpace(r.FormValue("scan_user"))
	var roots []string
	for _, line := range strings.Split(r.FormValue("roots"), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			roots = append(roots, t)
		}
	}
	s.cfg.PermissionMap.ScanUser = scanUser
	s.cfg.PermissionMap.Roots = roots
	// Saving config with the feature still enabled but an empty scan user would fail
	// validation; if the operator blanks the user, turn the feature off too.
	if scanUser == "" {
		s.cfg.PermissionMap.Enabled = false
	}
	if err := s.cfg.Save(); err != nil {
		s.renderError(w, r, sess, "Could not save the permission auditor settings.", http.StatusInternalServerError)
		return
	}
	s.audit.Record(sess.Username, "permmap_config", "permmap", audit.OK, fmt.Sprintf("user=%q roots=%d", scanUser, len(roots)))
	redirect(w, r, "/permmap", "Permission auditor settings saved.", false)
}
