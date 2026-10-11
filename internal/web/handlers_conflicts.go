package web

import (
	"net/http"
	"sort"
	"strings"

	"sopshq/internal/auth"
	"sopshq/internal/keysvc"
)

// Conflict resolution UI: the operator-facing half of the rule that replication never loses data silently.
//
// The reconcile pass leaves two records intact whenever merging them would drop a
// non-empty field (see internal/keysvc/reconcile.go). These handlers surface those
// left-intact groups (GET /conflicts), and resolve each one deliberately:
//
//   - MERGE INTO ONE is a two-step, double-confirmed flow. Step 1 is the /conflicts
//     list itself: for each group it shows what is KEPT vs DELETED and a radio per
//     genuinely-differing field. Submitting the picks renders a SEPARATE step-2 page
//     (POST /conflicts/merge/confirm) that restates exactly which records will be
//     permanently deleted and requires an explicit checkbox. Only that step-2 page can
//     reach POST /conflicts/merge/execute, which independently refuses unless the
//     checkbox token is present - so a deletion is impossible without both confirmations.
//   - KEEP BOTH (POST /conflicts/keep-both) records a replicated marker that the records
//     are intentionally distinct; it deletes nothing, so it is a single confirmation.
//
// Every route is login-gated (s.protect) and CSRF-checked (guardPost). No secret value
// is ever shown or logged - only non-secret distinguishing facts and provenance.

// listConflicts renders the "Conflicts to resolve" page: every group the lossless pass
// left intact, each with its non-secret facts and inline resolution controls.
func (s *Server) listConflicts(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	groups := s.keys.DetectConflicts()
	fields := s.keys.DetectFieldConflicts()
	data := struct {
		Groups []keysvc.ConflictGroup
		Fields []keysvc.FieldConflictVM
	}{groups, fields}
	s.render(w, r, "conflicts", sess, "Conflicts to resolve", data, http.StatusOK)
}

// confirmFieldConflict is step 1 of the field-conflict flow: it re-reads the CURRENT
// conflict, binds the operator's pick, and renders the final confirmation page (which
// value is kept, which is discarded, an explicit checkbox). It writes nothing.
func (s *Server) confirmFieldConflict(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/conflicts") {
		return
	}
	id := r.FormValue("id")
	pick := r.FormValue("pick")
	vm, ok := s.keys.FieldConflictByID(id)
	if !ok {
		redirect(w, r, "/conflicts", "That conflict has changed; review it again.", true)
		return
	}
	if pick != keysvc.FieldPickLocal && pick != keysvc.FieldPickRemote {
		pick = keysvc.FieldPickLocal
	}
	chosen, discarded := vm.Local, vm.Remote
	if pick == keysvc.FieldPickRemote {
		chosen, discarded = vm.Remote, vm.Local
	}
	data := struct {
		Conflict  keysvc.FieldConflictVM
		Pick      string
		Chosen    keysvc.FieldCandidate
		Discarded keysvc.FieldCandidate
	}{vm, pick, chosen, discarded}
	s.render(w, r, "field_conflict_confirm", sess, "Confirm field choice", data, http.StatusOK)
}

// executeFieldConflict is the FINAL step: it refuses unless the step-2 confirmation
// checkbox is present, then writes the chosen value with a dominating version vector
// (which replicates and converges the other machine) and clears the conflict.
func (s *Server) executeFieldConflict(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/conflicts") {
		return
	}
	if r.FormValue("confirm_overwrite") != "yes" {
		redirect(w, r, "/conflicts", "Cancelled: the overwrite was not confirmed.", true)
		return
	}
	id := r.FormValue("id")
	pick := r.FormValue("pick")
	if _, ok := s.keys.FieldConflictByID(id); !ok {
		redirect(w, r, "/conflicts", "That conflict has changed; review it again.", true)
		return
	}
	if err := s.keys.ResolveFieldConflict(id, pick, sess.Username); err != nil {
		redirect(w, r, "/conflicts", "Could not resolve: "+err.Error(), true)
		return
	}
	s.refreshPendingAsync()
	redirect(w, r, "/conflicts", "Field resolved; the chosen value now applies on both machines.", false)
}

// pickVM is one resolved field choice carried from step 1 into step 2 and execute.
type pickVM struct {
	FieldKey   string
	FieldLabel string
	RecordID   string // the record whose value wins
	Display    string // non-secret rendering of the chosen value (or provenance for a secret)
	Secret     bool
}

// confirmConflictMerge is step 2 of the merge flow: it re-reads the CURRENT group, binds
// the operator's picks, and renders the final confirmation page (which records will be
// deleted, an explicit checkbox). It writes nothing.
func (s *Server) confirmConflictMerge(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/conflicts") {
		return
	}
	entity := r.FormValue("entity")
	ids := splitIDs(r.FormValue("ids"))
	g, ok := s.keys.ConflictGroupByIDs(entity, ids)
	if !ok {
		redirect(w, r, "/conflicts", "That conflict has changed; review it again.", true)
		return
	}
	// Resolve each differing field's pick (default to the survivor's own value when the
	// operator left it unset, so a merge always has a defined winner).
	var picks []pickVM
	for _, f := range g.Fields {
		chosen := strings.TrimSpace(r.FormValue("pick_" + f.Key))
		if !validOption(f, chosen) {
			chosen = g.SurvivorID
		}
		picks = append(picks, pickVM{
			FieldKey:   f.Key,
			FieldLabel: f.Label,
			RecordID:   chosen,
			Display:    optionDisplay(f, chosen),
			Secret:     f.Secret,
		})
	}
	var survivor keysvc.ConflictRecord
	var losers []keysvc.ConflictRecord
	for _, rec := range g.Records {
		if rec.UUID == g.SurvivorID {
			survivor = rec
		} else {
			losers = append(losers, rec)
		}
	}
	data := struct {
		Group    keysvc.ConflictGroup
		Survivor keysvc.ConflictRecord
		Losers   []keysvc.ConflictRecord
		Picks    []pickVM
		IDs      string
	}{g, survivor, losers, picks, strings.Join(ids, ",")}
	s.render(w, r, "conflict_merge", sess, "Confirm merge", data, http.StatusOK)
}

// executeConflictMerge is the FINAL step: it refuses unless the step-2 confirmation
// checkbox is present (so it can never run straight from step 1), then merges the group
// into one record, re-points references, and tombstones the losers.
func (s *Server) executeConflictMerge(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/conflicts") {
		return
	}
	// The second, explicit confirmation. Without it, nothing is deleted.
	if r.FormValue("confirm_delete") != "yes" {
		redirect(w, r, "/conflicts", "Merge cancelled: the deletion was not confirmed.", true)
		return
	}
	entity := r.FormValue("entity")
	ids := splitIDs(r.FormValue("ids"))
	// Re-validate the group is still exactly as reviewed before deleting anything.
	g, ok := s.keys.ConflictGroupByIDs(entity, ids)
	if !ok {
		redirect(w, r, "/conflicts", "That conflict has changed; review it again.", true)
		return
	}
	picks := map[string]string{}
	for _, f := range g.Fields {
		chosen := strings.TrimSpace(r.FormValue("pick_" + f.Key))
		if !validOption(f, chosen) {
			chosen = g.SurvivorID
		}
		picks[f.Key] = chosen
	}
	if err := s.keys.ResolveMerge(entity, ids, picks, sess.Username); err != nil {
		redirect(w, r, "/conflicts", "Could not merge: "+err.Error(), true)
		return
	}
	// A machine merge may have absorbed this node's own record; the reconcile pass
	// follows the redirect and persists the new cfg.LocalMachineID.
	s.reconcileCluster()
	s.refreshPendingAsync()
	redirect(w, r, "/conflicts", "Records merged into one; the duplicates were removed.", false)
}

// keepBothConflict records the operator's "these are different things" decision (a
// replicated marker) so the pass stops surfacing the group. It deletes nothing.
func (s *Server) keepBothConflict(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/conflicts") {
		return
	}
	entity := r.FormValue("entity")
	ids := splitIDs(r.FormValue("ids"))
	if err := s.keys.KeepBothDistinct(entity, ids, sess.Username); err != nil {
		redirect(w, r, "/conflicts", "Could not keep both: "+err.Error(), true)
		return
	}
	s.refreshPendingAsync()
	redirect(w, r, "/conflicts", "Kept both records; they will no longer be flagged as a conflict.", false)
}

// splitIDs parses the comma-joined record-id form field into a sorted slice.
func splitIDs(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// validOption reports whether recordID is one of the field's offered options.
func validOption(f keysvc.ConflictField, recordID string) bool {
	for _, o := range f.Options {
		if o.RecordID == recordID {
			return true
		}
	}
	return false
}

// optionDisplay returns the display text of the chosen option (empty if not offered).
func optionDisplay(f keysvc.ConflictField, recordID string) string {
	for _, o := range f.Options {
		if o.RecordID == recordID {
			return o.Display
		}
	}
	return ""
}
