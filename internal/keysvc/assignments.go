package keysvc

import (
	"strconv"

	"sopshq/internal/audit"
	"sopshq/internal/model"
	"sopshq/internal/store"
)

// Referential integrity for Assignment records.
//
// An Assignment ties a key to a project + machine + OS user (a project-less
// assignment, ProjectID == "", is a user's key-placement grant for an adopted
// key). When the Project or OS user it references is removed, the assignment is
// meaningless and must not linger: a lingering "dangling" assignment would keep
// a key looking used forever and block the key's own removal. These helpers keep
// the set consistent - cascading on a parent delete, self-healing pre-existing
// orphans, and telling a LIVE assignment from a dangling one for the key-delete
// guard. Every removal is a store tombstone (soft delete), so it replicates to
// peers like any other delete; audit rows carry ids and counts only.

// assignmentLive reports whether an assignment still points at records that
// exist: its Project (only when ProjectID is set) and its OS user must both be
// present and not tombstoned. A project-less placement assignment (ProjectID ==
// "") is live as long as its OS user is live. A dangling assignment - one whose
// project or user was already deleted - is NOT live.
func (s *Service) assignmentLive(a *model.Assignment) bool {
	if a.ProjectID != "" {
		if _, err := s.store.Projects.Get(a.ProjectID); err != nil {
			return false
		}
	}
	if _, err := s.store.OSUsers.Get(a.OSUserID); err != nil {
		return false
	}
	return true
}

// LiveKeyAssignments counts the assignments that reference keyID AND are still
// live (see assignmentLive). It backs the key-delete guard: a key is protected
// only while a real, still-referenced project or user uses it, so a dangling
// assignment (its project or user gone) never keeps the key stuck.
func (s *Service) LiveKeyAssignments(keyID string) int {
	n := 0
	for _, a := range s.store.Assignments.List() {
		if a.KeyID == keyID && s.assignmentLive(a) {
			n++
		}
	}
	return n
}

// CascadeDeleteProjectAssignments tombstones every assignment that references
// projectID, called when that project is deleted. It touches ONLY this project's
// assignments: an assignment for another project has a different ProjectID and a
// project-less placement assignment (ProjectID == "") never matches a real id, so
// both are spared. Returns how many were tombstoned.
func (s *Service) CascadeDeleteProjectAssignments(projectID, actor string) int {
	if projectID == "" {
		return 0
	}
	n := 0
	for _, a := range s.store.Assignments.List() {
		if a.ProjectID == projectID {
			if err := s.store.Assignments.Delete(a.M.UUID); err == nil {
				n++
			}
		}
	}
	if n > 0 {
		_ = s.audit.Record(actor, "assignment_cascade_project", projectID, audit.OK, strconv.Itoa(n)+" assignment(s) removed")
	}
	return n
}

// CascadeDeleteOSUserAssignments tombstones every assignment that references
// osUserID, called when that OS user is deleted (its assignments are meaningless
// without the account that holds the key). It touches ONLY this user's
// assignments; every other assignment has a different OSUserID and is spared.
// Returns how many were tombstoned.
func (s *Service) CascadeDeleteOSUserAssignments(osUserID, actor string) int {
	if osUserID == "" {
		return 0
	}
	n := 0
	for _, a := range s.store.Assignments.List() {
		if a.OSUserID == osUserID {
			if err := s.store.Assignments.Delete(a.M.UUID); err == nil {
				n++
			}
		}
	}
	if n > 0 {
		_ = s.audit.Record(actor, "assignment_cascade_osuser", osUserID, audit.OK, strconv.Itoa(n)+" assignment(s) removed")
	}
	return n
}

// PruneOrphanedAssignments tombstones every assignment whose parent is PROVABLY,
// durably gone - a Project (when set) or OS user that exists as a TOMBSTONE - so a
// dangling record left by an earlier delete self-heals. It deliberately does NOT prune
// an assignment whose parent id is merely absent from this node's store: during a
// partial sync an assignment can arrive before the Project/OSUser it references, and
// pruning then would destroy a still-valid grant. A project-less placement assignment
// (ProjectID == "") is kept as long as its OS user is not tombstoned. It is read-mostly
// and idempotent: with no orphans it only scans and writes nothing, and a tombstoned
// assignment leaves the live set so it is never re-processed. Returns how many were
// pruned. Audits the count only.
func (s *Service) PruneOrphanedAssignments(actor string) int {
	n := 0
	for _, a := range s.store.Assignments.List() {
		if s.assignmentProvablyOrphaned(a) {
			if err := s.store.Assignments.Delete(a.M.UUID); err == nil {
				n++
			}
		}
	}
	if n > 0 {
		_ = s.audit.Record(actor, "assignment_prune", strconv.Itoa(n), audit.OK, "orphaned assignment(s) removed")
	}
	return n
}

// assignmentProvablyOrphaned reports whether an assignment's parent has been truly
// DELETED (a tombstone with NO merge redirect), as opposed to merely not-yet-synced or
// MERGED away. It returns true only when the referenced Project (when ProjectID is set)
// or OS user exists in the store as a terminally tombstoned record. An id that is
// entirely unknown (never synced, or synced later) is NOT orphaned, so a partial-sync
// ordering never prunes a valid grant. A parent that was MERGED (its tombstone carries a
// MergedInto redirect) is NOT orphaned either: repointMergedRefs re-points the assignment
// onto the survivor instead, so the grant is preserved rather than deleted.
func (s *Service) assignmentProvablyOrphaned(a *model.Assignment) bool {
	if a.ProjectID != "" && tombstoneTerminal(s.store.Projects, a.ProjectID) {
		return true
	}
	if tombstoneTerminal(s.store.OSUsers, a.OSUserID) {
		return true
	}
	return false
}

// tombstoneTerminal reports whether id names a record that exists in c as a tombstone
// that was truly deleted - soft-deleted with NO MergedInto redirect. A merged-away
// tombstone (MergedInto set) returns false, because its references should be re-pointed
// to the survivor, not pruned. An empty or entirely-unknown id returns false, so a
// not-yet-synced reference is never mistaken for a deleted one.
func tombstoneTerminal[T model.Record](c *store.Collection[T], id string) bool {
	if id == "" {
		return false
	}
	rec, ok := c.GetRaw(id)
	return ok && rec.Meta().Deleted && rec.Meta().MergedInto == ""
}
