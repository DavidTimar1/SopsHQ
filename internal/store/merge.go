package store

import (
	"encoding/json"
	"time"

	"sopshq/internal/model"
)

// Per-field replication merge (see model/merge.go for the model side).
//
// This file holds the store's half of per-field merge: stamping a field group's
// version vector on a local Put, and merging a remote record into the local one
// field-group by field-group in ApplyRemote. A record type that does not implement
// model.Merger never reaches this code - it keeps whole-record last-writer-wins.

// fingerprintsOf snapshots every field group's fingerprint for a Merger record.
func fingerprintsOf(mg model.Merger) map[string]string {
	out := make(map[string]string, len(mg.Groups()))
	for _, g := range mg.Groups() {
		out[g] = mg.Fingerprint(g)
	}
	return out
}

// snapshotSaved records rec's current field fingerprints as the last-saved baseline,
// so the NEXT local Put can tell which groups actually changed. Caller holds c.mu.
func (c *Collection[T]) snapshotSaved(rec T) {
	if mg, ok := any(rec).(model.Merger); ok {
		c.saved[rec.Meta().UUID] = fingerprintsOf(mg)
	}
}

// stampLocalVV bumps the version vector of every field group whose value changed
// since the last save - the local-write rule. A new record's groups all count as
// changed from empty, so each non-empty group gets its first vector. Caller holds
// c.mu and has already set m.Origin to this node.
func (c *Collection[T]) stampLocalVV(rec T, mg model.Merger) {
	m := rec.Meta()
	prev := c.saved[m.UUID] // nil for a brand-new record
	for _, g := range mg.Groups() {
		fp := mg.Fingerprint(g)
		if fp == prev[g] {
			continue // unchanged since last save
		}
		setVV(m, g, m.FieldVV[g].Bump(c.store.node))
	}
}

// setVV writes group g's version vector into a record's Meta, allocating the map on
// first use.
func setVV(m *model.Meta, g string, vv model.VClock) {
	if m.FieldVV == nil {
		m.FieldVV = map[string]model.VClock{}
	}
	m.FieldVV[g] = vv
}

// vclockEqual reports whether two vectors record the identical counters.
func vclockEqual(a, b model.VClock) bool {
	return model.CompareVClock(a, b) == model.VCEqual
}

// applyMerger merges a remote Merger record into the local one field-group by
// field-group. It keeps a group's local value on a genuine same-group divergence
// (recording a FieldConflict), takes the remote value on a causal update, and unions
// the version vectors on a converged (equal-value) group. Caller holds c.mu.
func (c *Collection[T]) applyMerger(existing, rec T, lm, rm model.Merger) (applied, conflict bool, err error) {
	lmeta := existing.Meta()
	rmeta := rec.Meta()
	changed := false
	anyConflict := false

	for _, g := range lm.Groups() {
		lv := lmeta.FieldVV[g] // may be nil (never-written)
		rv := rmeta.FieldVV[g]
		lval := lm.Fingerprint(g)
		rval := rm.Fingerprint(g)

		if lval == rval {
			// Same value on both sides: converge the vectors, never a conflict.
			merged := lv.MergeMax(rv)
			if !vclockEqual(merged, lv) {
				setVV(lmeta, g, merged)
				changed = true
			}
			c.store.clearFieldConflict(c.kind, lmeta.UUID, g)
			continue
		}

		// Values differ. Decide with the version vectors.
		switch {
		case lv.Empty() && rv.Empty():
			// Neither side has a per-field vector for this group (both legacy). Fall
			// back to whole-record last-writer-wins by Updated, with no conflict surfaced.
			if rmeta.Updated.Compare(lmeta.Updated) > 0 {
				lm.AdoptGroup(g, rec)
				changed = true
			}
			c.store.clearFieldConflict(c.kind, lmeta.UUID, g)
		case !lv.Empty() && rv.Empty():
			// Local made an explicit field edit; remote is only the legacy baseline.
			// The explicit edit is causally newer - keep local.
			c.store.clearFieldConflict(c.kind, lmeta.UUID, g)
		case lv.Empty() && !rv.Empty():
			// Symmetric: remote made the explicit edit - adopt it.
			lm.AdoptGroup(g, rec)
			setVV(lmeta, g, rv.Clone())
			changed = true
			c.store.clearFieldConflict(c.kind, lmeta.UUID, g)
		default:
			switch model.CompareVClock(lv, rv) {
			case model.VCDominatesA:
				// Local has seen everything remote has, and more - keep local.
				c.store.clearFieldConflict(c.kind, lmeta.UUID, g)
			case model.VCDominatesB:
				// Remote is a causal successor - take its value and vector.
				lm.AdoptGroup(g, rec)
				setVV(lmeta, g, rv.Clone())
				changed = true
				c.store.clearFieldConflict(c.kind, lmeta.UUID, g)
			default:
				// Concurrent (or an equal-vector/differing-value anomaly): a genuine
				// same-field divergence. Keep the LOCAL value untouched and record the
				// peer's candidate for operator resolution. Never overwrite.
				anyConflict = true
				if e := c.recordGroupConflict(rec, g); e != nil {
					return changed, true, e
				}
			}
		}
	}

	lm.Fold(rec)
	// Advance the whole-record clock/origin to the later side, so provenance and the
	// record's own Updated stay monotonic even though the body is a merge.
	if rmeta.Updated.Compare(lmeta.Updated) > 0 {
		lmeta.Updated = rmeta.Updated
		lmeta.Origin = rmeta.Origin
		changed = true
	}

	if changed || anyConflict {
		if err := c.save(); err != nil {
			return false, anyConflict, err
		}
		c.snapshotSaved(existing)
	}
	return changed, anyConflict, nil
}

// recordGroupConflict stashes the peer's whole record as the losing candidate for a
// same-field divergence on group g, so /conflicts can offer it as a pick. Caller
// holds c.mu (of THIS collection; the FieldConflicts collection has its own lock).
func (c *Collection[T]) recordGroupConflict(rec T, group string) error {
	snap, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	m := rec.Meta()
	c.store.recordFieldConflict(c.kind, m.UUID, group, snap, m.Origin, m.Updated.Wall)
	return nil
}

// recordFieldConflict upserts a machine-local FieldConflict row for a diverged
// record + group (deterministic id, so re-detecting the same divergence overwrites
// rather than duplicates). It never appends to the oplog (the collection is
// localOnly). Never called with any unsealed secret; the snapshot is stored verbatim.
func (s *Store) recordFieldConflict(kind, recordUUID, group string, snapshot []byte, origin string, updatedWall int64) {
	id := model.FieldConflictID(kind, recordUUID, group)
	fc := &model.FieldConflict{
		M:              model.Meta{UUID: id},
		Kind:           kind,
		RecordUUID:     recordUUID,
		Group:          group,
		RemoteSnapshot: append([]byte(nil), snapshot...),
		RemoteOrigin:   origin,
		DetectedAt:     time.Now().Unix(),
	}
	fc.RemoteUpdated.Wall = updatedWall
	_ = s.FieldConflicts.Put(fc)
}

// DiscardFieldConflict removes the machine-local FieldConflict row with the given id.
// The resolution flow calls it after writing the chosen value with a dominating
// version vector. Idempotent (a missing row is fine).
func (s *Store) DiscardFieldConflict(id string) { _ = s.FieldConflicts.hardDelete(id) }

// clearFieldConflict removes any machine-local FieldConflict row for a record + group
// (called whenever a group converges or one side causally wins, so a resolved or
// no-longer-diverged group stops being flagged). Idempotent.
func (s *Store) clearFieldConflict(kind, recordUUID, group string) {
	id := model.FieldConflictID(kind, recordUUID, group)
	if _, ok := s.FieldConflicts.GetRaw(id); ok {
		_ = s.FieldConflicts.hardDelete(id)
	}
}
