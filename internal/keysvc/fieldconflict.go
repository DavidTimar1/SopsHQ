package keysvc

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	"sopshq/internal/audit"
	"sopshq/internal/model"
)

// Same-field conflict resolution: the operator-facing half of per-field merge.
//
// When two machines change the SAME field group of the SAME record to different
// values concurrently, ApplyRemote keeps the local value and records a machine-local
// model.FieldConflict holding the peer's candidate (see internal/store/merge.go).
// This file surfaces those rows on /conflicts (DetectFieldConflicts) and resolves one
// deliberately (ResolveFieldConflict) with the same two-step double-confirm the record
// merges use: the chosen value is written with a version vector that dominates BOTH
// candidates, so the decision replicates and both machines converge.
//
// SECURITY: a secret group (a Key's keypair, which holds the sealed private key) is
// never rendered - only its non-secret FieldDisplay (generation + public recipient).

// FieldPickLocal / FieldPickRemote are the two resolution choices: keep this machine's
// current value, or take the peer's candidate.
const (
	FieldPickLocal  = "local"
	FieldPickRemote = "remote"
)

// ErrFieldConflictGone means the named field conflict no longer exists (already
// resolved, the record was deleted, or the two values have since converged).
var ErrFieldConflictGone = errors.New("keysvc: that field conflict is no longer pending")

// FieldConflictVM describes one pending same-field divergence for the UI: one record,
// one field group, and the two candidate values (local vs the peer's) as picks. No
// secret value ever appears here.
type FieldConflictVM struct {
	ID         string // the FieldConflict row id (stable; the resolution form key)
	Kind       string // record kind, e.g. "key"
	RecordUUID string
	Group      string
	GroupLabel string // human field label, e.g. "note", "key material"
	KeyLabel   string // human record label, e.g. key "project-app"
	Secret     bool   // the group holds a secret; values are shown as provenance only
	Local      FieldCandidate
	Remote     FieldCandidate
}

// FieldCandidate is one side of a field conflict: the non-secret display of a value
// plus its provenance (which machine last changed it).
type FieldCandidate struct {
	Pick    string // FieldPickLocal or FieldPickRemote
	Display string
	Origin  string
}

// groupLabels maps a field-group name to a friendlier UI label.
var groupLabels = map[string]string{
	model.KeyGroupName:    "name",
	model.KeyGroupType:    "key type",
	model.KeyGroupNote:    "note",
	model.KeyGroupKeypair: "key material (public + sealed private key)",
	model.KeyGroupStatus:  "rotation status",
	model.KeyGroupOwner:   "owner account",
}

// DetectFieldConflicts returns every pending same-field divergence, newest first. It
// is READ-ONLY. A row whose record was deleted, or whose two values have since
// converged, is skipped (stale).
func (s *Service) DetectFieldConflicts() []FieldConflictVM {
	var out []FieldConflictVM
	for _, fc := range s.store.FieldConflicts.List() {
		vm, ok := s.fieldConflictVM(fc)
		if !ok {
			continue
		}
		out = append(out, vm)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// FieldConflictCount is the number of pending same-field divergences (drives the
// dashboard alert alongside the record-conflict count).
func (s *Service) FieldConflictCount() int { return len(s.DetectFieldConflicts()) }

// FieldConflictByID returns the CURRENT view model for one row, or false when it is
// no longer pending - so the resolution flow re-reviews rather than acting on a stale
// conflict.
func (s *Service) FieldConflictByID(id string) (FieldConflictVM, bool) {
	fc, ok := s.store.FieldConflicts.GetRaw(id)
	if !ok || fc.M.Deleted {
		return FieldConflictVM{}, false
	}
	return s.fieldConflictVM(fc)
}

// fieldConflictVM builds the view model for a row, or false if it is stale.
func (s *Service) fieldConflictVM(fc *model.FieldConflict) (FieldConflictVM, bool) {
	local, remote, ok := s.loadFieldPair(fc)
	if !ok {
		return FieldConflictVM{}, false
	}
	g := fc.Group
	if local.Fingerprint(g) == remote.Fingerprint(g) {
		return FieldConflictVM{}, false // converged since detection - nothing to resolve
	}
	localText, secret := local.FieldDisplay(g)
	remoteText, _ := remote.FieldDisplay(g)
	label := groupLabels[g]
	if label == "" {
		label = g
	}
	return FieldConflictVM{
		ID:         fc.M.UUID,
		Kind:       fc.Kind,
		RecordUUID: fc.RecordUUID,
		Group:      g,
		GroupLabel: label,
		KeyLabel:   s.recordLabel(fc.Kind, local),
		Secret:     secret,
		Local:      FieldCandidate{Pick: FieldPickLocal, Display: localText, Origin: s.machineName(local.Meta().Origin)},
		Remote:     FieldCandidate{Pick: FieldPickRemote, Display: remoteText, Origin: s.machineName(fc.RemoteOrigin)},
	}, true
}

// loadFieldPair loads the live LOCAL record and decodes the peer's candidate for a
// field conflict. ok is false when the local record is gone or the kind is unknown.
func (s *Service) loadFieldPair(fc *model.FieldConflict) (local, remote model.Merger, ok bool) {
	switch fc.Kind {
	case "key":
		k, err := s.store.Keys.Get(fc.RecordUUID)
		if err != nil {
			return nil, nil, false
		}
		var rk model.Key
		if json.Unmarshal(fc.RemoteSnapshot, &rk) != nil {
			return nil, nil, false
		}
		return k, &rk, true
	default:
		return nil, nil, false
	}
}

// recordLabel is a short human label for the conflicting record (non-secret).
func (s *Service) recordLabel(kind string, rec model.Merger) string {
	if kind == "key" {
		if k, ok := rec.(*model.Key); ok {
			return "key " + strconv.Quote(k.Name)
		}
	}
	return kind + " " + rec.Meta().UUID
}

// ResolveFieldConflict resolves one same-field divergence by writing the chosen value
// with a version vector that dominates BOTH candidates, then discarding the local row.
// pick is FieldPickLocal (keep this machine's value) or FieldPickRemote (take the
// peer's). The dominating write replicates, so the other machine converges and clears
// its own row. It is the ONLY overwrite path here, gated behind the web layer's
// two-step confirm.
func (s *Service) ResolveFieldConflict(id, pick, actor string) error {
	if pick != FieldPickLocal && pick != FieldPickRemote {
		return errors.New("keysvc: invalid field-conflict choice")
	}
	fc, ok := s.store.FieldConflicts.GetRaw(id)
	if !ok || fc.M.Deleted {
		return ErrFieldConflictGone
	}
	switch fc.Kind {
	case "key":
		return s.resolveKeyField(fc, pick, actor)
	default:
		return ErrFieldConflictGone
	}
}

// resolveKeyField applies a field-conflict resolution to a Key.
func (s *Service) resolveKeyField(fc *model.FieldConflict, pick, actor string) error {
	k, err := s.store.Keys.Get(fc.RecordUUID)
	if err != nil {
		s.store.DiscardFieldConflict(fc.M.UUID)
		return ErrFieldConflictGone
	}
	var rk model.Key
	if err := json.Unmarshal(fc.RemoteSnapshot, &rk); err != nil {
		return ErrFieldConflictGone
	}
	g := fc.Group
	if k.Fingerprint(g) == rk.Fingerprint(g) {
		// Already converged (a resolution arrived first); just drop the row.
		s.store.DiscardFieldConflict(fc.M.UUID)
		return nil
	}
	// A vector that dominates both candidates, so the chosen value wins everywhere.
	target := k.M.FieldVV[g].MergeMax(rk.M.FieldVV[g]).Bump(s.store.Node())
	if pick == FieldPickRemote {
		k.AdoptGroup(g, &rk)
	}
	if k.M.FieldVV == nil {
		k.M.FieldVV = map[string]model.VClock{}
	}
	k.M.FieldVV[g] = target
	if err := s.store.Keys.Put(k); err != nil {
		return err
	}
	s.store.DiscardFieldConflict(fc.M.UUID)
	label := groupLabels[g]
	if label == "" {
		label = g
	}
	_ = s.audit.Record(actor, "field_conflict_resolve", k.Name, audit.OK, "field "+label+", kept "+pick+" value")
	return nil
}
