package model

import "strconv"

// Per-field merge support.
//
// A record type that implements Merger opts in to FIELD-LEVEL replication merge:
// instead of one copy of the record overwriting the other whole (last-writer-wins),
// ApplyRemote merges the two copies one field-GROUP at a time, so two machines that
// edited DIFFERENT groups of the same record both keep their edit, and only a
// genuine same-group divergence is surfaced as a conflict (never silently dropped).
//
// A field GROUP is a set of fields that must move together (atomic), named by a
// stable ASCII string. Each group carries its own version vector in Meta.FieldVV.
//
// This interface is the ONLY thing the generic store needs to merge a record type;
// the store never learns the concrete fields. A type that does NOT implement Merger
// keeps whole-record last-writer-wins, unchanged.

// Merger is implemented by a record type to enable per-field-group replication merge.
type Merger interface {
	Record
	// Groups returns the record's field-group names (stable, ASCII).
	Groups() []string
	// Fingerprint returns a value that changes if and only if group g's value
	// changes. It MUST be empty ("") when the group is semantically unset (e.g. an
	// ungenerated key's keypair), so an unset group is never stamped with a version.
	Fingerprint(group string) string
	// AdoptGroup copies group g's field values from src into the receiver. src is a
	// record of the same concrete type (the merge only ever pairs like with like).
	AdoptGroup(group string, src Record)
	// Fold losslessly folds any UNGROUPED bookkeeping (timestamps) from src into the
	// receiver. It is called once per merge regardless of which side won which group.
	Fold(src Record)
	// FieldDisplay returns a NON-SECRET human rendering of group g's current value
	// and whether the group holds any secret. When secret is true the value itself
	// is never shown anywhere - only this provenance/summary string.
	FieldDisplay(group string) (text string, secret bool)
}

// VClock is a version vector: node id -> update counter for one field group. A
// missing node key means that node has contributed no update (counter 0).
type VClock map[string]uint64

// Bump returns a copy of v with node's counter incremented by one - the local-write
// rule. Incrementing only the writer's own entry makes the new vector strictly
// dominate the previous local vector (which already reflected everything the writer
// knew), while staying concurrent with any un-merged remote write.
func (v VClock) Bump(node string) VClock {
	out := v.Clone()
	out[node] = out[node] + 1
	return out
}

// MergeMax returns the componentwise maximum of v and o - the "I have now seen both"
// vector. Used when converging equal values and when resolving a conflict.
func (v VClock) MergeMax(o VClock) VClock {
	out := v.Clone()
	for n, c := range o {
		if c > out[n] {
			out[n] = c
		}
	}
	return out
}

// Clone returns an independent copy of the vector.
func (v VClock) Clone() VClock {
	out := make(VClock, len(v)+1)
	for n, c := range v {
		out[n] = c
	}
	return out
}

// Empty reports whether the vector records no updates at all (a never-written group).
func (v VClock) Empty() bool {
	for _, c := range v {
		if c > 0 {
			return false // any positive counter means non-empty
		}
	}
	return true
}

// VClock ordering results.
const (
	VCEqual      = 0 // identical vectors
	VCDominatesA = 1 // a strictly dominates b (a has seen everything b has, and more)
	VCDominatesB = 2 // b strictly dominates a
	VCConcurrent = 3 // neither dominates the other
)

// CompareVClock orders two version vectors. It reports VCEqual, VCDominatesA (a >
// b), VCDominatesB (b > a), or VCConcurrent (neither). This is the causality test:
// a dominating vector is a CAUSAL successor (safe to take), a concurrent pair is a
// genuine divergence.
func CompareVClock(a, b VClock) int {
	aGreater, bGreater := false, false
	// Walk the union of node keys.
	seen := map[string]bool{}
	for n := range a {
		seen[n] = true
	}
	for n := range b {
		seen[n] = true
	}
	for n := range seen {
		av, bv := a[n], b[n]
		if av > bv {
			aGreater = true
		} else if bv > av {
			bGreater = true
		}
	}
	switch {
	case aGreater && bGreater:
		return VCConcurrent
	case aGreater:
		return VCDominatesA
	case bGreater:
		return VCDominatesB
	default:
		return VCEqual
	}
}

// ---- Key implements Merger -------------------------------------------------

// Key field-group names. Each is a stable ASCII identifier used as the Meta.FieldVV
// key and (for conflicts) the /conflicts field key.
const (
	KeyGroupName    = "name"
	KeyGroupType    = "type"
	KeyGroupNote    = "note"
	KeyGroupKeypair = "keypair" // Recipient + PrivSealed + Generation, atomic
	KeyGroupStatus  = "status"
	KeyGroupOwner   = "owner"
)

// keyGroups is the fixed group order for a Key (deterministic iteration).
var keyGroups = []string{KeyGroupName, KeyGroupType, KeyGroupNote, KeyGroupKeypair, KeyGroupStatus, KeyGroupOwner}

// Groups implements Merger.
func (k *Key) Groups() []string { return keyGroups }

// Fingerprint implements Merger. Each group returns "" when unset so an unset group
// is never versioned.
func (k *Key) Fingerprint(group string) string {
	switch group {
	case KeyGroupName:
		return k.Name
	case KeyGroupType:
		return string(k.Type)
	case KeyGroupNote:
		return k.Note
	case KeyGroupKeypair:
		if k.Recipient == "" {
			return "" // not generated yet - no keypair to version
		}
		return k.Recipient + "\x00" + k.PrivSealed + "\x00" + strconv.Itoa(k.Generation)
	case KeyGroupStatus:
		return string(k.Status)
	case KeyGroupOwner:
		return k.OwnerUserID
	}
	return ""
}

// AdoptGroup implements Merger: copy group g's fields from src (another *Key).
func (k *Key) AdoptGroup(group string, src Record) {
	o, ok := src.(*Key)
	if !ok {
		return
	}
	switch group {
	case KeyGroupName:
		k.Name = o.Name
	case KeyGroupType:
		k.Type = o.Type
	case KeyGroupNote:
		k.Note = o.Note
	case KeyGroupKeypair:
		k.Recipient = o.Recipient
		k.PrivSealed = o.PrivSealed
		k.Generation = o.Generation
	case KeyGroupStatus:
		k.Status = o.Status
	case KeyGroupOwner:
		k.OwnerUserID = o.OwnerUserID
	}
}

// Fold implements Merger: keep the earliest creation and latest edit (never a loss).
func (k *Key) Fold(src Record) {
	o, ok := src.(*Key)
	if !ok {
		return
	}
	if o.CreatedAt != 0 && (k.CreatedAt == 0 || o.CreatedAt < k.CreatedAt) {
		k.CreatedAt = o.CreatedAt
	}
	if o.EditedAt > k.EditedAt {
		k.EditedAt = o.EditedAt
	}
}

// FieldDisplay implements Merger: a non-secret rendering of each group's value. The
// keypair group is SECRET (it holds the sealed private key); it renders only the
// public recipient + generation, never the private material.
func (k *Key) FieldDisplay(group string) (string, bool) {
	switch group {
	case KeyGroupName:
		return k.Name, false
	case KeyGroupType:
		return string(k.Type), false
	case KeyGroupNote:
		return k.Note, false
	case KeyGroupKeypair:
		rec := k.Recipient
		if len(rec) > 20 {
			rec = rec[:14] + "..." + rec[len(rec)-4:]
		}
		return "generation " + strconv.Itoa(k.Generation) + ", public key " + rec + " (private key sealed)", true
	case KeyGroupStatus:
		return string(k.Status), false
	case KeyGroupOwner:
		return k.OwnerUserID, false
	}
	return "", false
}
