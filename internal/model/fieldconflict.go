package model

import (
	"encoding/json"

	"sopshq/internal/hlc"
)

// FieldConflict records ONE unresolved same-field divergence detected during
// replication: two machines changed the SAME field group of the SAME record to
// different values without either having seen the other's change (a concurrent
// version-vector divergence). ApplyRemote keeps the LOCAL value untouched and stores
// the peer's candidate here so the operator can pick a winner in /conflicts.
//
// It is MACHINE-LOCAL: it embeds Meta so it lives in a normal store collection, but
// its collection is localOnly (never appended to the oplog, never replicated). Both
// machines detect the same divergence independently when they apply each other's
// event, so each records its own row - there is nothing to replicate. When the
// operator resolves the conflict on either machine, the winning value is written with
// a dominating version vector; that write replicates and clears the divergence (and
// thus the FieldConflict row) on the other machine automatically.
//
// SECURITY: RemoteSnapshot is the peer's stored record verbatim. For a Key that means
// it may contain the vault-SEALED private key (ciphertext, safe at rest) - it is NEVER
// unsealed or rendered. The UI shows only the non-secret FieldDisplay of a group.
type FieldConflict struct {
	M Meta `json:"meta"`
	// Kind is the collection kind of the conflicting record (e.g. "key").
	Kind string `json:"kind"`
	// RecordUUID is the UUID of the diverged record (shared by both candidates).
	RecordUUID string `json:"record_uuid"`
	// Group is the field-group name that diverged (e.g. "note", "keypair").
	Group string `json:"group"`
	// RemoteSnapshot is the peer's whole record as received, so resolution can adopt
	// the remote candidate's group value and its version vector. May contain sealed
	// ciphertext; never rendered.
	RemoteSnapshot json.RawMessage `json:"remote_snapshot"`
	// RemoteOrigin / RemoteUpdated are the peer candidate's provenance, for a
	// non-secret "who / when" fact in the UI.
	RemoteOrigin  string        `json:"remote_origin"`
	RemoteUpdated hlc.Timestamp `json:"remote_updated"`
	// DetectedAt is when this divergence was first recorded (Unix seconds).
	DetectedAt int64 `json:"detected_at"`
}

func (c *FieldConflict) Meta() *Meta { return &c.M }

// FieldConflictID is the stable, deterministic id of the FieldConflict row for a
// given record + group, so re-detecting the same divergence UPSERTS one row rather
// than piling up duplicates (idempotent replication).
func FieldConflictID(kind, recordUUID, group string) string {
	return "fc:" + kind + ":" + recordUUID + ":" + group
}
