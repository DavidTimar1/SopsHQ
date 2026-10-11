package model

// DistinctAck is the operator's "keep both" decision about a conflict group: a
// record that says "these specific records share a natural key, but they are
// intentionally DIFFERENT things - stop flagging them as a conflict to resolve."
//
// It is the conflict-resolution counterpart of Machine.Confirmed for the
// new-vs-reinstall flow: a small, replicated marker so the decision is visible on
// every node and the cluster converges (both nodes stop surfacing the same group).
// It embeds Meta and flows through the store's Put/Delete and the oplog like any
// other record, so it carries no secret of any kind - only an entity-type string
// and the UUIDs of the records the operator declared distinct.
//
// A group is suppressed only when a live ack's RecordIDs COVER every member of the
// group (a superset). So if a THIRD record later appears sharing the same natural
// key, the older ack no longer covers the enlarged group and the conflict surfaces
// again for a fresh decision - never silently swallowed.
type DistinctAck struct {
	M Meta `json:"meta"`
	// EntityType is the conflicting record kind: "key", "project", "osuser",
	// "machine", or "map_view" (the kinds where two records can be legitimately
	// distinct). The per-machine settings kinds are never kept-both, so they never
	// appear here.
	EntityType string `json:"entity_type"`
	// RecordIDs are the UUIDs the operator declared intentionally distinct, sorted
	// ascending so the same decision produces the same value on every node.
	RecordIDs []string `json:"record_ids"`
}

func (a *DistinctAck) Meta() *Meta { return &a.M }
