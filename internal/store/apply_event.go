package store

import (
	"encoding/json"
	"fmt"

	"sopshq/internal/model"
)

// ApplyEvent applies a replication event from a peer to the correct collection,
// using last-writer-wins. It decodes the event's record snapshot into the right
// type based on ev.Kind and delegates to that collection's ApplyRemote.
//
// It returns whether the local copy changed and whether a conflict was observed
// (independent concurrent edits), so the caller can surface conflicts in the
// audit log.
func (s *Store) ApplyEvent(ev Event) (applied, conflict bool, err error) {
	switch ev.Kind {
	case "machine":
		return applyTyped(s.Machines, ev)
	case "os_user":
		return applyTyped(s.OSUsers, ev)
	case "panel_user":
		// Panel-login accounts are per-machine credentials and are never replicated.
		// A peer running older code may still have panel_user events in its oplog;
		// ignore them (no error, so replication does not wedge) so a peer's admin
		// account can never appear on this machine.
		return false, false, nil
	case "project":
		return applyTyped(s.Projects, ev)
	case "key":
		return applyTyped(s.Keys, ev)
	case "assignment":
		return applyTyped(s.Assignments, ev)
	case "global_set":
		return applyTyped(s.GlobalSets, ev)
	case "backup_settings":
		return applyTyped(s.BackupSettingsColl, ev)
	case "map_view":
		return applyTyped(s.MapViews, ev)
	case "notification_settings":
		return applyTyped(s.NotificationSettingsColl, ev)
	case "distinct_ack":
		return applyTyped(s.DistinctAcks, ev)
	default:
		return false, false, fmt.Errorf("store: unknown event kind %q", ev.Kind)
	}
}

// applyTyped decodes an event's record into the collection's type and applies it.
func applyTyped[T model.Record](c *Collection[T], ev Event) (bool, bool, error) {
	rec := c.newFn()
	if err := json.Unmarshal(ev.Record, rec); err != nil {
		return false, false, fmt.Errorf("store: decode %s event: %w", ev.Kind, err)
	}
	return c.ApplyRemote(rec)
}
