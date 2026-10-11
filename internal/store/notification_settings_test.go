package store

import (
	"testing"

	"sopshq/internal/model"
)

// TestNotificationSettingsForGetOrMake verifies NotificationSettingsFor returns a
// fresh, unpersisted, disabled default (with the curated event toggles) when no
// record exists, returns the SAME record once persisted, and keys records per
// machine.
func TestNotificationSettingsForGetOrMake(t *testing.T) {
	st, err := Open(t.TempDir(), "node-1", nil)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	// Absent -> fresh, disabled default with a new id and default event toggles.
	a := st.NotificationSettingsFor("machine-A")
	if a.MachineID != "machine-A" {
		t.Fatalf("MachineID = %q, want machine-A", a.MachineID)
	}
	if a.M.UUID == "" {
		t.Fatal("fresh default has no UUID")
	}
	if a.Enabled {
		t.Fatal("fresh default should be disabled")
	}
	if !a.Events[model.EventApply] || a.Events[model.EventSecretReveal] {
		t.Fatalf("fresh default has wrong event toggles: %+v", a.Events)
	}
	// A read must not persist anything.
	if n := len(st.NotificationSettingsColl.List()); n != 0 {
		t.Fatalf("read persisted a record (count = %d, want 0)", n)
	}

	// Persist an edit, then read it back: same id, edited fields survive.
	a.Enabled = true
	a.SlackEnabled = true
	if err := st.NotificationSettingsColl.Put(a); err != nil {
		t.Fatalf("put: %v", err)
	}
	got := st.NotificationSettingsFor("machine-A")
	if got.M.UUID != a.M.UUID || !got.Enabled || !got.SlackEnabled {
		t.Fatalf("re-read did not return the persisted record: %+v", got)
	}

	// A different machine gets its OWN record (per-machine scoping).
	b := st.NotificationSettingsFor("machine-B")
	if b.M.UUID == a.M.UUID {
		t.Fatal("two machines share one notification-settings record")
	}
	if b.Enabled {
		t.Fatal("machine-B inherited machine-A's settings")
	}
}

// TestNotificationSettingsReplicates verifies a notification_settings event from a
// peer is decoded and applied to the right collection.
func TestNotificationSettingsReplicates(t *testing.T) {
	src, err := Open(t.TempDir(), "node-1", nil)
	if err != nil {
		t.Fatalf("open source store: %v", err)
	}
	rec := src.NotificationSettingsFor("machine-A")
	rec.Enabled = true
	rec.TelegramEnabled = true
	rec.TelegramChatID = "chat-1"
	if err := src.NotificationSettingsColl.Put(rec); err != nil {
		t.Fatalf("put: %v", err)
	}

	dst, err := Open(t.TempDir(), "node-2", nil)
	if err != nil {
		t.Fatalf("open dest store: %v", err)
	}
	events, err := src.Oplog().Since(0)
	if err != nil {
		t.Fatalf("read oplog: %v", err)
	}
	for _, ev := range events {
		if _, _, err := dst.ApplyEvent(ev); err != nil {
			t.Fatalf("apply event %q: %v", ev.Kind, err)
		}
	}
	got := dst.NotificationSettingsFor("machine-A")
	if got.M.UUID != rec.M.UUID || !got.Enabled || got.TelegramChatID != "chat-1" {
		t.Fatalf("replicated record mismatch: %+v", got)
	}
}
