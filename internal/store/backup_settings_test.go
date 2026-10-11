package store

import (
	"testing"

	"sopshq/internal/model"
)

// TestBackupSettingsForGetOrMake verifies that BackupSettingsFor returns a fresh,
// unpersisted default when no record exists for a machine, returns the SAME record
// once it has been persisted, and keys records per machine.
func TestBackupSettingsForGetOrMake(t *testing.T) {
	st, err := Open(t.TempDir(), "node-1", nil)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	// Absent -> fresh default carrying the standard presets, with a new id.
	a := st.BackupSettingsFor("machine-A")
	if a.MachineID != "machine-A" {
		t.Fatalf("MachineID = %q, want machine-A", a.MachineID)
	}
	if a.M.UUID == "" {
		t.Fatal("fresh default has no UUID")
	}
	if a.BaseName != model.DefaultBackupBaseName ||
		a.DateFormat != model.DefaultBackupDateFormat ||
		a.DatePosition != model.DefaultBackupDatePosition {
		t.Fatalf("fresh default missing presets: %+v", a)
	}
	// A read must not persist anything.
	if n := len(st.BackupSettingsColl.List()); n != 0 {
		t.Fatalf("read persisted a record (count = %d, want 0)", n)
	}

	// Persist an edit, then read it back: same id, edited fields survive.
	a.Enabled = true
	a.DailyAt = "03:30"
	if err := st.BackupSettingsColl.Put(a); err != nil {
		t.Fatalf("put: %v", err)
	}
	got := st.BackupSettingsFor("machine-A")
	if got.M.UUID != a.M.UUID || !got.Enabled || got.DailyAt != "03:30" {
		t.Fatalf("re-read did not return the persisted record: %+v", got)
	}

	// A different machine gets its OWN record (per-machine scoping).
	b := st.BackupSettingsFor("machine-B")
	if b.M.UUID == a.M.UUID {
		t.Fatal("two machines share one backup-settings record")
	}
	if b.Enabled {
		t.Fatal("machine-B inherited machine-A's settings")
	}
}
