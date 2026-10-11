package keysvc

import (
	"testing"

	"sopshq/internal/model"
)

// TestNotificationEventsSurfaceNotDropped is Medium-1 for NotificationSettings: two
// records for one machine whose ONLY difference is a per-event toggle must surface as a
// conflict (not silently auto-merged, which would drop one toggle), and merging exposes
// the events field as a pick.
func TestNotificationEventsSurfaceNotDropped(t *testing.T) {
	svc, st := buildNode(t, "N")
	a := &model.NotificationSettings{M: model.Meta{UUID: "n1"}, MachineID: "m1", Events: map[string]bool{model.EventApply: true, model.EventDrift: true}}
	b := &model.NotificationSettings{M: model.Meta{UUID: "n2"}, MachineID: "m1", Events: map[string]bool{model.EventApply: true, model.EventDrift: false}}
	if err := st.NotificationSettingsColl.Put(a); err != nil {
		t.Fatalf("n1: %v", err)
	}
	if err := st.NotificationSettingsColl.Put(b); err != nil {
		t.Fatalf("n2: %v", err)
	}

	// The lossless pass must NOT merge them (a differing toggle would be dropped).
	svc.ReconcileCluster("system")
	if n := len(st.NotificationSettingsColl.List()); n != 2 {
		t.Fatalf("a differing events toggle must block the auto-merge; records=%d", n)
	}
	byE := groupsByEntity(svc.DetectConflicts())
	if len(byE[ConflictNotify]) != 1 {
		t.Fatalf("want 1 notification conflict; got %d", len(byE[ConflictNotify]))
	}
	hasEvents := false
	for _, f := range byE[ConflictNotify][0].Fields {
		if f.Key == "events" {
			hasEvents = true
		}
	}
	if !hasEvents {
		t.Fatalf("the differing events toggle must be offered as a pick; fields=%+v", byE[ConflictNotify][0].Fields)
	}
}

// TestNotificationEventsFoldedWhenLoserOnly is Medium-1's lossless half: an event key
// only the loser carries is UNIONED into the survivor (never dropped), and because it is
// not a shared-key disagreement the records still auto-merge.
func TestNotificationEventsFoldedWhenLoserOnly(t *testing.T) {
	svc, st := buildNode(t, "N")
	// Survivor (smallest UUID) lacks the "custom" event; loser carries it ON.
	surv := &model.NotificationSettings{M: model.Meta{UUID: "n1"}, MachineID: "m1", Events: map[string]bool{model.EventApply: true}}
	loser := &model.NotificationSettings{M: model.Meta{UUID: "n2"}, MachineID: "m1", Events: map[string]bool{model.EventApply: true, "custom_event": true}}
	if err := st.NotificationSettingsColl.Put(surv); err != nil {
		t.Fatalf("n1: %v", err)
	}
	if err := st.NotificationSettingsColl.Put(loser); err != nil {
		t.Fatalf("n2: %v", err)
	}

	svc.ReconcileCluster("system")
	recs := st.NotificationSettingsColl.List()
	if len(recs) != 1 {
		t.Fatalf("a loser-only event key is a lossless union, should still merge to 1; got %d", len(recs))
	}
	if !recs[0].Events["custom_event"] {
		t.Fatalf("the loser-only event key must be folded into the survivor, not dropped; events=%v", recs[0].Events)
	}
}

// TestBackupBaseNameSurfacesAndFolds is Medium-1 for BackupSettings: a differing non-empty
// BaseName blocks the auto-merge and surfaces, while an empty survivor BaseName is folded.
func TestBackupBaseNameSurfacesAndFolds(t *testing.T) {
	// Differing non-empty base names -> conflict, not auto-merged.
	svc, st := buildNode(t, "N")
	if err := st.BackupSettingsColl.Put(&model.BackupSettings{M: model.Meta{UUID: "b1"}, MachineID: "m1", BaseName: "alpha"}); err != nil {
		t.Fatalf("b1: %v", err)
	}
	if err := st.BackupSettingsColl.Put(&model.BackupSettings{M: model.Meta{UUID: "b2"}, MachineID: "m1", BaseName: "beta"}); err != nil {
		t.Fatalf("b2: %v", err)
	}
	svc.ReconcileCluster("system")
	if n := len(st.BackupSettingsColl.List()); n != 2 {
		t.Fatalf("a differing base name must block the auto-merge; records=%d", n)
	}
	byE := groupsByEntity(svc.DetectConflicts())
	if len(byE[ConflictBackup]) != 1 {
		t.Fatalf("want 1 backup conflict; got %d", len(byE[ConflictBackup]))
	}
	hasBase := false
	for _, f := range byE[ConflictBackup][0].Fields {
		if f.Key == "basename" {
			hasBase = true
		}
	}
	if !hasBase {
		t.Fatalf("the differing base name must be offered as a pick; fields=%+v", byE[ConflictBackup][0].Fields)
	}

	// Empty survivor base name -> folded from the loser, still auto-merges.
	svc2, st2 := buildNode(t, "N2")
	if err := st2.BackupSettingsColl.Put(&model.BackupSettings{M: model.Meta{UUID: "c1"}, MachineID: "m1", BaseName: ""}); err != nil {
		t.Fatalf("c1: %v", err)
	}
	if err := st2.BackupSettingsColl.Put(&model.BackupSettings{M: model.Meta{UUID: "c2"}, MachineID: "m1", BaseName: "filled"}); err != nil {
		t.Fatalf("c2: %v", err)
	}
	svc2.ReconcileCluster("system")
	recs := st2.BackupSettingsColl.List()
	if len(recs) != 1 {
		t.Fatalf("an empty survivor base name is a lossless fill, should merge to 1; got %d", len(recs))
	}
	if recs[0].BaseName != "filled" {
		t.Fatalf("the survivor must inherit the loser's base name; got %q", recs[0].BaseName)
	}
}
