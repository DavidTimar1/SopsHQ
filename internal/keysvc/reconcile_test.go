package keysvc

import (
	"path/filepath"
	"testing"

	"sopshq/internal/audit"
	"sopshq/internal/model"
	"sopshq/internal/place"
	"sopshq/internal/store"
	"sopshq/internal/vault"
)

// buildNode wires a bare Service over a fresh temp store + vault for node id, with
// the safe placer and no host effects, and NO pre-created machine (the test owns the
// machine records). It returns the service and its store.
func buildNode(t *testing.T, nodeID string) (*Service, *store.Store) {
	t.Helper()
	t.Setenv("SOPS_AGE_KEY_FILE", "")
	dir := t.TempDir()
	v, err := vault.Init(filepath.Join(dir, "vault"), "pass")
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	st, err := store.Open(filepath.Join(dir, "data"), nodeID, nil)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	a := audit.Open(filepath.Join(dir, "audit.jsonl"), nodeID, nil)
	svc := New(st, v, a, "")
	svc.SetPlacer(place.WriteKeyStore)
	place.DisableEffectsForTest(t)
	return svc, st
}

// selfMachine creates this node's canonical self-record (id == node id) and links
// the service to it, mirroring fresh-setup in main.go.
func selfMachine(t *testing.T, svc *Service, st *store.Store, id, name string, os model.OS) {
	t.Helper()
	mc := &model.Machine{M: model.Meta{UUID: id}, Name: name, OS: os, Canonical: true}
	if err := st.Machines.Put(mc); err != nil {
		t.Fatalf("self machine: %v", err)
	}
	svc.SetLocalMachine(id)
}

// replicate copies every oplog event from one store into another with the
// last-writer-wins ApplyEvent, so a test can converge two nodes by replaying both
// directions. Replaying all events each round is safe (ApplyRemote is idempotent).
func replicate(t *testing.T, from, to *store.Store) {
	t.Helper()
	evs, err := from.Oplog().Since(0)
	if err != nil {
		t.Fatalf("oplog since: %v", err)
	}
	for _, ev := range evs {
		if _, _, err := to.ApplyEvent(ev); err != nil {
			t.Fatalf("apply event: %v", err)
		}
	}
}

// liveMachineCount returns how many live machines the store holds, for assertions.
func liveMachineCount(st *store.Store) int { return len(st.Machines.List()) }

func machineByName(st *store.Store, name string) *model.Machine {
	for _, mc := range st.Machines.List() {
		if mc.Name == name {
			return mc
		}
	}
	return nil
}

// TestTwoNodeMachineConvergence is case (a): each node has its own canonical record
// and a manually-added placeholder for the other; after replication + reconcile both
// nodes converge to the SAME two machine records, references intact, the placeholder's
// advertised address folded into the canonical record, and repeated passes never
// flip-flop.
func TestTwoNodeMachineConvergence(t *testing.T) {
	svcA, stA := buildNode(t, "A")
	svcB, stB := buildNode(t, "B")
	selfMachine(t, svcA, stA, "A", "nodeA", model.OSLinux)
	selfMachine(t, svcB, stB, "B", "nodeB", model.OSWindows)

	// Each node adds the other by address (a non-canonical placeholder). A's
	// placeholder for B carries the advertised address the operator typed.
	if err := stA.Machines.Put(&model.Machine{M: model.Meta{UUID: store.NewID()}, Name: "nodeB", OS: model.OSWindows, TailscaleHost: "100.0.0.2", AgentPort: 8443}); err != nil {
		t.Fatalf("A adds B: %v", err)
	}
	if err := stB.Machines.Put(&model.Machine{M: model.Meta{UUID: store.NewID()}, Name: "nodeA", OS: model.OSLinux, TailscaleHost: "100.0.0.1", AgentPort: 8443}); err != nil {
		t.Fatalf("B adds A: %v", err)
	}

	// Converge: replicate both ways and reconcile on both, a few rounds.
	for i := 0; i < 4; i++ {
		replicate(t, stA, stB)
		replicate(t, stB, stA)
		svcA.ReconcileCluster("system")
		svcB.ReconcileCluster("system")
	}

	for _, tc := range []struct {
		name string
		st   *store.Store
	}{{"A", stA}, {"B", stB}} {
		if n := liveMachineCount(tc.st); n != 2 {
			var names []string
			for _, mc := range tc.st.Machines.List() {
				names = append(names, mc.Name)
			}
			t.Fatalf("node %s: want 2 machines, got %d (%v)", tc.name, n, names)
		}
		a := machineByName(tc.st, "nodeA")
		b := machineByName(tc.st, "nodeB")
		if a == nil || b == nil {
			t.Fatalf("node %s: both canonical machines must survive", tc.name)
		}
		if !a.Canonical || !b.Canonical {
			t.Fatalf("node %s: survivors must be the canonical records", tc.name)
		}
		if a.M.UUID != "A" || b.M.UUID != "B" {
			t.Fatalf("node %s: canonical ids must be the node ids; got A=%s B=%s", tc.name, a.M.UUID, b.M.UUID)
		}
		// The placeholder's advertised address folded into the canonical record.
		if b.TailscaleHost != "100.0.0.2" {
			t.Fatalf("node %s: nodeB advertised address must be preserved, got %q", tc.name, b.TailscaleHost)
		}
		if a.TailscaleHost != "100.0.0.1" {
			t.Fatalf("node %s: nodeA advertised address must be preserved, got %q", tc.name, a.TailscaleHost)
		}
		if a.Pending || b.Pending {
			t.Fatalf("node %s: the founding pair must not be pending", tc.name)
		}
	}

	// Idempotency / no flip-flop: another converge round changes nothing.
	beforeA := liveMachineCount(stA)
	svcA.ReconcileCluster("system")
	svcA.ReconcileCluster("system")
	if liveMachineCount(stA) != beforeA {
		t.Fatalf("reconcile must be idempotent; machine count changed from %d", beforeA)
	}
}

// TestReinstallAdoptMergesIntoExisting is case (b): a new peer identity appears while
// a confirmed peer exists, is held Pending, and confirming "reinstall of X" merges the
// new install into X, re-pointing references and tombstoning the new record.
func TestReinstallAdoptMergesIntoExisting(t *testing.T) {
	svc, st := buildNode(t, "boss")
	selfMachine(t, svc, st, "boss", "boss", model.OSLinux)
	svc.ReconcileCluster("system") // seed the acknowledged-peers set

	// An existing, confirmed peer "cold" (the machine that will be reinstalled).
	if err := st.Machines.Put(&model.Machine{M: model.Meta{UUID: "cold"}, Name: "workstation", OS: model.OSWindows, Canonical: true}); err != nil {
		t.Fatalf("cold: %v", err)
	}
	svc.ReconcileCluster("system") // cold is the first peer -> accepted, not pending
	if machineByName(st, "workstation").Pending {
		t.Fatal("the first peer must be accepted, not pending")
	}

	// The reinstalled node appears with a brand-new id and the same hostname.
	if err := st.Machines.Put(&model.Machine{M: model.Meta{UUID: "cnew"}, Name: "workstation", OS: model.OSWindows, Canonical: true}); err != nil {
		t.Fatalf("cnew: %v", err)
	}
	// It re-created an OS user referencing its new id.
	if err := st.OSUsers.Put(&model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: "cnew", Username: "dev"}); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	svc.ReconcileCluster("system")

	cnew, ok := st.Machines.GetRaw("cnew")
	if !ok || !cnew.Pending {
		t.Fatalf("a brand-new peer identity must be held Pending; got %+v", cnew)
	}

	// Confirm it is a reinstall of the existing peer "cold".
	if err := svc.ConfirmReinstallPeer("cnew", "cold", "tester"); err != nil {
		t.Fatalf("ConfirmReinstallPeer: %v", err)
	}
	svc.ReconcileCluster("system")

	// cnew is tombstoned and redirected into cold; cold survives as the identity.
	cnew, _ = st.Machines.GetRaw("cnew")
	if !cnew.M.Deleted || cnew.MergedInto != "cold" {
		t.Fatalf("cnew must be tombstoned with MergedInto=cold; got %+v", cnew)
	}
	if _, err := st.Machines.Get("cold"); err != nil {
		t.Fatalf("cold must survive the reinstall merge: %v", err)
	}
	// The reinstalled node's OS user now belongs to the adopted identity.
	u := st.OSUsers.List()[0]
	if u.MachineID != "cold" {
		t.Fatalf("references must re-point to the adopted identity; osuser.MachineID=%q", u.MachineID)
	}
	if n := liveMachineCount(st); n != 2 {
		t.Fatalf("after reinstall merge want 2 live machines (boss, cold), got %d", n)
	}
}

// TestReinstallLocalFollowsIdentity is the local half of case (b): when THIS node is
// the reinstalled one and the operator confirms it is a reinstall of an existing peer,
// the reconcile pass follows the merge redirect to rewrite this node's own local
// machine id, and its local references move with it.
func TestReinstallLocalFollowsIdentity(t *testing.T) {
	svc, st := buildNode(t, "cnew")
	selfMachine(t, svc, st, "cnew", "ws", model.OSLinux)
	svc.ReconcileCluster("system")

	// The existing identity this node is really a reinstall of, synced in as a peer.
	if err := st.Machines.Put(&model.Machine{M: model.Meta{UUID: "cold"}, Name: "ws-old", OS: model.OSLinux, Canonical: true}); err != nil {
		t.Fatalf("cold: %v", err)
	}
	svc.ReconcileCluster("system")
	// A local OS user referencing this node's (soon-to-be-merged) id.
	if err := st.OSUsers.Put(&model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: "cnew", Username: "dev"}); err != nil {
		t.Fatalf("osuser: %v", err)
	}

	// Operator on the reinstalled node declares it is a reinstall of "cold".
	if err := svc.ConfirmReinstallPeer("cnew", "cold", "tester"); err != nil {
		t.Fatalf("ConfirmReinstallPeer: %v", err)
	}
	res := svc.ReconcileCluster("system")

	if !res.LocalChanged || res.LocalMachineID != "cold" {
		t.Fatalf("local identity must follow the merge to cold; res=%+v", res)
	}
	if svc.LocalMachine() != "cold" {
		t.Fatalf("service local machine must be cold, got %q", svc.LocalMachine())
	}
	if u := st.OSUsers.List()[0]; u.MachineID != "cold" {
		t.Fatalf("local references must follow the merge; osuser.MachineID=%q", u.MachineID)
	}
}

// TestConfirmNewKeepsDistinct is case (c): a Pending peer confirmed as NEW stays a
// distinct, confirmed machine and is not re-prompted on later reconciles.
func TestConfirmNewKeepsDistinct(t *testing.T) {
	svc, st := buildNode(t, "A")
	selfMachine(t, svc, st, "A", "nodeA", model.OSLinux)
	svc.ReconcileCluster("system")
	// First peer accepted.
	if err := st.Machines.Put(&model.Machine{M: model.Meta{UUID: "B"}, Name: "nodeB", OS: model.OSLinux, Canonical: true}); err != nil {
		t.Fatalf("B: %v", err)
	}
	svc.ReconcileCluster("system")
	// A genuinely new third peer -> pending.
	if err := st.Machines.Put(&model.Machine{M: model.Meta{UUID: "C"}, Name: "nodeC", OS: model.OSLinux, Canonical: true}); err != nil {
		t.Fatalf("C: %v", err)
	}
	svc.ReconcileCluster("system")
	if c, _ := st.Machines.GetRaw("C"); !c.Pending {
		t.Fatal("a new third peer must be pending")
	}

	if err := svc.ConfirmNewPeer("C", "tester"); err != nil {
		t.Fatalf("ConfirmNewPeer: %v", err)
	}
	// Stays a distinct, live, non-pending machine across further reconciles.
	svc.ReconcileCluster("system")
	svc.ReconcileCluster("system")
	c, err := st.Machines.Get("C")
	if err != nil {
		t.Fatalf("confirmed-new peer must remain live: %v", err)
	}
	if c.Pending {
		t.Fatal("a confirmed-new peer must not be re-flagged pending")
	}
	if n := liveMachineCount(st); n != 3 {
		t.Fatalf("want 3 distinct machines, got %d", n)
	}
}

// TestFirstPeerNoPrompt is case (d): with no other peer yet, the first peer to appear
// is accepted with no pending confirmation.
func TestFirstPeerNoPrompt(t *testing.T) {
	svc, st := buildNode(t, "A")
	selfMachine(t, svc, st, "A", "nodeA", model.OSLinux)
	svc.ReconcileCluster("system") // establish the acknowledged-peers set (only self)

	if err := st.Machines.Put(&model.Machine{M: model.Meta{UUID: "B"}, Name: "nodeB", OS: model.OSLinux, Canonical: true}); err != nil {
		t.Fatalf("B: %v", err)
	}
	svc.ReconcileCluster("system")
	if b, _ := st.Machines.GetRaw("B"); b.Pending {
		t.Fatal("the first peer must be accepted with no prompt")
	}
}

// TestHealLegacyPlaceholderNoPrompt is case (e): a legacy self-record plus a
// case-different manual placeholder for the same machine heal into ONE record (the
// canonical self-record) with references re-pointed, and with NO confirmation prompt.
func TestHealLegacyPlaceholderNoPrompt(t *testing.T) {
	svc, st := buildNode(t, "self")
	// Legacy self-record: not yet marked canonical (predates the flag).
	if err := st.Machines.Put(&model.Machine{M: model.Meta{UUID: "self"}, Name: "MyHost", OS: model.OSLinux}); err != nil {
		t.Fatalf("self: %v", err)
	}
	svc.SetLocalMachine("self")
	// A case-different placeholder for the same machine, carrying an OS user.
	if err := st.Machines.Put(&model.Machine{M: model.Meta{UUID: "ph"}, Name: "myhost", OS: model.OSLinux}); err != nil {
		t.Fatalf("placeholder: %v", err)
	}
	if err := st.OSUsers.Put(&model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: "ph", Username: "dev"}); err != nil {
		t.Fatalf("osuser: %v", err)
	}

	svc.ReconcileCluster("system")

	if n := liveMachineCount(st); n != 1 {
		t.Fatalf("legacy self+placeholder must heal to 1 machine, got %d", n)
	}
	surv := st.Machines.List()[0]
	if surv.M.UUID != "self" || !surv.Canonical {
		t.Fatalf("the canonical self-record must survive; got %+v", surv)
	}
	if surv.Pending {
		t.Fatal("a legacy self-vs-placeholder heal must not prompt")
	}
	if u := st.OSUsers.List()[0]; u.MachineID != "self" {
		t.Fatalf("references must re-point to the surviving self-record; got %q", u.MachineID)
	}
}

// TestNonMachineSilentMergeViaReplication is case (f): two nodes independently create
// the same project (by name) and a key with the same public key; after replication a
// silent reconcile converges each to one record with no reader dropped and no orphan.
func TestNonMachineSilentMergeViaReplication(t *testing.T) {
	svcA, stA := buildNode(t, "A")
	svcB, stB := buildNode(t, "B")

	// Same project name and same public key, minted independently on each node.
	if err := stA.Projects.Put(&model.Project{M: model.Meta{UUID: "pa"}, Name: "app"}); err != nil {
		t.Fatalf("pa: %v", err)
	}
	if err := stB.Projects.Put(&model.Project{M: model.Meta{UUID: "pb"}, Name: "app"}); err != nil {
		t.Fatalf("pb: %v", err)
	}
	if err := stA.Keys.Put(&model.Key{M: model.Meta{UUID: "ka"}, Name: "adopted", Type: model.KeyShared, Recipient: "age1shared"}); err != nil {
		t.Fatalf("ka: %v", err)
	}
	if err := stB.Keys.Put(&model.Key{M: model.Meta{UUID: "kb"}, Name: "project", Type: model.KeyShared, Recipient: "age1shared"}); err != nil {
		t.Fatalf("kb: %v", err)
	}
	// Each node has an OS user + an assignment binding its own key/project.
	if err := stA.OSUsers.Put(&model.OSUser{M: model.Meta{UUID: "ua"}, MachineID: "A", Username: "dev"}); err != nil {
		t.Fatalf("ua: %v", err)
	}
	if err := stB.OSUsers.Put(&model.OSUser{M: model.Meta{UUID: "ub"}, MachineID: "B", Username: "dev"}); err != nil {
		t.Fatalf("ub: %v", err)
	}
	if err := stA.Assignments.Put(&model.Assignment{M: model.Meta{UUID: "aa"}, KeyID: "ka", ProjectID: "pa", MachineID: "A", OSUserID: "ua"}); err != nil {
		t.Fatalf("aa: %v", err)
	}
	if err := stB.Assignments.Put(&model.Assignment{M: model.Meta{UUID: "ab"}, KeyID: "kb", ProjectID: "pb", MachineID: "B", OSUserID: "ub"}); err != nil {
		t.Fatalf("ab: %v", err)
	}

	for i := 0; i < 3; i++ {
		replicate(t, stA, stB)
		replicate(t, stB, stA)
		svcA.ReconcileCluster("system")
		svcB.ReconcileCluster("system")
	}

	for _, tc := range []struct {
		name string
		st   *store.Store
	}{{"A", stA}, {"B", stB}} {
		if n := len(tc.st.Projects.List()); n != 1 {
			t.Fatalf("node %s: duplicate project must merge to 1, got %d", tc.name, n)
		}
		keys := tc.st.Keys.List()
		if len(keys) != 1 {
			t.Fatalf("node %s: duplicate public key must merge to 1, got %d", tc.name, len(keys))
		}
		// Deterministic survivor (smallest UUID) on BOTH nodes.
		if tc.st.Projects.List()[0].M.UUID != "pa" {
			t.Fatalf("node %s: survivor project must be the smallest UUID (pa)", tc.name)
		}
		if keys[0].M.UUID != "ka" {
			t.Fatalf("node %s: survivor key must be the smallest UUID (ka)", tc.name)
		}
		// No reader dropped and no orphan: both original assignments survive, re-pointed
		// to the survivors, each still pointing at a live key + project.
		live := 0
		for _, a := range tc.st.Assignments.List() {
			if a.KeyID != "ka" || a.ProjectID != "pa" {
				t.Fatalf("node %s: assignment not re-pointed to survivors: %+v", tc.name, a)
			}
			if _, err := tc.st.Keys.Get(a.KeyID); err != nil {
				t.Fatalf("node %s: assignment orphaned (key gone)", tc.name)
			}
			if _, err := tc.st.Projects.Get(a.ProjectID); err != nil {
				t.Fatalf("node %s: assignment orphaned (project gone)", tc.name)
			}
			live++
		}
		if live != 2 {
			t.Fatalf("node %s: both grants must survive the merge, got %d", tc.name, live)
		}
	}
}

// TestConcurrentOppositeConfirmationNoMisattribution covers this: because machine
// re-pointing is tombstone-driven (mergeMachine only tombstones; repointAllMerged owns
// the re-point), a reinstall merge whose loser is RESURRECTED live by a concurrent
// ConfirmNewPeer that wins last-writer-wins does NOT leave the resurrected machine's
// OS user silently attached to the wrong machine.
func TestConcurrentOppositeConfirmationNoMisattribution(t *testing.T) {
	svc, st := buildNode(t, "boss")
	selfMachine(t, svc, st, "boss", "boss", model.OSLinux)
	svc.ReconcileCluster("system")
	// An existing confirmed peer (differently named so it never name-merges with cnew).
	if err := st.Machines.Put(&model.Machine{M: model.Meta{UUID: "cold"}, Name: "cold-host", OS: model.OSLinux, Canonical: true}); err != nil {
		t.Fatalf("cold: %v", err)
	}
	svc.ReconcileCluster("system")
	// A brand-new peer identity with its own OS user, held pending.
	if err := st.Machines.Put(&model.Machine{M: model.Meta{UUID: "cnew"}, Name: "workstation", OS: model.OSLinux, Canonical: true}); err != nil {
		t.Fatalf("cnew: %v", err)
	}
	if err := st.OSUsers.Put(&model.OSUser{M: model.Meta{UUID: "u1"}, MachineID: "cnew", Username: "dev"}); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	svc.ReconcileCluster("system")

	// This node confirms it a reinstall of cold (tombstone-only; no eager re-point yet).
	if err := svc.ConfirmReinstallPeer("cnew", "cold", "tester"); err != nil {
		t.Fatalf("ConfirmReinstallPeer: %v", err)
	}
	// Concurrently, another node confirmed it NEW and won last-writer-wins: the cnew
	// record resurrects LIVE with a newer clock. (ApplyRemote keeps the newer write.)
	live := &model.Machine{M: model.Meta{UUID: "cnew", Updated: st.Clock().Now(), Origin: "peerB"}, Name: "workstation", OS: model.OSLinux, Canonical: true, Confirmed: true}
	if applied, _, _ := st.Machines.ApplyRemote(live); !applied {
		t.Fatal("the resurrecting write must win last-writer-wins")
	}

	svc.ReconcileCluster("system")

	// cnew is live and distinct, and its OS user is STILL on cnew - never silently
	// re-attached to cold.
	if _, err := st.Machines.Get("cnew"); err != nil {
		t.Fatalf("cnew must be live after the resurrection: %v", err)
	}
	if u := st.OSUsers.List()[0]; u.MachineID != "cnew" {
		t.Fatalf("the resurrected machine's OS user must NOT be mis-attributed; got %q", u.MachineID)
	}
}

// TestConfirmRefusesWhenNotPending is the other half of the concurrent-confirmation case: a confirm handler refuses
// once the record is no longer pending, so a decision already made is not undone.
func TestConfirmRefusesWhenNotPending(t *testing.T) {
	svc, st := buildNode(t, "A")
	selfMachine(t, svc, st, "A", "nodeA", model.OSLinux)
	svc.ReconcileCluster("system")
	if err := st.Machines.Put(&model.Machine{M: model.Meta{UUID: "B"}, Name: "nodeB", OS: model.OSLinux, Canonical: true}); err != nil {
		t.Fatalf("B: %v", err)
	}
	svc.ReconcileCluster("system")
	if err := st.Machines.Put(&model.Machine{M: model.Meta{UUID: "C"}, Name: "nodeC", OS: model.OSLinux, Canonical: true}); err != nil {
		t.Fatalf("C: %v", err)
	}
	svc.ReconcileCluster("system")
	// Resolve as new; a second confirm (new or reinstall) must refuse.
	if err := svc.ConfirmNewPeer("C", "tester"); err != nil {
		t.Fatalf("ConfirmNewPeer: %v", err)
	}
	if err := svc.ConfirmNewPeer("C", "tester"); err != ErrPeerNotPending {
		t.Fatalf("second confirm-new must refuse with ErrPeerNotPending, got %v", err)
	}
	if err := svc.ConfirmReinstallPeer("C", "B", "tester"); err != ErrPeerNotPending {
		t.Fatalf("confirm-reinstall of an already-resolved peer must refuse, got %v", err)
	}
}

// TestConfirmedPeerNotReflaggedOnAcklessNode covers a node with no local memory of
// a peer (its ack set does not contain it) must NOT re-flag a peer whose record is
// already Confirmed (a decision replicated from another node).
func TestConfirmedPeerNotReflaggedOnAcklessNode(t *testing.T) {
	svc, st := buildNode(t, "D")
	selfMachine(t, svc, st, "D", "nodeD", model.OSLinux)
	svc.ReconcileCluster("system") // creates the ack set (grandfathers only self)

	// Two already-Confirmed peers arrive (as if replicated in) - NOT in D's ack set.
	if err := st.Machines.Put(&model.Machine{M: model.Meta{UUID: "A"}, Name: "nodeA", OS: model.OSLinux, Canonical: true, Confirmed: true}); err != nil {
		t.Fatalf("A: %v", err)
	}
	if err := st.Machines.Put(&model.Machine{M: model.Meta{UUID: "B"}, Name: "nodeB", OS: model.OSLinux, Canonical: true, Confirmed: true}); err != nil {
		t.Fatalf("B: %v", err)
	}
	svc.ReconcileCluster("system")

	if a, _ := st.Machines.GetRaw("A"); a.Pending {
		t.Fatal("a Confirmed peer must not be re-flagged pending on an ack-less node")
	}
	if b, _ := st.Machines.GetRaw("B"); b.Pending {
		t.Fatal("a Confirmed peer must not be re-flagged pending on an ack-less node")
	}
}

// TestMachineMergeRepointsAllRefs checks the full reference map: a machine merge moves
// every kind of reference (OSUser, Assignment, Project path, GlobalSet, BackupSettings,
// NotificationSettings) from the merged-away machine to the survivor.
func TestMachineMergeRepointsAllRefs(t *testing.T) {
	svc, st := buildNode(t, "self")
	selfMachine(t, svc, st, "self", "host", model.OSLinux)
	svc.ReconcileCluster("system")
	// A confirmed peer, plus a case-different placeholder for the SAME peer carrying all
	// the machine-scoped references (so the reconcile merges the placeholder into it).
	if err := st.Machines.Put(&model.Machine{M: model.Meta{UUID: "peer"}, Name: "worker", OS: model.OSLinux, Canonical: true}); err != nil {
		t.Fatalf("peer: %v", err)
	}
	svc.ReconcileCluster("system")
	if err := st.Machines.Put(&model.Machine{M: model.Meta{UUID: "ph"}, Name: "Worker", OS: model.OSLinux}); err != nil {
		t.Fatalf("placeholder: %v", err)
	}
	if err := st.OSUsers.Put(&model.OSUser{M: model.Meta{UUID: "u1"}, MachineID: "ph", Username: "dev"}); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	if err := st.Projects.Put(&model.Project{M: model.Meta{UUID: "p1"}, Name: "app", Paths: []model.ProjectPath{{MachineID: "ph", Path: "/srv/app"}}}); err != nil {
		t.Fatalf("project: %v", err)
	}
	if err := st.Assignments.Put(&model.Assignment{M: model.Meta{UUID: "a1"}, KeyID: "k1", ProjectID: "p1", MachineID: "ph", OSUserID: "u1"}); err != nil {
		t.Fatalf("assignment: %v", err)
	}
	if err := st.GlobalSets.Put(&model.GlobalSet{M: model.Meta{UUID: "g1"}, Name: "shared", MachineID: "ph", RecipientUserIDs: []string{"u1"}}); err != nil {
		t.Fatalf("globalset: %v", err)
	}
	if err := st.BackupSettingsColl.Put(&model.BackupSettings{M: model.Meta{UUID: "bs1"}, MachineID: "ph", Enabled: true}); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if err := st.NotificationSettingsColl.Put(&model.NotificationSettings{M: model.Meta{UUID: "ns1"}, MachineID: "ph", Enabled: true}); err != nil {
		t.Fatalf("notification: %v", err)
	}

	svc.ReconcileCluster("system")

	if u, _ := st.OSUsers.GetRaw("u1"); u.MachineID != "peer" {
		t.Fatalf("OSUser.MachineID must re-point to peer, got %q", u.MachineID)
	}
	if a, _ := st.Assignments.GetRaw("a1"); a.MachineID != "peer" {
		t.Fatalf("Assignment.MachineID must re-point to peer, got %q", a.MachineID)
	}
	if p, _ := st.Projects.GetRaw("p1"); p.Paths[0].MachineID != "peer" {
		t.Fatalf("Project path MachineID must re-point to peer, got %q", p.Paths[0].MachineID)
	}
	if g, _ := st.GlobalSets.GetRaw("g1"); g.MachineID != "peer" {
		t.Fatalf("GlobalSet.MachineID must re-point to peer, got %q", g.MachineID)
	}
	if b, _ := st.BackupSettingsColl.GetRaw("bs1"); b.MachineID != "peer" {
		t.Fatalf("BackupSettings.MachineID must re-point to peer, got %q", b.MachineID)
	}
	if n, _ := st.NotificationSettingsColl.GetRaw("ns1"); n.MachineID != "peer" {
		t.Fatalf("NotificationSettings.MachineID must re-point to peer, got %q", n.MachineID)
	}
}

// TestDedupNewCollections is the SWEEP: BackupSettings (by machine), Notification
// settings (by machine), and MapViews (by name) each merge their accidental
// duplicates to one. Panel logins are deliberately NOT deduped - they are per-machine
// credentials and merging one would risk locking the operator out - so they are not
// part of this sweep.
func TestDedupNewCollections(t *testing.T) {
	svc, st := buildNode(t, "A")
	selfMachine(t, svc, st, "A", "nodeA", model.OSLinux)

	// Two backup-settings for the same machine; the configured one's fields survive.
	if err := st.BackupSettingsColl.Put(&model.BackupSettings{M: model.Meta{UUID: "bs-2"}, MachineID: "A"}); err != nil {
		t.Fatalf("bs-2: %v", err)
	}
	if err := st.BackupSettingsColl.Put(&model.BackupSettings{M: model.Meta{UUID: "bs-1"}, MachineID: "A", Enabled: true, DailyAt: "03:30", PasswordSealed: "sealed"}); err != nil {
		t.Fatalf("bs-1: %v", err)
	}
	// Two notification-settings for the same machine.
	if err := st.NotificationSettingsColl.Put(&model.NotificationSettings{M: model.Meta{UUID: "ns-2"}, MachineID: "A"}); err != nil {
		t.Fatalf("ns-2: %v", err)
	}
	if err := st.NotificationSettingsColl.Put(&model.NotificationSettings{M: model.Meta{UUID: "ns-1"}, MachineID: "A", Enabled: true}); err != nil {
		t.Fatalf("ns-1: %v", err)
	}
	// Two map views with the same name.
	if err := st.MapViews.Put(&model.MapView{M: model.Meta{UUID: "mv-2"}, Name: "By project"}); err != nil {
		t.Fatalf("mv-2: %v", err)
	}
	if err := st.MapViews.Put(&model.MapView{M: model.Meta{UUID: "mv-1"}, Name: "by project"}); err != nil {
		t.Fatalf("mv-1: %v", err)
	}
	// Two panel logins with the same username, one on each machine's behalf. They must
	// SURVIVE reconcile untouched: a panel login is a per-machine credential, and
	// deleting one to "de-duplicate" is exactly what locks the operator out.
	if err := st.PanelUsers.Put(&model.PanelUser{M: model.Meta{UUID: "pu-1"}, Username: "admin", PassHash: "hashA", Role: model.RoleAdmin, Enabled: true}); err != nil {
		t.Fatalf("pu-1: %v", err)
	}
	if err := st.PanelUsers.Put(&model.PanelUser{M: model.Meta{UUID: "pu-2"}, Username: "Admin", PassHash: "hashB", Role: model.RoleAdmin, Enabled: true}); err != nil {
		t.Fatalf("pu-2: %v", err)
	}

	svc.ReconcileCluster("system")

	if n := len(st.BackupSettingsColl.List()); n != 1 {
		t.Fatalf("backup settings must dedup to 1, got %d", n)
	}
	if b := st.BackupSettingsColl.List()[0]; b.M.UUID != "bs-1" || !b.Enabled || b.PasswordSealed != "sealed" {
		t.Fatalf("backup dedup must keep the configured smallest-UUID survivor; got %+v", b)
	}
	if n := len(st.NotificationSettingsColl.List()); n != 1 {
		t.Fatalf("notification settings must dedup to 1, got %d", n)
	}
	if n := len(st.MapViews.List()); n != 1 {
		t.Fatalf("map views must dedup to 1, got %d", n)
	}
	// Both panel logins must remain: reconcile must never delete a credential record.
	if n := len(st.PanelUsers.List()); n != 2 {
		t.Fatalf("panel logins must NOT be deduped (no credential deletion); got %d, want 2", n)
	}
}

// TestReconcileLeavesConflictingDuplicatesIntact is the lossless-only guarantee: when
// two records that collide on their natural key DISAGREE on a non-empty field, reconcile
// must NOT merge or delete either - it leaves both intact for an operator-confirmed flow.
func TestReconcileLeavesConflictingDuplicatesIntact(t *testing.T) {
	svc, st := buildNode(t, "A")
	selfMachine(t, svc, st, "A", "nodeA", model.OSLinux)

	// Two OS users, same account on the same machine, with DIFFERENT key-store bases.
	if err := st.OSUsers.Put(&model.OSUser{M: model.Meta{UUID: "ou-1"}, MachineID: "A", Username: "dev", KeyBase: "/home/dev/.sops"}); err != nil {
		t.Fatalf("ou-1: %v", err)
	}
	if err := st.OSUsers.Put(&model.OSUser{M: model.Meta{UUID: "ou-2"}, MachineID: "A", Username: "dev", KeyBase: "/opt/keys"}); err != nil {
		t.Fatalf("ou-2: %v", err)
	}
	// Two keys, same public key, with DIFFERENT sealed private halves.
	if err := st.Keys.Put(&model.Key{M: model.Meta{UUID: "k-1"}, Name: "shared", Recipient: "age1xyz", PrivSealed: "sealedA"}); err != nil {
		t.Fatalf("k-1: %v", err)
	}
	if err := st.Keys.Put(&model.Key{M: model.Meta{UUID: "k-2"}, Name: "shared", Recipient: "age1xyz", PrivSealed: "sealedB"}); err != nil {
		t.Fatalf("k-2: %v", err)
	}
	// Two projects, same name, giving the SAME machine DIFFERENT paths.
	if err := st.Projects.Put(&model.Project{M: model.Meta{UUID: "p-1"}, Name: "app", Paths: []model.ProjectPath{{MachineID: "A", Path: "/srv/app"}}}); err != nil {
		t.Fatalf("p-1: %v", err)
	}
	if err := st.Projects.Put(&model.Project{M: model.Meta{UUID: "p-2"}, Name: "app", Paths: []model.ProjectPath{{MachineID: "A", Path: "/opt/app"}}}); err != nil {
		t.Fatalf("p-2: %v", err)
	}
	// Two backup settings for the same machine with DIFFERENT sealed passwords.
	if err := st.BackupSettingsColl.Put(&model.BackupSettings{M: model.Meta{UUID: "bs-a"}, MachineID: "A", PasswordSealed: "sealedX"}); err != nil {
		t.Fatalf("bs-a: %v", err)
	}
	if err := st.BackupSettingsColl.Put(&model.BackupSettings{M: model.Meta{UUID: "bs-b"}, MachineID: "A", PasswordSealed: "sealedY"}); err != nil {
		t.Fatalf("bs-b: %v", err)
	}
	// Two map views, same name, with DIFFERENT layouts.
	if err := st.MapViews.Put(&model.MapView{M: model.Meta{UUID: "mv-a"}, Name: "view", GroupBy: []string{"Project"}, Leaf: "Key"}); err != nil {
		t.Fatalf("mv-a: %v", err)
	}
	if err := st.MapViews.Put(&model.MapView{M: model.Meta{UUID: "mv-b"}, Name: "view", GroupBy: []string{"Machine"}, Leaf: "Key"}); err != nil {
		t.Fatalf("mv-b: %v", err)
	}

	svc.ReconcileCluster("system")

	if n := len(st.OSUsers.List()); n != 2 {
		t.Fatalf("conflicting OS users (differing key base) must both survive; got %d", n)
	}
	if n := len(st.Keys.List()); n != 2 {
		t.Fatalf("conflicting keys (differing sealed private) must both survive; got %d", n)
	}
	if n := len(st.Projects.List()); n != 2 {
		t.Fatalf("conflicting projects (differing path for same machine) must both survive; got %d", n)
	}
	if n := len(st.BackupSettingsColl.List()); n != 2 {
		t.Fatalf("conflicting backup settings (differing sealed password) must both survive; got %d", n)
	}
	if n := len(st.MapViews.List()); n != 2 {
		t.Fatalf("conflicting map views (differing layout) must both survive; got %d", n)
	}
}

// TestReconcileStillMergesLossless proves the gating is precise, not blanket: a duplicate
// that only FILLS an empty field (survivor gains, loses nothing) still merges to one.
func TestReconcileStillMergesLossless(t *testing.T) {
	svc, st := buildNode(t, "A")
	selfMachine(t, svc, st, "A", "nodeA", model.OSLinux)

	// Same key: a metadata-only record (no sealed private) and a generated one. The
	// survivor inherits the sealed half - a pure gain - so they merge to one.
	if err := st.Keys.Put(&model.Key{M: model.Meta{UUID: "k-1"}, Name: "shared", Recipient: "age1abc", PrivSealed: ""}); err != nil {
		t.Fatalf("k-1: %v", err)
	}
	if err := st.Keys.Put(&model.Key{M: model.Meta{UUID: "k-2"}, Name: "shared", Recipient: "age1abc", PrivSealed: "sealed", Generation: 1, Status: model.KeyActive}); err != nil {
		t.Fatalf("k-2: %v", err)
	}
	// Same account, one with an empty key base: the survivor inherits the base.
	if err := st.OSUsers.Put(&model.OSUser{M: model.Meta{UUID: "ou-1"}, MachineID: "A", Username: "dev", KeyBase: ""}); err != nil {
		t.Fatalf("ou-1: %v", err)
	}
	if err := st.OSUsers.Put(&model.OSUser{M: model.Meta{UUID: "ou-2"}, MachineID: "A", Username: "dev", KeyBase: "/home/dev/.sops"}); err != nil {
		t.Fatalf("ou-2: %v", err)
	}

	svc.ReconcileCluster("system")

	keys := st.Keys.List()
	if len(keys) != 1 {
		t.Fatalf("lossless key duplicate must merge to 1; got %d", len(keys))
	}
	if keys[0].PrivSealed != "sealed" {
		t.Fatalf("survivor must inherit the sealed private half; got %q", keys[0].PrivSealed)
	}
	users := st.OSUsers.List()
	if len(users) != 1 {
		t.Fatalf("lossless OS-user duplicate must merge to 1; got %d", len(users))
	}
	if users[0].KeyBase != "/home/dev/.sops" {
		t.Fatalf("survivor must inherit the key base; got %q", users[0].KeyBase)
	}
}

// TestReconcileIdempotent is case (g): a second reconcile over a converged store makes
// no further changes (live counts stable), so the pass never churns.
func TestReconcileIdempotent(t *testing.T) {
	svc, st := buildNode(t, "A")
	selfMachine(t, svc, st, "A", "nodeA", model.OSLinux)
	if err := st.Projects.Put(&model.Project{M: model.Meta{UUID: "p1"}, Name: "app"}); err != nil {
		t.Fatalf("p1: %v", err)
	}
	if err := st.Projects.Put(&model.Project{M: model.Meta{UUID: "p2"}, Name: "app"}); err != nil {
		t.Fatalf("p2: %v", err)
	}
	svc.ReconcileCluster("system")
	projects := len(st.Projects.List())
	machines := liveMachineCount(st)

	svc.ReconcileCluster("system")
	svc.ReconcileCluster("system")
	if len(st.Projects.List()) != projects || liveMachineCount(st) != machines {
		t.Fatalf("reconcile must be idempotent; projects %d->%d machines %d->%d",
			projects, len(st.Projects.List()), machines, liveMachineCount(st))
	}
	if projects != 1 {
		t.Fatalf("duplicate projects must have merged to 1, got %d", projects)
	}
}
