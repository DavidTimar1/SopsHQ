package keysvc

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"sopshq/internal/audit"
	"sopshq/internal/model"
)

// ErrReinstallTargetInvalid means the peer chosen as the reinstall target is not a
// valid choice: it is the pending record itself, the local node, another pending
// record, or not a live machine.
var ErrReinstallTargetInvalid = errors.New("keysvc: choose an existing, confirmed, non-local peer")

// Convergent cluster reconcile.
//
// Two goals, both deterministic so every node reaches the SAME single set of
// records without flip-flop:
//
//  1. MACHINES are one record per physical machine cluster-wide. A node's own
//     record is "canonical". A manually-typed peer placeholder (no canonical id)
//     merges into the canonical record that shares its name. A brand-new canonical
//     identity that appears while another confirmed peer already exists is held
//     Pending for the operator (new peer, or reinstall of an existing one) - the ONE
//     case that always asks. A reinstall the operator confirms merges the new install
//     into the existing peer's identity; the reinstalled node then follows the merge
//     pointer to rewrite its own local identity.
//
//  2. NON-MACHINE records (Project by name, Key by public key, GlobalSet by
//     machine+name, OSUser by machine+username OS-aware, and the per-machine settings)
//     that collide on their natural key are the same thing, so their duplicates fold
//     together automatically.
//
// LOSSLESS-ONLY POLICY. An automatic merge is performed ONLY when it is provably
// lossless: identical records collapse, a set (recipients, project paths) is unioned,
// and a value fills a field the survivor left EMPTY. If the two records disagree on
// any non-empty field - a differing sealed credential, key material, key-store base,
// project path for the same machine, backup destination, notification channel, machine
// address, or map layout - the merge is SKIPPED and BOTH records are left intact. The
// reconcile pass never deletes a record or overwrites a non-empty value to resolve such
// a conflict; a real deletion is left to an explicit, operator-confirmed flow. Because
// the lossless rules and the conflict test are deterministic, every node performs the
// same automatic merges and skips the same conflicts, so the cluster still converges.
//
// The pass is idempotent: with nothing to do it only scans. It heals pre-existing
// duplicates on the next run: records already stored as several rows for one
// machine converge without operator action.

// ReconcileResult reports what a reconcile pass changed. LocalMachineID is the
// (possibly-updated) local machine id after following any merge redirect that
// absorbed this node's own record; LocalChanged says it moved, so the caller must
// persist it to the config.
type ReconcileResult struct {
	LocalMachineID string
	LocalChanged   bool
	MachinesMerged int
	EntitiesMerged int
	PendingPeers   int
}

// ReconcileCluster runs one convergent reconcile pass and returns what changed. It
// is safe to call on startup, after any mutation, and on a timer. The machine
// portion runs only when a local machine is designated (a node not yet linked to a
// machine record is not part of the cluster-identity flow); the non-machine dedup
// runs always. Every change is a normal local mutation (Put/Delete tombstone) so it
// replicates, and determinism is what makes the replicas converge.
func (s *Service) ReconcileCluster(actor string) ReconcileResult {
	res := ReconcileResult{LocalMachineID: s.localMachineID}

	if s.localMachineID != "" {
		s.healLocalCanonical(actor)
		res.MachinesMerged = s.dedupMachinesByName(actor)
		// followLocalMerge and repointAllMerged run AFTER dedupMachinesByName so a merge
		// this pass created re-points in the same pass. All machine re-pointing is
		// TOMBSTONE-DRIVEN (repointAllMerged owns it): mergeMachine only tombstones with a
		// MergedInto redirect, so if a concurrent ConfirmNewPeer wins last-writer-wins and
		// the loser resurrects LIVE, no eager re-point has already mis-attached its
		// records to the wrong machine.
		if newLocal, changed := s.followLocalMerge(); changed {
			s.localMachineID = newLocal
			res.LocalMachineID = newLocal
			res.LocalChanged = true
		}
		s.repointAllMerged(actor)
	}

	res.EntitiesMerged += s.dedupOSUsers(actor)
	res.EntitiesMerged += s.dedupKeys(actor)
	res.EntitiesMerged += s.dedupProjects(actor)
	res.EntitiesMerged += s.dedupGlobalSets(actor)
	res.EntitiesMerged += s.dedupBackupSettings(actor)
	res.EntitiesMerged += s.dedupNotificationSettings(actor)
	res.EntitiesMerged += s.dedupMapViews(actor)
	// Re-point every reference that still names a merged-away (tombstoned + MergedInto)
	// record onto its live survivor BEFORE de-duplicating or pruning assignments, so a
	// grant another node created against a record this node merged away is preserved (not
	// left dangling, not pruned). Idempotent and convergent.
	s.repointMergedRefs(actor)
	s.dedupAssignments(actor)

	if s.localMachineID != "" {
		res.PendingPeers = s.markPendingPeers(actor)
	}
	s.PruneOrphanedAssignments(actor)
	return res
}

// ---- machine identity -----------------------------------------------------

// healLocalCanonical marks this node's own machine record Canonical, so a legacy
// store (whose self-record predates the canonical flag) is upgraded in place. It
// writes only when the flag is not already set, preserving every other field
// (including a Pending flag a peer may have set), so it never churns or flip-flops.
func (s *Service) healLocalCanonical(actor string) {
	mc, ok := s.store.Machines.GetRaw(s.localMachineID)
	if !ok || mc.M.Deleted || mc.Canonical {
		return
	}
	mc.Canonical = true
	_ = s.store.Machines.Put(mc)
	_ = s.audit.Record(actor, "machine_heal_canonical", mc.Name, audit.OK, "")
}

// followLocalMerge follows this node's own machine record through any merge
// redirect (set when the operator confirmed elsewhere that this install is a
// reinstall of an existing peer) to the surviving identity. It returns the final
// id and whether it moved, so the caller rewrites cfg.LocalMachineID. It also
// updates the service's own SetLocalMachine so the key engine follows immediately.
func (s *Service) followLocalMerge() (newLocal string, changed bool) {
	final := s.resolveMachine(s.localMachineID)
	if final == "" || final == s.localMachineID {
		return s.localMachineID, false
	}
	s.SetLocalMachine(final)
	s.ackPeer(final)
	return final, true
}

// resolveMachine follows a chain of MergedInto redirects from id to the surviving
// (live) machine id. It stops at the first live record or a broken pointer, and
// guards against a cycle. An unknown id resolves to itself.
func (s *Service) resolveMachine(id string) string {
	seen := map[string]bool{}
	cur := id
	for cur != "" && !seen[cur] {
		seen[cur] = true
		mc, ok := s.store.Machines.GetRaw(cur)
		if !ok {
			return cur
		}
		if !mc.M.Deleted || mc.MergedInto == "" {
			return cur
		}
		cur = mc.MergedInto
	}
	return cur
}

// repointAllMerged re-points every reference away from a merged-away machine to its
// surviving identity, on every node, so references converge no matter which node
// performed the merge. It is idempotent: it writes a record only when a reference
// actually changes, so once settled it produces no further writes.
func (s *Service) repointAllMerged(actor string) {
	for _, mc := range s.store.Machines.All() {
		if !mc.M.Deleted || mc.MergedInto == "" {
			continue
		}
		final := s.resolveMachine(mc.MergedInto)
		if final == "" || final == mc.M.UUID {
			continue
		}
		s.repointMachineRefs(mc.M.UUID, final, actor)
	}
}

// dedupMachinesByName merges machine records that name the same physical machine.
// Grouping is by case-insensitive name. Within a group:
//   - exactly one canonical record: every placeholder in the group merges into it
//     (the canonical id is referenced cluster-wide, so it must survive);
//   - no canonical record: the placeholders merge into the smallest-UUID one;
//   - two or more canonical records: left alone - two real self-records sharing a
//     name is the reinstall/rename ambiguity, which the Pending confirmation
//     resolves, never a silent merge.
//
// It returns how many records were merged away.
func (s *Service) dedupMachinesByName(actor string) int {
	groups := map[string][]*model.Machine{}
	var order []string
	for _, mc := range s.store.Machines.List() {
		key := strings.ToLower(strings.TrimSpace(mc.Name))
		if key == "" {
			continue
		}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], mc)
	}
	merged := 0
	for _, key := range order {
		grp := groups[key]
		if len(grp) < 2 {
			continue
		}
		var canon []*model.Machine
		var placeholders []*model.Machine
		for _, mc := range grp {
			if mc.Canonical {
				canon = append(canon, mc)
			} else {
				placeholders = append(placeholders, mc)
			}
		}
		switch {
		case len(canon) >= 2:
			continue // reinstall/rename ambiguity - the Pending flow decides
		case len(canon) == 1:
			for _, ph := range placeholders {
				if machinesConflict(canon[0], ph) {
					continue // differing non-empty address/OS/version - leave both for confirm
				}
				s.mergeMachine(ph, canon[0], actor)
				merged++
			}
		default: // no canonical: keep the smallest-UUID placeholder
			survivor := smallestByUUID(placeholders)
			for _, ph := range placeholders {
				if ph.M.UUID == survivor.M.UUID {
					continue
				}
				if machinesConflict(survivor, ph) {
					continue // differing non-empty address/OS/version - leave both for confirm
				}
				s.mergeMachine(ph, survivor, actor)
				merged++
			}
		}
	}
	return merged
}

// mergeMachine folds loser into survivor: it copies useful fields survivor lacks
// (advertised address, port, OS, version, last-seen), then tombstones loser with a
// MergedInto redirect so the merge replicates. It does NOT move references here -
// re-pointing is tombstone-driven and owned by repointAllMerged (run later in the
// same reconcile pass). That way, if a concurrent decision on another node resurrects
// the loser LIVE via last-writer-wins, no eager re-point has already silently
// re-attached its OS users / assignments / global sets to the wrong machine. survivor
// keeps its own id. Fields that differ between the two are NOT merged (the survivor's
// win): the two are the same machine by construction, so a differing value is stale.
func (s *Service) mergeMachine(loser, survivor *model.Machine, actor string) {
	if loser.M.UUID == survivor.M.UUID {
		return
	}
	changed := false
	if survivor.TailscaleHost == "" && loser.TailscaleHost != "" {
		survivor.TailscaleHost = loser.TailscaleHost
		if survivor.AgentPort == 0 {
			survivor.AgentPort = loser.AgentPort
		}
		changed = true
	}
	if survivor.AgentPort == 0 && loser.AgentPort != 0 {
		survivor.AgentPort = loser.AgentPort
		changed = true
	}
	if survivor.OS == "" && loser.OS != "" {
		survivor.OS = loser.OS
		changed = true
	}
	if survivor.Version == "" && loser.Version != "" {
		survivor.Version = loser.Version
		changed = true
	}
	if loser.LastSeen > survivor.LastSeen {
		survivor.LastSeen = loser.LastSeen
		changed = true
	}
	if changed {
		_ = s.store.Machines.Put(survivor)
	}
	loser.MergedInto = survivor.M.UUID
	_ = s.store.Machines.Put(loser)
	_ = s.store.Machines.Delete(loser.M.UUID)
	_ = s.audit.Record(actor, "machine_merge", survivor.Name, audit.OK, "absorbed "+loser.M.UUID)
}

// repointMachineRefs moves every reference from oldID to newID: OSUser.MachineID,
// Assignment.MachineID, Project.Paths[].MachineID (de-duplicating a project path that
// then names the same machine twice), GlobalSet.MachineID, and the two machine-scoped
// settings records (BackupSettings, NotificationSettings) so a merged-away machine's
// backup schedule and notification channels are not orphaned onto a tombstone. It
// writes a record only when it actually changes, so it is idempotent and never churns.
// (MapView carries no MachineID - it is not machine-scoped - so there is nothing to
// re-point there; it is de-duplicated by name instead.)
func (s *Service) repointMachineRefs(oldID, newID, actor string) {
	for _, u := range s.store.OSUsers.List() {
		if u.MachineID == oldID {
			u.MachineID = newID
			_ = s.store.OSUsers.Put(u)
		}
	}
	for _, a := range s.store.Assignments.List() {
		if a.MachineID == oldID {
			a.MachineID = newID
			_ = s.store.Assignments.Put(a)
		}
	}
	for _, p := range s.store.Projects.List() {
		moved := false
		newPath, hasNew := "", false
		for _, pp := range p.Paths {
			if pp.MachineID == newID {
				hasNew = true
				newPath = pp.Path
			}
		}
		out := p.Paths[:0:0]
		for _, pp := range p.Paths {
			if pp.MachineID == oldID {
				moved = true
				if hasNew {
					if pp.Path == newPath {
						continue // identical path already present - drop the true duplicate
					}
					// A DIFFERENT path for the merged machine is real data; keep it rather
					// than drop it. Both entries name the survivor machine now.
					pp.MachineID = newID
					out = append(out, pp)
					continue
				}
				pp.MachineID = newID
			}
			out = append(out, pp)
		}
		if moved {
			p.Paths = out
			_ = s.store.Projects.Put(p)
		}
	}
	for _, g := range s.store.GlobalSets.List() {
		if g.MachineID == oldID {
			g.MachineID = newID
			_ = s.store.GlobalSets.Put(g)
		}
	}
	for _, b := range s.store.BackupSettingsColl.List() {
		if b.MachineID == oldID {
			b.MachineID = newID
			_ = s.store.BackupSettingsColl.Put(b)
		}
	}
	for _, n := range s.store.NotificationSettingsColl.List() {
		if n.MachineID == oldID {
			n.MachineID = newID
			_ = s.store.NotificationSettingsColl.Put(n)
		}
	}
}

// repointMergedRefs re-points every reference that still targets a merged-away
// non-machine record (a Key/OSUser/Project tombstone carrying a Meta.MergedInto redirect)
// onto its surviving record, on EVERY reconcile pass. This is the non-machine analogue of
// repointAllMerged: it makes a reference another node created against a record THIS node
// merged away converge onto the survivor instead of dangling. It writes a record only when
// a reference actually changes, so it is idempotent and never churns.
//
// It re-points Assignment.KeyID / OSUserID / ProjectID and GlobalSet reader ids. A
// merged-away GlobalSet, per-machine settings or map view has no inbound reference, so
// there is nothing to re-point for those kinds (their tombstone's MergedInto is harmless).
func (s *Service) repointMergedRefs(actor string) {
	for _, k := range s.store.Keys.All() {
		if !k.M.Deleted || k.M.MergedInto == "" {
			continue
		}
		final := resolveMerged(s.store.Keys, k.M.MergedInto)
		if final == "" || final == k.M.UUID {
			continue
		}
		for _, a := range s.store.Assignments.List() {
			if a.KeyID == k.M.UUID {
				a.KeyID = final
				_ = s.store.Assignments.Put(a)
			}
		}
	}
	for _, u := range s.store.OSUsers.All() {
		if !u.M.Deleted || u.M.MergedInto == "" {
			continue
		}
		final := resolveMerged(s.store.OSUsers, u.M.MergedInto)
		if final == "" || final == u.M.UUID {
			continue
		}
		for _, a := range s.store.Assignments.List() {
			if a.OSUserID == u.M.UUID {
				a.OSUserID = final
				_ = s.store.Assignments.Put(a)
			}
		}
		// A global-set membership pointing at the merged-away account moves to the
		// survivor - never silently dropped.
		for _, g := range s.store.GlobalSets.List() {
			if replaceRecipient(g, u.M.UUID, final) {
				_ = s.store.GlobalSets.Put(g)
			}
		}
	}
	for _, p := range s.store.Projects.All() {
		if !p.M.Deleted || p.M.MergedInto == "" {
			continue
		}
		final := resolveMerged(s.store.Projects, p.M.MergedInto)
		if final == "" || final == p.M.UUID {
			continue
		}
		for _, a := range s.store.Assignments.List() {
			if a.ProjectID == p.M.UUID {
				a.ProjectID = final
				_ = s.store.Assignments.Put(a)
			}
		}
	}
}

// ---- new-peer confirmation ------------------------------------------------

// ErrPeerNotPending means the machine is no longer awaiting confirmation - another
// node (or an earlier click) already resolved it. Refusing on this shrinks the window
// for two nodes to make opposite decisions on the same pending record.
var ErrPeerNotPending = errors.New("keysvc: this peer is no longer pending (already resolved)")

// ConfirmNewPeer accepts a Pending machine as a distinct new peer: it clears the
// Pending flag and sets Confirmed (both on the REPLICATED record, so every node sees
// the decision), and records the decision in this node's local memory. It refuses if
// the record is no longer Pending, so a decision already made elsewhere is not undone.
func (s *Service) ConfirmNewPeer(machineID, actor string) error {
	mc, err := s.store.Machines.Get(machineID)
	if err != nil {
		return err
	}
	if !mc.Pending {
		return ErrPeerNotPending
	}
	mc.Pending = false
	mc.Confirmed = true
	if err := s.store.Machines.Put(mc); err != nil {
		return err
	}
	s.ackPeer(machineID)
	_ = s.audit.Record(actor, "peer_confirm_new", mc.Name, audit.OK, "")
	return nil
}

// ConfirmReinstallPeer resolves a Pending machine as a REINSTALL of an existing,
// confirmed, non-local peer: it merges the new install (newID) into that existing
// peer (existingID), so the reinstalled node takes over the existing identity and
// every reference re-points to it. If the confirming node is the reinstalled one,
// its own local record is the one merged away; the reconcile pass then follows the
// merge redirect to rewrite this node's local identity. existingID must be a live,
// confirmed, non-local peer distinct from newID.
func (s *Service) ConfirmReinstallPeer(newID, existingID, actor string) error {
	loser, err := s.store.Machines.Get(newID)
	if err != nil {
		return err
	}
	// Refuse to undo a decision already made on a PENDING peer (a concurrent opposite confirmation). The one
	// exception is this node declaring its OWN record a reinstall (its self-record is
	// never pending), which is always a legitimate operator action on the machine itself.
	if !loser.Pending && newID != s.localMachineID {
		return ErrPeerNotPending
	}
	survivor, err := s.store.Machines.Get(existingID)
	if err != nil {
		return ErrReinstallTargetInvalid
	}
	if existingID == newID || existingID == s.localMachineID || survivor.Pending {
		return ErrReinstallTargetInvalid
	}
	// Record the surviving identity as confirmed (replicated), so no node re-flags it,
	// then merge the new install into it (tombstone-only; re-pointing happens in the
	// reconcile pass).
	if !survivor.Confirmed {
		survivor.Confirmed = true
		_ = s.store.Machines.Put(survivor)
	}
	s.mergeMachine(loser, survivor, actor)
	s.ackPeer(newID)
	_ = s.audit.Record(actor, "peer_confirm_reinstall", survivor.Name, audit.OK, "reinstall of "+existingID)
	return nil
}

// ReinstallCandidates lists the confirmed, non-local peers a Pending machine could
// be a reinstall of (every live machine that is not the local node, not the pending
// record itself, and not itself pending), for the confirmation dropdown.
func (s *Service) ReinstallCandidates(pendingID string) []*model.Machine {
	var out []*model.Machine
	for _, mc := range s.store.Machines.List() {
		if mc.M.UUID == s.localMachineID || mc.M.UUID == pendingID || mc.Pending {
			continue
		}
		out = append(out, mc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// markPendingPeers flags a newly-noticed peer identity Pending when another
// confirmed peer already exists, so it is held for the operator's new-vs-reinstall
// decision instead of silently becoming a distinct machine. It uses a machine-local,
// non-replicated "acknowledged peers" set (peers_ack.json) to remember which peer
// ids this node has already decided about, so a confirmed peer is never re-flagged
// and the pass never flip-flops. On the FIRST run (no set yet) it grandfathers every
// record then present - pre-existing peers are trusted, only peers that appear later
// are evaluated. It returns how many peers it flagged Pending this pass.
func (s *Service) markPendingPeers(actor string) int {
	path := s.ackPath()
	_, statErr := os.Stat(path)
	first := os.IsNotExist(statErr)
	ack := s.loadAck()

	live := s.store.Machines.List()
	if first {
		// Grandfather every record already present: they are pre-existing, established
		// machines, not new arrivals. Mark them Confirmed (replicated, so a late-joining
		// node also sees they are decided) and remember them locally.
		for _, mc := range live {
			if !mc.Confirmed {
				mc.Confirmed = true
				_ = s.store.Machines.Put(mc)
			}
			ack[mc.M.UUID] = true
		}
		s.saveAck(ack)
		return 0
	}

	flagged := 0
	for _, mc := range live {
		// Skip anything already decided: our own record, a peer we acked locally, or a
		// peer marked Confirmed on the record itself (a decision replicated from another
		// node - so a confirmed peer is never re-flagged, even here).
		if mc.M.UUID == s.localMachineID || mc.Confirmed || ack[mc.M.UUID] {
			continue
		}
		// A peer we have not decided about yet. If another CONFIRMED peer already
		// exists, hold this one for the operator; otherwise it is the first/only peer
		// and is accepted with no prompt (and marked Confirmed so it too is decided
		// cluster-wide).
		if s.confirmedPeerExists(mc.M.UUID) {
			if !mc.Pending {
				mc.Pending = true
				if err := s.store.Machines.Put(mc); err == nil {
					_ = s.audit.Record(actor, "peer_pending", mc.Name, audit.OK, "awaiting new-vs-reinstall confirmation")
				}
			}
			flagged++
		} else if !mc.Confirmed {
			mc.Confirmed = true
			_ = s.store.Machines.Put(mc)
		}
		ack[mc.M.UUID] = true
	}
	s.saveAck(ack)
	return flagged
}

// confirmedPeerExists reports whether a live, Confirmed, non-local machine other than
// exclID exists - the "another confirmed peer already exists" test that turns a fresh
// peer's arrival into a confirmation prompt. It reads the replicated Confirmed flag,
// so the answer is consistent across nodes.
func (s *Service) confirmedPeerExists(exclID string) bool {
	for _, mc := range s.store.Machines.List() {
		if mc.M.UUID == s.localMachineID || mc.M.UUID == exclID {
			continue
		}
		if mc.Confirmed {
			return true
		}
	}
	return false
}

// ackPath is the machine-local file recording which peer ids this node has already
// decided about (never replicated - it is this node's memory, like the sync
// watermarks).
func (s *Service) ackPath() string { return filepath.Join(s.store.Dir(), "peers_ack.json") }

// loadAck reads the acknowledged-peers set (empty when absent or unreadable).
func (s *Service) loadAck() map[string]bool {
	out := map[string]bool{}
	b, err := os.ReadFile(s.ackPath())
	if err != nil {
		return out
	}
	var ids []string
	if json.Unmarshal(b, &ids) == nil {
		for _, id := range ids {
			out[id] = true
		}
	}
	return out
}

// saveAck writes the acknowledged-peers set atomically.
func (s *Service) saveAck(set map[string]bool) {
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	b, err := json.MarshalIndent(ids, "", "  ")
	if err != nil {
		return
	}
	tmp := s.ackPath() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, s.ackPath())
	}
}

// ackPeer records that this node has decided about a peer id, so the reconcile pass
// never re-prompts for it.
func (s *Service) ackPeer(id string) {
	ack := s.loadAck()
	if ack[id] {
		return
	}
	ack[id] = true
	s.saveAck(ack)
}

// ---- non-machine silent dedup ---------------------------------------------

// dedupKeys merges Key records that share a public key (Recipient): the smallest-
// UUID key survives, its assignments absorb the losers', and the losers are
// tombstoned. Ungenerated keys (empty Recipient) are never grouped - they are not
// yet a real public key. Returns how many keys were merged away.
func (s *Service) dedupKeys(actor string) int {
	groups := map[string][]*model.Key{}
	for _, k := range s.store.Keys.List() {
		if k.Recipient == "" {
			continue
		}
		groups[k.Recipient] = append(groups[k.Recipient], k)
	}
	merged := 0
	for _, grp := range groups {
		if len(grp) < 2 {
			continue
		}
		survivor := smallestKeyByUUID(grp)
		for _, k := range grp {
			if k.M.UUID == survivor.M.UUID {
				continue
			}
			// Two records for the same public key normally hold the same key material,
			// but if they disagree on a non-empty sealed private half, rotation status, or
			// owner, that is a real difference; folding one away would drop it. Leave both
			// for an operator-confirmed merge.
			if keysConflict(survivor, k) {
				continue
			}
			for _, a := range s.store.Assignments.List() {
				if a.KeyID == k.M.UUID {
					a.KeyID = survivor.M.UUID
					_ = s.store.Assignments.Put(a)
				}
			}
			// Fold in fields the survivor lacks (survivor gains, loses nothing): a
			// metadata-only survivor inherits the loser's sealed private half and becomes
			// usable rather than a dead reference. Only EMPTY survivor fields are filled;
			// a conflicting non-empty value was already skipped above.
			if kv := foldKeyFields(survivor, k); kv {
				_ = s.store.Keys.Put(survivor)
			}
			mergeTombstone(s.store.Keys, k, survivor.M.UUID)
			merged++
		}
		_ = s.audit.Record(actor, "key_dedup", survivor.Name, audit.OK, "merged duplicate public key")
	}
	return merged
}

// foldKeyFields fills the survivor key's EMPTY fields from the loser (sealed private
// half, generation, status, note, name, type), so a metadata-only survivor inherits a
// usable keypair and no field only the loser set is dropped. Timestamps fold to the
// earliest creation and latest edit (never a loss). Returns whether the survivor changed.
// A field both set but DIFFERING is left to keysConflict, which blocks the auto-merge and
// surfaces the field for operator resolution.
func foldKeyFields(survivor, loser *model.Key) bool {
	changed := false
	if survivor.PrivSealed == "" && loser.PrivSealed != "" {
		survivor.PrivSealed = loser.PrivSealed
		if survivor.Generation == 0 {
			survivor.Generation = loser.Generation
		}
		if survivor.Status == "" {
			survivor.Status = loser.Status
		}
		changed = true
	}
	if survivor.Note == "" && loser.Note != "" {
		survivor.Note = loser.Note
		changed = true
	}
	if survivor.Name == "" && loser.Name != "" {
		survivor.Name = loser.Name
		changed = true
	}
	if survivor.Type == "" && loser.Type != "" {
		survivor.Type = loser.Type
		changed = true
	}
	if loser.CreatedAt != 0 && (survivor.CreatedAt == 0 || loser.CreatedAt < survivor.CreatedAt) {
		survivor.CreatedAt = loser.CreatedAt
		changed = true
	}
	if loser.EditedAt > survivor.EditedAt {
		survivor.EditedAt = loser.EditedAt
		changed = true
	}
	return changed
}

// dedupBackupSettings merges the per-machine backup-settings records so a machine has
// at most one (two nodes both minting a default is the collision). The smallest-UUID
// record survives and inherits any configured field it lacks (a sealed password,
// destinations, an enabled schedule) from a loser; differing non-empty values are kept
// as the survivor's (same machine => same intended settings). Losers are tombstoned.
func (s *Service) dedupBackupSettings(actor string) int {
	groups := map[string][]*model.BackupSettings{}
	for _, b := range s.store.BackupSettingsColl.List() {
		if b.MachineID == "" {
			continue
		}
		groups[b.MachineID] = append(groups[b.MachineID], b)
	}
	merged := 0
	for _, grp := range groups {
		if len(grp) < 2 {
			continue
		}
		survivor := grp[0]
		for _, b := range grp[1:] {
			if b.M.UUID < survivor.M.UUID {
				survivor = b
			}
		}
		for _, b := range grp {
			if b.M.UUID == survivor.M.UUID {
				continue
			}
			// A differing non-empty sealed password, schedule, or destination list is real
			// configuration; folding one away would drop it. Leave both for confirm.
			if backupSettingsConflict(survivor, b) {
				continue
			}
			if foldBackupFields(survivor, b) {
				_ = s.store.BackupSettingsColl.Put(survivor)
			}
			mergeTombstone(s.store.BackupSettingsColl, b, survivor.M.UUID)
			merged++
		}
		_ = s.audit.Record(actor, "backup_settings_dedup", survivor.MachineID, audit.OK, "merged duplicate per-machine backup settings")
	}
	return merged
}

// foldBackupFields fills the survivor's empty backup fields from a loser. Differing
// non-empty values are kept as the survivor's (same-machine premise).
func foldBackupFields(survivor, loser *model.BackupSettings) bool {
	changed := false
	if !survivor.Enabled && loser.Enabled {
		survivor.Enabled = true
		changed = true
	}
	if survivor.PasswordSealed == "" && loser.PasswordSealed != "" {
		survivor.PasswordSealed = loser.PasswordSealed
		changed = true
	}
	if survivor.DailyAt == "" && loser.DailyAt != "" {
		survivor.DailyAt = loser.DailyAt
		changed = true
	}
	if len(survivor.Destinations) == 0 && len(loser.Destinations) > 0 {
		survivor.Destinations = loser.Destinations
		changed = true
	}
	if survivor.BaseName == "" && loser.BaseName != "" {
		survivor.BaseName = loser.BaseName
		changed = true
	}
	if survivor.DateFormat == "" && loser.DateFormat != "" {
		survivor.DateFormat = loser.DateFormat
		changed = true
	}
	if survivor.DatePosition == "" && loser.DatePosition != "" {
		survivor.DatePosition = loser.DatePosition
		changed = true
	}
	return changed
}

// dedupNotificationSettings merges the per-machine notification-settings records so a
// machine has at most one. The smallest-UUID record survives and inherits any
// configured channel it lacks; differing non-empty values are kept as the survivor's.
func (s *Service) dedupNotificationSettings(actor string) int {
	groups := map[string][]*model.NotificationSettings{}
	for _, n := range s.store.NotificationSettingsColl.List() {
		if n.MachineID == "" {
			continue
		}
		groups[n.MachineID] = append(groups[n.MachineID], n)
	}
	merged := 0
	for _, grp := range groups {
		if len(grp) < 2 {
			continue
		}
		survivor := grp[0]
		for _, n := range grp[1:] {
			if n.M.UUID < survivor.M.UUID {
				survivor = n
			}
		}
		for _, n := range grp {
			if n.M.UUID == survivor.M.UUID {
				continue
			}
			// A differing non-empty sealed channel credential is real configuration;
			// folding one away would drop it. Leave both for confirm.
			if notificationSettingsConflict(survivor, n) {
				continue
			}
			if foldNotificationFields(survivor, n) {
				_ = s.store.NotificationSettingsColl.Put(survivor)
			}
			mergeTombstone(s.store.NotificationSettingsColl, n, survivor.M.UUID)
			merged++
		}
		_ = s.audit.Record(actor, "notification_settings_dedup", survivor.MachineID, audit.OK, "merged duplicate per-machine notification settings")
	}
	return merged
}

// foldNotificationFields fills the survivor's empty notification channels from a loser.
// Differing non-empty values are kept as the survivor's (same-machine premise).
func foldNotificationFields(survivor, loser *model.NotificationSettings) bool {
	changed := false
	if !survivor.Enabled && loser.Enabled {
		survivor.Enabled = true
		changed = true
	}
	if survivor.TelegramTokenSealed == "" && loser.TelegramTokenSealed != "" {
		survivor.TelegramTokenSealed = loser.TelegramTokenSealed
		survivor.TelegramChatID = loser.TelegramChatID
		survivor.TelegramEnabled = survivor.TelegramEnabled || loser.TelegramEnabled
		changed = true
	}
	if survivor.SlackWebhookSealed == "" && loser.SlackWebhookSealed != "" {
		survivor.SlackWebhookSealed = loser.SlackWebhookSealed
		survivor.SlackEnabled = survivor.SlackEnabled || loser.SlackEnabled
		changed = true
	}
	// Union the per-event toggle map by event key: an event only the loser carries is
	// added, so a toggle is never dropped. A key present in BOTH but set differently is a
	// real disagreement left to notificationSettingsConflict (it blocks the auto-merge).
	if len(loser.Events) > 0 {
		if survivor.Events == nil {
			survivor.Events = map[string]bool{}
		}
		for k, v := range loser.Events {
			if _, ok := survivor.Events[k]; !ok {
				survivor.Events[k] = v
				changed = true
			}
		}
	}
	return changed
}

// dedupMapViews merges custom Map views that share a case-insensitive name to the
// smallest-UUID survivor (a view is a display layout, so a differing group-by ordering
// on a same-named duplicate is discarded rather than merged). Losers are tombstoned.
func (s *Service) dedupMapViews(actor string) int {
	groups := map[string][]*model.MapView{}
	for _, v := range s.store.MapViews.List() {
		name := strings.ToLower(strings.TrimSpace(v.Name))
		if name == "" {
			continue
		}
		groups[name] = append(groups[name], v)
	}
	merged := 0
	for _, grp := range groups {
		if len(grp) < 2 {
			continue
		}
		survivor := grp[0]
		for _, v := range grp[1:] {
			if v.M.UUID < survivor.M.UUID {
				survivor = v
			}
		}
		for _, v := range grp {
			if v.M.UUID == survivor.M.UUID {
				continue
			}
			// A same-named view with a DIFFERENT layout (group-by order or leaf) is a
			// distinct saved layout, not a duplicate; deleting it would lose it. Only an
			// identical-layout duplicate is removed.
			if !mapViewLayoutEqual(survivor, v) {
				continue
			}
			mergeTombstone(s.store.MapViews, v, survivor.M.UUID)
			merged++
		}
		_ = s.audit.Record(actor, "map_view_dedup", survivor.Name, audit.OK, "merged duplicate map view name")
	}
	return merged
}

// dedupProjects merges Project records that share a case-insensitive name: the
// smallest-UUID project survives, its paths (unioned by machine) and assignments
// absorb the losers', and the losers are tombstoned. Returns how many were merged.
func (s *Service) dedupProjects(actor string) int {
	groups := map[string][]*model.Project{}
	for _, p := range s.store.Projects.List() {
		key := strings.ToLower(strings.TrimSpace(p.Name))
		if key == "" {
			continue
		}
		groups[key] = append(groups[key], p)
	}
	merged := 0
	for _, grp := range groups {
		if len(grp) < 2 {
			continue
		}
		survivor := smallestProjectByUUID(grp)
		for _, p := range grp {
			if p.M.UUID == survivor.M.UUID {
				continue
			}
			// If both name the SAME machine but at a DIFFERENT path, or they carry a
			// different non-empty note, that is a real disagreement; folding one project
			// away would drop it. Leave both for an operator-confirmed merge. (Paths for
			// machines the survivor lacks are a pure addition, unioned losslessly below.)
			if projectsConflict(survivor, p) {
				continue
			}
			for _, a := range s.store.Assignments.List() {
				if a.ProjectID == p.M.UUID {
					a.ProjectID = survivor.M.UUID
					_ = s.store.Assignments.Put(a)
				}
			}
			if foldProjectFields(survivor, p) {
				_ = s.store.Projects.Put(survivor)
			}
			mergeTombstone(s.store.Projects, p, survivor.M.UUID)
			merged++
		}
		_ = s.audit.Record(actor, "project_dedup", survivor.Name, audit.OK, "merged duplicate project name")
	}
	return merged
}

// dedupGlobalSets merges GlobalSet records that share a machine + case-insensitive
// name: the smallest-UUID set survives and absorbs the losers' recipient users
// (unioned), then the losers are tombstoned. Returns how many were merged.
func (s *Service) dedupGlobalSets(actor string) int {
	groups := map[string][]*model.GlobalSet{}
	for _, g := range s.store.GlobalSets.List() {
		name := strings.ToLower(strings.TrimSpace(g.Name))
		if name == "" || g.MachineID == "" {
			continue
		}
		groups[g.MachineID+"\x00"+name] = append(groups[g.MachineID+"\x00"+name], g)
	}
	merged := 0
	for _, grp := range groups {
		if len(grp) < 2 {
			continue
		}
		survivor := smallestSetByUUID(grp)
		for _, g := range grp {
			if g.M.UUID == survivor.M.UUID {
				continue
			}
			if unionRecipients(survivor, g.RecipientUserIDs) {
				_ = s.store.GlobalSets.Put(survivor)
			}
			mergeTombstone(s.store.GlobalSets, g, survivor.M.UUID)
			merged++
		}
		_ = s.audit.Record(actor, "global_set_dedup", survivor.Name, audit.OK, "merged duplicate set name")
	}
	return merged
}

// dedupOSUsers merges OSUser records that name the same account on the same machine.
// The username comparison is OS-aware (Windows account names are case-insensitive,
// Linux names are case-sensitive), matching createOSUser. The smallest-UUID record
// survives (keeping a non-empty key-store base), its assignments and global-set
// recipient memberships absorb the losers', and the losers are tombstoned.
func (s *Service) dedupOSUsers(actor string) int {
	groups := map[string][]*model.OSUser{}
	for _, u := range s.store.OSUsers.List() {
		if u.MachineID == "" || u.Username == "" {
			continue
		}
		name := u.Username
		if s.machineIsWindows(u.MachineID) {
			name = strings.ToLower(name)
		}
		groups[u.MachineID+"\x00"+name] = append(groups[u.MachineID+"\x00"+name], u)
	}
	merged := 0
	for _, grp := range groups {
		if len(grp) < 2 {
			continue
		}
		survivor := smallestUserByUUID(grp)
		for _, u := range grp {
			if u.M.UUID == survivor.M.UUID {
				continue
			}
			// A differing non-empty key-store base is real, distinct data; folding one
			// account away would drop it. Leave both for an operator-confirmed merge.
			if osUserConflict(survivor, u) {
				continue
			}
			for _, a := range s.store.Assignments.List() {
				if a.OSUserID == u.M.UUID {
					a.OSUserID = survivor.M.UUID
					_ = s.store.Assignments.Put(a)
				}
			}
			for _, g := range s.store.GlobalSets.List() {
				if replaceRecipient(g, u.M.UUID, survivor.M.UUID) {
					_ = s.store.GlobalSets.Put(g)
				}
			}
			// Fill an empty survivor key-store base from the loser (survivor gains, loses
			// nothing). A conflicting non-empty base was already skipped above.
			if survivor.KeyBase == "" && u.KeyBase != "" {
				survivor.KeyBase = u.KeyBase
				_ = s.store.OSUsers.Put(survivor)
			}
			mergeTombstone(s.store.OSUsers, u, survivor.M.UUID)
			merged++
		}
		_ = s.audit.Record(actor, "osuser_dedup", survivor.Username, audit.OK, "merged duplicate account")
	}
	return merged
}

// dedupAssignments tombstones assignment rows that became identical after a merge
// re-pointed their key/project/machine/user, keeping the smallest-UUID row of each
// identical quadruple so no grant is duplicated. Idempotent.
func (s *Service) dedupAssignments(actor string) int {
	byKey := map[string][]*model.Assignment{}
	for _, a := range s.store.Assignments.List() {
		k := a.KeyID + "\x00" + a.ProjectID + "\x00" + a.MachineID + "\x00" + a.OSUserID
		byKey[k] = append(byKey[k], a)
	}
	removed := 0
	for _, grp := range byKey {
		if len(grp) < 2 {
			continue
		}
		survivor := smallestAsgByUUID(grp)
		for _, a := range grp {
			if a.M.UUID == survivor.M.UUID {
				continue
			}
			if s.store.Assignments.Delete(a.M.UUID) == nil {
				removed++
			}
		}
	}
	if removed > 0 {
		_ = s.audit.Record(actor, "assignment_dedup", "", audit.OK, "removed duplicate grant(s)")
	}
	return removed
}

// machineIsWindows reports whether a machine (live or tombstoned) is Windows, for
// the OS-aware OS-user comparison.
func (s *Service) machineIsWindows(machineID string) bool {
	if mc, ok := s.store.Machines.GetRaw(machineID); ok {
		return mc.OS == model.OSWindows
	}
	return false
}

// ---- lossless-merge conflict tests ----------------------------------------
//
// Each reports whether two records that collide on their natural key DISAGREE on a
// non-empty field, so folding one away would lose data. When true, reconcile skips the
// merge and leaves both records for an operator-confirmed flow. A field only one side
// has set (the other empty) is NOT a conflict - it folds losslessly into the survivor.

// machinesConflict reports a real disagreement between two records for the same machine:
// a differing non-empty advertised address, port, OS, or version. LastSeen is excluded
// (it folds as a max, never a loss).
func machinesConflict(a, b *model.Machine) bool {
	return bothSetDiffer(a.TailscaleHost, b.TailscaleHost) ||
		(a.AgentPort != 0 && b.AgentPort != 0 && a.AgentPort != b.AgentPort) ||
		bothSetDiffer(string(a.OS), string(b.OS)) ||
		bothSetDiffer(a.Version, b.Version)
}

// keysConflict reports a real disagreement between two records for the same public key:
// a differing non-empty sealed private half, rotation status, owner, or key type. Any
// such field would be dropped by a fold, so its difference blocks the auto-merge and
// surfaces for operator resolution instead. The display NAME is deliberately excluded: the
// same public key adopted under two labels on two machines is one identity, so the names
// fold (survivor keeps its own) rather than blocking convergence with a cosmetic conflict.
func keysConflict(a, b *model.Key) bool {
	return bothSetDiffer(a.PrivSealed, b.PrivSealed) ||
		bothSetDiffer(string(a.Status), string(b.Status)) ||
		bothSetDiffer(a.OwnerUserID, b.OwnerUserID) ||
		bothSetDiffer(string(a.Type), string(b.Type))
}

// projectPathsConflict reports whether two same-named projects give the SAME machine a
// DIFFERENT path (a real disagreement). A path for a machine only one project lists is
// not a conflict - it is a pure addition, unioned losslessly.
func projectPathsConflict(a, b *model.Project) bool {
	byMachine := map[string]string{}
	for _, pp := range a.Paths {
		byMachine[pp.MachineID] = pp.Path
	}
	for _, pp := range b.Paths {
		if have, ok := byMachine[pp.MachineID]; ok && have != pp.Path {
			return true
		}
	}
	return false
}

// projectsConflict reports a real disagreement between two same-named projects: the same
// machine given a different path, or a different non-empty note. Either would be dropped
// by a fold, so it blocks the auto-merge and surfaces for resolution.
func projectsConflict(a, b *model.Project) bool {
	return projectPathsConflict(a, b) || bothSetDiffer(a.Note, b.Note)
}

// foldProjectFields folds a loser project into the survivor losslessly: it unions the
// paths for machines the survivor lacks and fills an empty note. Returns whether the
// survivor changed. A same-machine different path or a differing non-empty note was
// already blocked by projectsConflict.
func foldProjectFields(survivor, loser *model.Project) bool {
	changed := unionProjectPaths(survivor, loser)
	if survivor.Note == "" && loser.Note != "" {
		survivor.Note = loser.Note
		changed = true
	}
	return changed
}

// backupSettingsConflict reports a real disagreement between two per-machine backup
// records: a differing non-empty sealed password, schedule, destination list, or archive
// filename shape (base name, date format, date position). Any such field would be dropped
// by a fold, so its difference blocks the auto-merge and surfaces for resolution.
func backupSettingsConflict(a, b *model.BackupSettings) bool {
	return bothSetDiffer(a.PasswordSealed, b.PasswordSealed) ||
		bothSetDiffer(a.DailyAt, b.DailyAt) ||
		bothSetDiffer(a.BaseName, b.BaseName) ||
		bothSetDiffer(a.DateFormat, b.DateFormat) ||
		bothSetDiffer(a.DatePosition, b.DatePosition) ||
		(len(a.Destinations) > 0 && len(b.Destinations) > 0 && !reflect.DeepEqual(a.Destinations, b.Destinations))
}

// notificationSettingsConflict reports a real disagreement between two per-machine
// notification records: a differing non-empty sealed channel credential, or a per-event
// toggle both records set but to different values (a fold could not reconcile it without
// dropping one, so it surfaces for resolution).
func notificationSettingsConflict(a, b *model.NotificationSettings) bool {
	return bothSetDiffer(a.TelegramTokenSealed, b.TelegramTokenSealed) ||
		bothSetDiffer(a.SlackWebhookSealed, b.SlackWebhookSealed) ||
		eventsConflict(a.Events, b.Events)
}

// eventsConflict reports whether two per-event toggle maps disagree on a key both set.
func eventsConflict(a, b map[string]bool) bool {
	for k, av := range a {
		if bv, ok := b[k]; ok && av != bv {
			return true
		}
	}
	return false
}

// osUserConflict reports a real disagreement between two records for the same account
// on the same machine: a differing non-empty key-store base. It is the shared predicate
// the silent dedup skips on and the conflict detection surfaces, so the two always agree.
func osUserConflict(a, b *model.OSUser) bool {
	return bothSetDiffer(a.KeyBase, b.KeyBase)
}

// mapViewLayoutEqual reports whether two same-named views describe the IDENTICAL layout
// (same group-by ordering and leaf), so one is a true duplicate safe to drop. A
// differing layout is a distinct saved view and must be kept.
func mapViewLayoutEqual(a, b *model.MapView) bool {
	return a.Leaf == b.Leaf && reflect.DeepEqual(a.GroupBy, b.GroupBy)
}

// bothSetDiffer reports whether two strings are both non-empty and unequal - the shape
// of a lossy conflict (one side empty folds losslessly; equal values are not a loss).
func bothSetDiffer(a, b string) bool { return a != "" && b != "" && a != b }

// ---- small deterministic helpers ------------------------------------------

func smallestByUUID(list []*model.Machine) *model.Machine {
	out := list[0]
	for _, m := range list[1:] {
		if m.M.UUID < out.M.UUID {
			out = m
		}
	}
	return out
}

func smallestKeyByUUID(list []*model.Key) *model.Key {
	out := list[0]
	for _, m := range list[1:] {
		if m.M.UUID < out.M.UUID {
			out = m
		}
	}
	return out
}

func smallestProjectByUUID(list []*model.Project) *model.Project {
	out := list[0]
	for _, m := range list[1:] {
		if m.M.UUID < out.M.UUID {
			out = m
		}
	}
	return out
}

func smallestSetByUUID(list []*model.GlobalSet) *model.GlobalSet {
	out := list[0]
	for _, m := range list[1:] {
		if m.M.UUID < out.M.UUID {
			out = m
		}
	}
	return out
}

func smallestUserByUUID(list []*model.OSUser) *model.OSUser {
	out := list[0]
	for _, m := range list[1:] {
		if m.M.UUID < out.M.UUID {
			out = m
		}
	}
	return out
}

func smallestAsgByUUID(list []*model.Assignment) *model.Assignment {
	out := list[0]
	for _, m := range list[1:] {
		if m.M.UUID < out.M.UUID {
			out = m
		}
	}
	return out
}

// unionProjectPaths adds every path from src whose machine the survivor lacks.
// Returns whether the survivor changed.
func unionProjectPaths(survivor, src *model.Project) bool {
	have := map[string]bool{}
	for _, pp := range survivor.Paths {
		have[pp.MachineID] = true
	}
	changed := false
	for _, pp := range src.Paths {
		if !have[pp.MachineID] {
			survivor.Paths = append(survivor.Paths, pp)
			have[pp.MachineID] = true
			changed = true
		}
	}
	return changed
}

// unionRecipients folds ids into the set's recipient list without duplicates.
// Returns whether the set changed.
func unionRecipients(set *model.GlobalSet, ids []string) bool {
	have := map[string]bool{}
	for _, id := range set.RecipientUserIDs {
		have[id] = true
	}
	changed := false
	for _, id := range ids {
		if !have[id] {
			set.RecipientUserIDs = append(set.RecipientUserIDs, id)
			have[id] = true
			changed = true
		}
	}
	return changed
}

// replaceRecipient swaps oldID for newID in a set's recipient list (dropping a
// resulting duplicate). Returns whether the set changed.
func replaceRecipient(set *model.GlobalSet, oldID, newID string) bool {
	changed := false
	out := set.RecipientUserIDs[:0:0]
	seen := map[string]bool{}
	for _, id := range set.RecipientUserIDs {
		r := id
		if r == oldID {
			r = newID
			changed = true
		}
		if seen[r] {
			changed = true
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	if changed {
		set.RecipientUserIDs = out
	}
	return changed
}
