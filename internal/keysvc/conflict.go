package keysvc

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"sopshq/internal/audit"
	"sopshq/internal/model"
	"sopshq/internal/store"
)

// Conflict resolution: the operator-facing half of the rule that replication never loses data silently.
//
// The reconcile pass is LOSSLESS-ONLY: when two records share a natural key but a
// non-empty field genuinely differs, it SKIPS the merge and leaves BOTH records
// intact (see reconcile.go). This file finds those left-intact groups (DetectConflicts,
// read-only) and lets the operator resolve each one deliberately:
//
//   - ResolveMerge folds the group into ONE surviving record, applying the operator's
//     chosen winning value for every genuinely-differing field, unioning every
//     losslessly-mergeable field, re-pointing every reference, then tombstoning the
//     losers. It is the ONLY path that ever deletes a record here, and the web layer
//     gates it behind a two-step, explicitly-confirmed flow.
//   - KeepBothDistinct records a replicated DistinctAck ("these are different things"),
//     so DetectConflicts stops surfacing the group and both nodes converge on that
//     decision.
//
// Detection REUSES the exact *Conflict/bothSetDiffer/fold helpers the reconcile skip
// uses, and mirrors the same survivor-then-fold sequence on a CLONE of the survivor, so
// the set it reports is exactly the set the lossless pass leaves intact. It never writes.
//
// SECURITY: a sealed field (an age private key, a backup password, a channel token) is
// NEVER read out or displayed. A differing sealed field is surfaced by PRESENCE and
// PROVENANCE only ("sealed private key present, from <machine>"), and a merge copies the
// chosen ciphertext without ever unsealing it.

// Conflict entity-type keys. They are the stable ASCII identifier used in the URL, the
// form, and the audit target for a conflict group of that kind.
const (
	ConflictKey     = "key"
	ConflictProject = "project"
	ConflictOSUser  = "osuser"
	ConflictMachine = "machine"
	ConflictBackup  = "backup_settings"
	ConflictNotify  = "notification_settings"
	ConflictMapView = "map_view"
)

// ErrKeepBothInvalid means "keep both" was requested for an entity that can only ever
// have ONE record per natural key (the per-machine settings), where two records cannot
// both be valid - only a merge/pick resolves it.
var ErrKeepBothInvalid = errors.New("keysvc: these records cannot be kept as two - a machine has one such record; merge instead")

// ErrConflictGone means the records named for a resolution no longer form a live
// conflict group (already resolved, deleted, or never a real group), so the action is
// refused rather than applied to an unexpected set.
var ErrConflictGone = errors.New("keysvc: these records are no longer a conflict to resolve")

// ConflictFact is one NON-SECRET distinguishing fact about a record in a conflict group
// (a machine name, a path, "sealed password present"), shown so the operator can tell the
// records apart. Differs marks a fact that is one of the genuinely-differing fields.
type ConflictFact struct {
	Label   string
	Value   string
	Differs bool
}

// ConflictRecord is one record inside a conflict group, described only by non-secret
// facts. Survivor marks the record that a merge keeps (its id is referenced elsewhere).
type ConflictRecord struct {
	UUID     string
	Summary  string // a short human title (e.g. the project name, "alice on linux-server")
	Survivor bool
	Facts    []ConflictFact
}

// ConflictOption is one choosable winning value for a differing field: the value from
// one record in the group. Display is the NON-SECRET rendering (or provenance for a
// sealed value). RecordID is the record whose value the merge copies if this is picked.
type ConflictOption struct {
	RecordID string
	Display  string
}

// ConflictField is one genuinely-differing field the operator must pick a winner for
// when merging. Key is the stable form field name; Secret hides the value itself.
type ConflictField struct {
	Key     string
	Label   string
	Secret  bool
	Options []ConflictOption
}

// ConflictGroup is one natural-key group the lossless pass left intact: two or more live
// records that share the key but disagree on a non-empty field. It is everything the UI
// needs to explain and resolve the conflict without revealing any secret.
type ConflictGroup struct {
	EntityType string
	ID         string // entityType + sorted record UUIDs; the stable route/anchor id
	KeyLabel   string // human natural-key label ("public key age1abc...", "project \"app\"")
	Records    []ConflictRecord
	SurvivorID string
	Fields     []ConflictField
	KeepBothOK bool // whether "keep both (they are distinct)" is a valid resolution
}

// RecordIDs returns the group's member UUIDs (sorted), for the resolution form.
func (g ConflictGroup) RecordIDs() []string {
	out := make([]string, 0, len(g.Records))
	for _, r := range g.Records {
		out = append(out, r.UUID)
	}
	return out
}

// DetectConflicts returns every conflict group the lossless reconcile pass leaves
// intact, across all entity kinds. It is READ-ONLY: it writes nothing to the store. A
// group already acknowledged "keep both" (a covering DistinctAck) is suppressed.
func (s *Service) DetectConflicts() []ConflictGroup {
	var out []ConflictGroup
	out = append(out, s.detectKeys()...)
	out = append(out, s.detectProjects()...)
	out = append(out, s.detectOSUsers()...)
	out = append(out, s.detectMachines()...)
	out = append(out, s.detectBackup()...)
	out = append(out, s.detectNotify()...)
	out = append(out, s.detectMapViews()...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].EntityType != out[j].EntityType {
			return out[i].EntityType < out[j].EntityType
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// ConflictCount is the number of conflict groups awaiting resolution (drives the
// dashboard alert). It is a thin read-only wrapper over DetectConflicts.
func (s *Service) ConflictCount() int { return len(s.DetectConflicts()) }

// ConflictGroupByIDs returns the CURRENT conflict group whose members are exactly the
// named record ids (of the given entity type), recomputed fresh. It returns false when
// the group no longer exists as reported - already resolved, or changed shape (e.g. a
// third record appeared) - so the resolution flow re-reviews instead of acting on stale
// data.
func (s *Service) ConflictGroupByIDs(entityType string, ids []string) (ConflictGroup, bool) {
	want := groupID(entityType, ids)
	for _, g := range s.DetectConflicts() {
		if g.ID == want {
			return g, true
		}
	}
	return ConflictGroup{}, false
}

// ---- detection scaffolding ------------------------------------------------

// simulateRemaining mirrors the reconcile skip exactly: it sorts a natural-key group by
// less (survivor first), then walks the rest, keeping every record that CONFLICTS with
// the accumulating survivor and folding every non-conflicting one INTO a clone of the
// survivor (so a field a later record only fills was empty). What it returns - the
// survivor plus every record the pass would skip - is precisely the set left intact.
func simulateRemaining[T model.Record](grp []T, less func(a, b T) bool, conflict func(a, b T) bool, clone func(T) T, fold func(sv, l T)) []T {
	sorted := append([]T(nil), grp...)
	sort.SliceStable(sorted, func(i, j int) bool { return less(sorted[i], sorted[j]) })
	sv := clone(sorted[0])
	remaining := []T{sorted[0]}
	for _, r := range sorted[1:] {
		if conflict(sv, r) {
			remaining = append(remaining, r)
		} else {
			fold(sv, r)
		}
	}
	return remaining
}

// groupBy buckets records by a natural-key function (empty key = skip), preserving a
// deterministic key order for stable output.
func groupBy[T model.Record](recs []T, keyFn func(T) string) (map[string][]T, []string) {
	groups := map[string][]T{}
	var order []string
	for _, r := range recs {
		k := keyFn(r)
		if k == "" {
			continue
		}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r)
	}
	sort.Strings(order)
	return groups, order
}

// groupID builds the stable id/anchor for a group from its entity type and member ids.
func groupID(entityType string, ids []string) string {
	s := append([]string(nil), ids...)
	sort.Strings(s)
	return entityType + ":" + strings.Join(s, ",")
}

// groupAcked reports whether a live DistinctAck of this entity type COVERS every member
// of the group (a superset), i.e. the operator already said "keep these apart".
func (s *Service) groupAcked(entityType string, memberIDs []string) bool {
	for _, ack := range s.store.DistinctAcks.List() {
		if ack.EntityType != entityType {
			continue
		}
		have := map[string]bool{}
		for _, id := range ack.RecordIDs {
			have[id] = true
		}
		covered := true
		for _, id := range memberIDs {
			if !have[id] {
				covered = false
				break
			}
		}
		if covered {
			return true
		}
	}
	return false
}

// byUUID is the default survivor order for the non-machine kinds: smallest UUID first,
// matching every dedup* survivor choice so detection and the pass agree.
func byUUID[T model.Record](a, b T) bool { return a.Meta().UUID < b.Meta().UUID }

// ---- provenance helpers (non-secret) --------------------------------------

// machineName returns a machine's display name (live or tombstoned), or the id if
// unknown, for non-secret provenance facts.
func (s *Service) machineName(id string) string {
	if id == "" {
		return ""
	}
	if mc, ok := s.store.Machines.GetRaw(id); ok && mc.Name != "" {
		return mc.Name
	}
	return id
}

// osUserName returns an OS user's "username on machine" label for provenance.
func (s *Service) osUserName(id string) string {
	if id == "" {
		return ""
	}
	if u, ok := s.store.OSUsers.GetRaw(id); ok {
		if n := s.machineName(u.MachineID); n != "" {
			return u.Username + " on " + n
		}
		return u.Username
	}
	return id
}

// originFact renders a record's replication provenance (origin node + last-updated time)
// as a non-secret fact for telling near-identical records apart.
func (s *Service) originFact(m *model.Meta) ConflictFact {
	origin := m.Origin
	if n := s.machineName(origin); n != "" {
		origin = n
	}
	when := "-"
	if m.Updated.Wall > 0 {
		when = time.UnixMilli(m.Updated.Wall).Format("2006-01-02 15:04")
	}
	return ConflictFact{Label: "origin / last change", Value: origin + " (" + when + ")"}
}

// yesNo renders a boolean presence fact without revealing any value.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// ---- keys -----------------------------------------------------------------

func (s *Service) detectKeys() []ConflictGroup {
	groups, order := groupBy(s.store.Keys.List(), func(k *model.Key) string { return k.Recipient })
	var out []ConflictGroup
	for _, key := range order {
		grp := groups[key]
		if len(grp) < 2 {
			continue
		}
		rem := simulateRemaining(grp, byUUID[*model.Key], keysConflict,
			func(k *model.Key) *model.Key { c := *k; return &c },
			func(sv, l *model.Key) { foldKeyFields(sv, l) })
		if len(rem) < 2 {
			continue
		}
		ids := metaIDs(rem)
		if s.groupAcked(ConflictKey, ids) {
			continue
		}
		survivor := rem[0]
		g := ConflictGroup{
			EntityType: ConflictKey,
			ID:         groupID(ConflictKey, ids),
			KeyLabel:   "public key " + shortRec(key),
			SurvivorID: survivor.M.UUID,
			KeepBothOK: true,
		}
		diffPriv := manyDiffer(rem, func(k *model.Key) string { return k.PrivSealed })
		diffStatus := manyDiffer(rem, func(k *model.Key) string { return string(k.Status) })
		diffOwner := manyDiffer(rem, func(k *model.Key) string { return k.OwnerUserID })
		diffType := manyDiffer(rem, func(k *model.Key) string { return string(k.Type) })
		for _, k := range rem {
			g.Records = append(g.Records, ConflictRecord{
				UUID:     k.M.UUID,
				Summary:  k.Name,
				Survivor: k.M.UUID == survivor.M.UUID,
				Facts: []ConflictFact{
					{Label: "name", Value: k.Name},
					{Label: "type", Value: string(k.Type), Differs: diffType},
					{Label: "sealed private key present", Value: yesNo(k.PrivSealed != ""), Differs: diffPriv},
					{Label: "rotation status", Value: string(k.Status), Differs: diffStatus},
					{Label: "owner account", Value: s.osUserName(k.OwnerUserID), Differs: diffOwner},
					{Label: "created", Value: fmtUnix(k.CreatedAt)},
					s.originFact(&k.M),
				},
			})
		}
		if diffPriv {
			g.Fields = append(g.Fields, secretField("priv", "private key material", rem, func(k *model.Key) bool { return k.PrivSealed != "" }, func(k *model.Key) string { return "sealed private key from " + s.recProv(&k.M) }))
		}
		if diffType {
			g.Fields = append(g.Fields, plainField("type", "key type", rem, func(k *model.Key) string { return string(k.Type) }))
		}
		if diffStatus {
			g.Fields = append(g.Fields, plainField("status", "rotation status", rem, func(k *model.Key) string { return string(k.Status) }))
		}
		if diffOwner {
			g.Fields = append(g.Fields, plainFieldDisplay("owner", "owner account", rem, func(k *model.Key) string { return k.OwnerUserID }, func(k *model.Key) string { return s.osUserName(k.OwnerUserID) }))
		}
		out = append(out, g)
	}
	return out
}

// ---- projects -------------------------------------------------------------

func (s *Service) detectProjects() []ConflictGroup {
	groups, order := groupBy(s.store.Projects.List(), func(p *model.Project) string {
		return strings.ToLower(strings.TrimSpace(p.Name))
	})
	var out []ConflictGroup
	for _, key := range order {
		grp := groups[key]
		if len(grp) < 2 {
			continue
		}
		rem := simulateRemaining(grp, byUUID[*model.Project], projectsConflict,
			cloneProject, func(sv, l *model.Project) { foldProjectFields(sv, l) })
		if len(rem) < 2 {
			continue
		}
		ids := metaIDs(rem)
		if s.groupAcked(ConflictProject, ids) {
			continue
		}
		survivor := rem[0]
		g := ConflictGroup{
			EntityType: ConflictProject,
			ID:         groupID(ConflictProject, ids),
			KeyLabel:   "project " + strconv.Quote(survivor.Name),
			SurvivorID: survivor.M.UUID,
			KeepBothOK: true,
		}
		// The differing fields are per-machine paths (a machine two records both list but at
		// a DIFFERENT path) and a differing non-empty note.
		machinesInConflict := projectConflictMachines(rem)
		diffNote := manyDiffer(rem, func(p *model.Project) string { return p.Note })
		for _, p := range rem {
			facts := []ConflictFact{{Label: "name", Value: p.Name}}
			for _, pp := range p.Paths {
				facts = append(facts, ConflictFact{
					Label:   "path on " + s.machineName(pp.MachineID),
					Value:   pp.Path,
					Differs: machinesInConflict[pp.MachineID],
				})
			}
			facts = append(facts, ConflictFact{Label: "note", Value: p.Note, Differs: diffNote})
			facts = append(facts, s.originFact(&p.M))
			g.Records = append(g.Records, ConflictRecord{UUID: p.M.UUID, Summary: p.Name, Survivor: p.M.UUID == survivor.M.UUID, Facts: facts})
		}
		if diffNote {
			g.Fields = append(g.Fields, plainField("note", "note", rem, func(p *model.Project) string { return p.Note }))
		}
		var mids []string
		for mid := range machinesInConflict {
			mids = append(mids, mid)
		}
		sort.Strings(mids)
		for _, mid := range mids {
			f := ConflictField{Key: "path_" + mid, Label: "path on " + s.machineName(mid)}
			seen := map[string]bool{}
			for _, p := range rem {
				for _, pp := range p.Paths {
					if pp.MachineID == mid && pp.Path != "" && !seen[pp.Path] {
						seen[pp.Path] = true
						f.Options = append(f.Options, ConflictOption{RecordID: p.M.UUID, Display: pp.Path})
					}
				}
			}
			g.Fields = append(g.Fields, f)
		}
		out = append(out, g)
	}
	return out
}

// ---- OS users -------------------------------------------------------------

func (s *Service) detectOSUsers() []ConflictGroup {
	groups, order := groupBy(s.store.OSUsers.List(), func(u *model.OSUser) string {
		if u.MachineID == "" || u.Username == "" {
			return ""
		}
		name := u.Username
		if s.machineIsWindows(u.MachineID) {
			name = strings.ToLower(name)
		}
		return u.MachineID + "\x00" + name
	})
	var out []ConflictGroup
	for _, key := range order {
		grp := groups[key]
		if len(grp) < 2 {
			continue
		}
		rem := simulateRemaining(grp, byUUID[*model.OSUser], osUserConflict,
			func(u *model.OSUser) *model.OSUser { c := *u; return &c },
			func(sv, l *model.OSUser) {
				if sv.KeyBase == "" {
					sv.KeyBase = l.KeyBase
				}
			})
		if len(rem) < 2 {
			continue
		}
		ids := metaIDs(rem)
		if s.groupAcked(ConflictOSUser, ids) {
			continue
		}
		survivor := rem[0]
		g := ConflictGroup{
			EntityType: ConflictOSUser,
			ID:         groupID(ConflictOSUser, ids),
			KeyLabel:   "account " + strconv.Quote(survivor.Username) + " on " + s.machineName(survivor.MachineID),
			SurvivorID: survivor.M.UUID,
			KeepBothOK: true,
		}
		for _, u := range rem {
			g.Records = append(g.Records, ConflictRecord{
				UUID:     u.M.UUID,
				Summary:  s.osUserName(u.M.UUID),
				Survivor: u.M.UUID == survivor.M.UUID,
				Facts: []ConflictFact{
					{Label: "username", Value: u.Username},
					{Label: "machine", Value: s.machineName(u.MachineID)},
					{Label: "keystore path", Value: u.KeyBase, Differs: true},
					s.originFact(&u.M),
				},
			})
		}
		g.Fields = append(g.Fields, plainField("keybase", "keystore path", rem, func(u *model.OSUser) string { return u.KeyBase }))
		out = append(out, g)
	}
	return out
}

// ---- machines -------------------------------------------------------------

func (s *Service) detectMachines() []ConflictGroup {
	groups, order := groupBy(s.store.Machines.List(), func(mc *model.Machine) string {
		return strings.ToLower(strings.TrimSpace(mc.Name))
	})
	var out []ConflictGroup
	for _, key := range order {
		grp := groups[key]
		if len(grp) < 2 {
			continue
		}
		// A machine still awaiting the new-vs-reinstall decision is owned by that flow on
		// the Machines page - never double-surface it here.
		pending := false
		for _, mc := range grp {
			if mc.Pending {
				pending = true
				break
			}
		}
		if pending {
			continue
		}
		// Two or more CANONICAL same-name records never auto-merge (dedupMachinesByName
		// leaves the whole group intact for the operator - the reinstall/rename ambiguity),
		// so surface the whole group even when no single field differs. Otherwise mirror the
		// lossless skip: survivor plus every record that conflicts on a field.
		canon := 0
		for _, mc := range grp {
			if mc.Canonical {
				canon++
			}
		}
		var rem []*model.Machine
		if canon >= 2 {
			rem = append([]*model.Machine(nil), grp...)
			sort.SliceStable(rem, func(i, j int) bool { return machineLess(rem[i], rem[j]) })
		} else {
			rem = simulateRemaining(grp, machineLess, machinesConflict,
				func(mc *model.Machine) *model.Machine { c := *mc; return &c }, foldMachineFields)
		}
		if len(rem) < 2 {
			continue
		}
		ids := metaIDs(rem)
		if s.groupAcked(ConflictMachine, ids) {
			continue
		}
		survivor := rem[0]
		g := ConflictGroup{
			EntityType: ConflictMachine,
			ID:         groupID(ConflictMachine, ids),
			KeyLabel:   "machine " + strconv.Quote(survivor.Name),
			SurvivorID: survivor.M.UUID,
			KeepBothOK: true,
		}
		diffHost := manyDiffer(rem, func(mc *model.Machine) string { return mc.TailscaleHost })
		diffPort := manyDiffer(rem, func(mc *model.Machine) string { return portStr(mc.AgentPort) })
		diffOS := manyDiffer(rem, func(mc *model.Machine) string { return string(mc.OS) })
		diffVer := manyDiffer(rem, func(mc *model.Machine) string { return mc.Version })
		for _, mc := range rem {
			g.Records = append(g.Records, ConflictRecord{
				UUID:     mc.M.UUID,
				Summary:  mc.Name,
				Survivor: mc.M.UUID == survivor.M.UUID,
				Facts: []ConflictFact{
					{Label: "advertised address", Value: mc.TailscaleHost, Differs: diffHost},
					{Label: "agent port", Value: portStr(mc.AgentPort), Differs: diffPort},
					{Label: "operating system", Value: string(mc.OS), Differs: diffOS},
					{Label: "reported version", Value: mc.Version, Differs: diffVer},
					{Label: "this node's own record", Value: yesNo(mc.Canonical)},
					s.originFact(&mc.M),
				},
			})
		}
		if diffHost {
			g.Fields = append(g.Fields, plainField("host", "advertised address", rem, func(mc *model.Machine) string { return mc.TailscaleHost }))
		}
		if diffPort {
			g.Fields = append(g.Fields, plainField("port", "agent port", rem, func(mc *model.Machine) string { return portStr(mc.AgentPort) }))
		}
		if diffOS {
			g.Fields = append(g.Fields, plainField("os", "operating system", rem, func(mc *model.Machine) string { return string(mc.OS) }))
		}
		if diffVer {
			g.Fields = append(g.Fields, plainField("version", "reported version", rem, func(mc *model.Machine) string { return mc.Version }))
		}
		out = append(out, g)
	}
	return out
}

// ---- backup settings (merge-only) -----------------------------------------

func (s *Service) detectBackup() []ConflictGroup {
	groups, order := groupBy(s.store.BackupSettingsColl.List(), func(b *model.BackupSettings) string { return b.MachineID })
	var out []ConflictGroup
	for _, key := range order {
		grp := groups[key]
		if len(grp) < 2 {
			continue
		}
		rem := simulateRemaining(grp, byUUID[*model.BackupSettings], backupSettingsConflict,
			cloneBackup, func(sv, l *model.BackupSettings) { foldBackupFields(sv, l) })
		if len(rem) < 2 {
			continue
		}
		ids := metaIDs(rem)
		// Per-machine settings are merge-only, so a DistinctAck can never suppress them.
		survivor := rem[0]
		g := ConflictGroup{
			EntityType: ConflictBackup,
			ID:         groupID(ConflictBackup, ids),
			KeyLabel:   "backup settings for " + s.machineName(key),
			SurvivorID: survivor.M.UUID,
			KeepBothOK: false,
		}
		diffPass := manyDiffer(rem, func(b *model.BackupSettings) string { return b.PasswordSealed })
		diffTime := manyDiffer(rem, func(b *model.BackupSettings) string { return b.DailyAt })
		diffDest := manyDiffer(rem, func(b *model.BackupSettings) string { return destSummary(b.Destinations) })
		diffBase := manyDiffer(rem, func(b *model.BackupSettings) string { return b.BaseName })
		diffFmt := manyDiffer(rem, func(b *model.BackupSettings) string { return b.DateFormat })
		diffPos := manyDiffer(rem, func(b *model.BackupSettings) string { return b.DatePosition })
		for _, b := range rem {
			g.Records = append(g.Records, ConflictRecord{
				UUID:     b.M.UUID,
				Summary:  "backup on " + s.machineName(b.MachineID),
				Survivor: b.M.UUID == survivor.M.UUID,
				Facts: []ConflictFact{
					{Label: "enabled", Value: yesNo(b.Enabled)},
					{Label: "daily run time", Value: b.DailyAt, Differs: diffTime},
					{Label: "sealed password present", Value: yesNo(b.PasswordSealed != ""), Differs: diffPass},
					{Label: "destinations", Value: destSummary(b.Destinations), Differs: diffDest},
					{Label: "archive base name", Value: b.BaseName, Differs: diffBase},
					{Label: "date format", Value: b.DateFormat, Differs: diffFmt},
					{Label: "date position", Value: b.DatePosition, Differs: diffPos},
					s.originFact(&b.M),
				},
			})
		}
		if diffPass {
			g.Fields = append(g.Fields, secretField("password", "backup password", rem, func(b *model.BackupSettings) bool { return b.PasswordSealed != "" }, func(b *model.BackupSettings) string { return "sealed password from " + s.recProv(&b.M) }))
		}
		if diffTime {
			g.Fields = append(g.Fields, plainField("dailyat", "daily run time", rem, func(b *model.BackupSettings) string { return b.DailyAt }))
		}
		if diffDest {
			g.Fields = append(g.Fields, plainField("destinations", "backup destinations", rem, func(b *model.BackupSettings) string { return destSummary(b.Destinations) }))
		}
		if diffBase {
			g.Fields = append(g.Fields, plainField("basename", "archive base name", rem, func(b *model.BackupSettings) string { return b.BaseName }))
		}
		if diffFmt {
			g.Fields = append(g.Fields, plainField("dateformat", "date format", rem, func(b *model.BackupSettings) string { return b.DateFormat }))
		}
		if diffPos {
			g.Fields = append(g.Fields, plainField("dateposition", "date position", rem, func(b *model.BackupSettings) string { return b.DatePosition }))
		}
		out = append(out, g)
	}
	return out
}

// ---- notification settings (merge-only) -----------------------------------

func (s *Service) detectNotify() []ConflictGroup {
	groups, order := groupBy(s.store.NotificationSettingsColl.List(), func(n *model.NotificationSettings) string { return n.MachineID })
	var out []ConflictGroup
	for _, key := range order {
		grp := groups[key]
		if len(grp) < 2 {
			continue
		}
		rem := simulateRemaining(grp, byUUID[*model.NotificationSettings], notificationSettingsConflict,
			cloneNotify, func(sv, l *model.NotificationSettings) { foldNotificationFields(sv, l) })
		if len(rem) < 2 {
			continue
		}
		ids := metaIDs(rem)
		survivor := rem[0]
		g := ConflictGroup{
			EntityType: ConflictNotify,
			ID:         groupID(ConflictNotify, ids),
			KeyLabel:   "notification settings for " + s.machineName(key),
			SurvivorID: survivor.M.UUID,
			KeepBothOK: false,
		}
		diffTg := manyDiffer(rem, func(n *model.NotificationSettings) string { return n.TelegramTokenSealed })
		diffSl := manyDiffer(rem, func(n *model.NotificationSettings) string { return n.SlackWebhookSealed })
		diffEvents := notifyEventsDiffer(rem)
		for _, n := range rem {
			g.Records = append(g.Records, ConflictRecord{
				UUID:     n.M.UUID,
				Summary:  "notifications on " + s.machineName(n.MachineID),
				Survivor: n.M.UUID == survivor.M.UUID,
				Facts: []ConflictFact{
					{Label: "enabled", Value: yesNo(n.Enabled)},
					{Label: "telegram channel set", Value: yesNo(n.TelegramTokenSealed != ""), Differs: diffTg},
					{Label: "slack channel set", Value: yesNo(n.SlackWebhookSealed != ""), Differs: diffSl},
					{Label: "alert-on events", Value: eventsSummary(n.Events), Differs: diffEvents},
					s.originFact(&n.M),
				},
			})
		}
		if diffEvents {
			g.Fields = append(g.Fields, plainFieldDisplay("events", "alert-on events", rem,
				func(n *model.NotificationSettings) string { return eventsSummary(n.Events) },
				func(n *model.NotificationSettings) string { return eventsSummary(n.Events) }))
		}
		if diffTg {
			g.Fields = append(g.Fields, secretField("telegram", "telegram channel", rem, func(n *model.NotificationSettings) bool { return n.TelegramTokenSealed != "" }, func(n *model.NotificationSettings) string {
				p := "sealed telegram token from " + s.recProv(&n.M)
				if n.TelegramChatID != "" {
					p += " (chat " + n.TelegramChatID + ")"
				}
				return p
			}))
		}
		if diffSl {
			g.Fields = append(g.Fields, secretField("slack", "slack channel", rem, func(n *model.NotificationSettings) bool { return n.SlackWebhookSealed != "" }, func(n *model.NotificationSettings) string { return "sealed slack webhook from " + s.recProv(&n.M) }))
		}
		out = append(out, g)
	}
	return out
}

// ---- map views ------------------------------------------------------------

func (s *Service) detectMapViews() []ConflictGroup {
	groups, order := groupBy(s.store.MapViews.List(), func(v *model.MapView) string {
		return strings.ToLower(strings.TrimSpace(v.Name))
	})
	var out []ConflictGroup
	for _, key := range order {
		grp := groups[key]
		if len(grp) < 2 {
			continue
		}
		// The map-view "conflict" is a DIFFERING layout (identical-layout duplicates fold
		// losslessly). There is nothing to fold, so the remaining set is the survivor plus
		// every view whose layout differs from it.
		rem := simulateRemaining(grp, byUUID[*model.MapView],
			func(a, b *model.MapView) bool { return !mapViewLayoutEqual(a, b) },
			func(v *model.MapView) *model.MapView { c := *v; return &c },
			func(sv, l *model.MapView) {})
		if len(rem) < 2 {
			continue
		}
		ids := metaIDs(rem)
		if s.groupAcked(ConflictMapView, ids) {
			continue
		}
		survivor := rem[0]
		g := ConflictGroup{
			EntityType: ConflictMapView,
			ID:         groupID(ConflictMapView, ids),
			KeyLabel:   "map view " + strconv.Quote(survivor.Name),
			SurvivorID: survivor.M.UUID,
			KeepBothOK: true,
		}
		for _, v := range rem {
			g.Records = append(g.Records, ConflictRecord{
				UUID:     v.M.UUID,
				Summary:  v.Name,
				Survivor: v.M.UUID == survivor.M.UUID,
				Facts: []ConflictFact{
					{Label: "tree layout", Value: layoutSummary(v), Differs: true},
					s.originFact(&v.M),
				},
			})
		}
		g.Fields = append(g.Fields, plainField("layout", "tree layout", rem, layoutSummary))
		out = append(out, g)
	}
	return out
}

// ---- field/option builders ------------------------------------------------

// plainField builds a pick-a-winner field whose values are shown as-is.
func plainField[T model.Record](key, label string, recs []T, valueOf func(T) string) ConflictField {
	return plainFieldDisplay(key, label, recs, valueOf, valueOf)
}

// plainFieldDisplay builds a pick field where the option's DISPLAY differs from the raw
// value used for de-duplicating identical options (e.g. an id shown as a name).
func plainFieldDisplay[T model.Record](key, label string, recs []T, valueOf func(T) string, displayOf func(T) string) ConflictField {
	f := ConflictField{Key: key, Label: label}
	seen := map[string]bool{}
	for _, r := range recs {
		v := valueOf(r)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		f.Options = append(f.Options, ConflictOption{RecordID: r.Meta().UUID, Display: displayOf(r)})
	}
	return f
}

// secretField builds a pick field for a SEALED value: the value itself is never shown,
// only provenance, and Secret is set so the template renders no value.
func secretField[T model.Record](key, label string, recs []T, present func(T) bool, prov func(T) string) ConflictField {
	f := ConflictField{Key: key, Label: label, Secret: true}
	for _, r := range recs {
		if !present(r) {
			continue
		}
		f.Options = append(f.Options, ConflictOption{RecordID: r.Meta().UUID, Display: prov(r)})
	}
	return f
}

// manyDiffer reports whether two or more records in the set hold non-empty, unequal
// values for a field - the "genuinely differs" test, matching bothSetDiffer's shape.
func manyDiffer[T model.Record](recs []T, valueOf func(T) string) bool {
	var first string
	have := false
	for _, r := range recs {
		v := valueOf(r)
		if v == "" {
			continue
		}
		if !have {
			first, have = v, true
			continue
		}
		if v != first {
			return true
		}
	}
	return false
}

// metaIDs returns the sorted UUIDs of a record set.
func metaIDs[T model.Record](recs []T) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.Meta().UUID)
	}
	sort.Strings(out)
	return out
}

// recProv is a compact non-secret provenance string (origin + last change) for a record.
func (s *Service) recProv(m *model.Meta) string {
	origin := m.Origin
	if n := s.machineName(origin); n != "" {
		origin = n
	}
	if m.Updated.Wall > 0 {
		return origin + " (" + time.UnixMilli(m.Updated.Wall).Format("2006-01-02 15:04") + ")"
	}
	return origin
}

// ---- machine survivor + fold helpers --------------------------------------

// machineLess ranks a group's machine records: the single canonical (this node's own
// self-record) survives, otherwise the smallest UUID. It matches dedupMachinesByName's
// survivor choice, so the record detection marks "kept" is the one a merge keeps.
func machineLess(a, b *model.Machine) bool {
	if a.Canonical != b.Canonical {
		return a.Canonical
	}
	return a.M.UUID < b.M.UUID
}

// foldMachineFields fills a machine survivor's EMPTY fields from a loser (advertised
// address, port, OS, version, last-seen), mirroring mergeMachine's lossless fill so the
// accumulate-then-recheck in simulateRemaining matches the pass.
func foldMachineFields(sv, l *model.Machine) {
	if sv.TailscaleHost == "" && l.TailscaleHost != "" {
		sv.TailscaleHost = l.TailscaleHost
		if sv.AgentPort == 0 {
			sv.AgentPort = l.AgentPort
		}
	}
	if sv.AgentPort == 0 && l.AgentPort != 0 {
		sv.AgentPort = l.AgentPort
	}
	if sv.OS == "" && l.OS != "" {
		sv.OS = l.OS
	}
	if sv.Version == "" && l.Version != "" {
		sv.Version = l.Version
	}
	if l.LastSeen > sv.LastSeen {
		sv.LastSeen = l.LastSeen
	}
}

// cloneProject / cloneBackup / cloneNotify deep-copy the slice fields a fold mutates, so
// the read-only simulation never touches a stored record's backing arrays.
func cloneProject(p *model.Project) *model.Project {
	c := *p
	c.Paths = append([]model.ProjectPath(nil), p.Paths...)
	return &c
}

func cloneBackup(b *model.BackupSettings) *model.BackupSettings {
	c := *b
	c.Destinations = append([]model.BackupDest(nil), b.Destinations...)
	return &c
}

func cloneNotify(n *model.NotificationSettings) *model.NotificationSettings {
	c := *n
	if n.Events != nil {
		c.Events = make(map[string]bool, len(n.Events))
		for k, v := range n.Events {
			c.Events[k] = v
		}
	}
	return &c
}

// projectConflictMachines returns the set of machine ids on which two or more of the
// records list a DIFFERENT path (the genuinely-differing per-machine paths).
func projectConflictMachines(recs []*model.Project) map[string]bool {
	firstPath := map[string]string{}
	conflict := map[string]bool{}
	for _, p := range recs {
		for _, pp := range p.Paths {
			if have, ok := firstPath[pp.MachineID]; ok {
				if have != pp.Path {
					conflict[pp.MachineID] = true
				}
			} else {
				firstPath[pp.MachineID] = pp.Path
			}
		}
	}
	return conflict
}

// ---- small formatters -----------------------------------------------------

func shortRec(rec string) string {
	if len(rec) > 20 {
		return rec[:14] + "..." + rec[len(rec)-4:]
	}
	return rec
}

func portStr(p int) string {
	if p == 0 {
		return ""
	}
	return strconv.Itoa(p)
}

func fmtUnix(sec int64) string {
	if sec == 0 {
		return "-"
	}
	return time.Unix(sec, 0).Format("2006-01-02 15:04")
}

// destSummary is a non-secret one-line summary of a backup destination list: how many
// and of which kinds (local/ftp/telegram). It never includes a host, folder, or credential.
func destSummary(dests []model.BackupDest) string {
	if len(dests) == 0 {
		return "none"
	}
	kinds := map[string]int{}
	for _, d := range dests {
		kinds[d.Type]++
	}
	var parts []string
	for _, k := range []string{"local", "ftp", "telegram"} {
		if kinds[k] > 0 {
			parts = append(parts, strconv.Itoa(kinds[k])+" "+k)
		}
	}
	return strconv.Itoa(len(dests)) + " destination(s): " + strings.Join(parts, ", ")
}

// notifyEventsDiffer reports whether any two records disagree on a shared per-event
// toggle (the surface-worthy Events conflict). A toggle only one record carries is not a
// conflict - it folds losslessly by union.
func notifyEventsDiffer(recs []*model.NotificationSettings) bool {
	for i := 0; i < len(recs); i++ {
		for j := i + 1; j < len(recs); j++ {
			if eventsConflict(recs[i].Events, recs[j].Events) {
				return true
			}
		}
	}
	return false
}

// eventsSummary renders which events are turned ON as a sorted, non-secret list.
func eventsSummary(ev map[string]bool) string {
	if len(ev) == 0 {
		return "(default)"
	}
	var on []string
	for k, v := range ev {
		if v {
			on = append(on, k)
		}
	}
	sort.Strings(on)
	if len(on) == 0 {
		return "(none on)"
	}
	return strings.Join(on, ", ")
}

// layoutSummary renders a map view's group-by ordering and leaf as a non-secret string.
func layoutSummary(v *model.MapView) string {
	order := strings.Join(v.GroupBy, " > ")
	if order == "" {
		order = "(none)"
	}
	return "group by " + order + ", leaf " + v.Leaf
}

// ---- resolution: merge ----------------------------------------------------

// ResolveMerge folds a conflict group into ONE surviving record. recordIDs name the
// group (the same set DetectConflicts reported); picks maps a differing field's key to
// the record UUID whose value should win. It re-points every reference to the survivor,
// unions every losslessly-mergeable field, applies the picked winners, then tombstones
// the losers. It refuses (ErrConflictGone) if the ids do not still form a live group
// sharing one natural key, so a stale or crafted request can never merge unrelated
// records.
//
// It is the ONLY delete path in conflict resolution; the web layer calls it only after
// the operator's second, explicit confirmation.
func (s *Service) ResolveMerge(entityType string, recordIDs []string, picks map[string]string, actor string) error {
	switch entityType {
	case ConflictKey:
		return s.mergeKeys(recordIDs, picks, actor)
	case ConflictProject:
		return s.mergeProjects(recordIDs, picks, actor)
	case ConflictOSUser:
		return s.mergeOSUsers(recordIDs, picks, actor)
	case ConflictMachine:
		return s.mergeMachines(recordIDs, picks, actor)
	case ConflictBackup:
		return s.mergeBackup(recordIDs, picks, actor)
	case ConflictNotify:
		return s.mergeNotify(recordIDs, picks, actor)
	case ConflictMapView:
		return s.mergeMapViews(recordIDs, picks, actor)
	default:
		return fmt.Errorf("keysvc: unknown conflict entity %q", entityType)
	}
}

// loadLive returns the named records that are still live, refusing with
// ErrConflictGone unless at least two remain. Callers check the shared natural key.
func loadLive[T model.Record](c *store.Collection[T], ids []string) ([]T, error) {
	var out []T
	for _, id := range ids {
		if rec, err := c.Get(id); err == nil {
			out = append(out, rec)
		}
	}
	if len(out) < 2 {
		return nil, ErrConflictGone
	}
	return out, nil
}

func (s *Service) mergeKeys(ids []string, picks map[string]string, actor string) error {
	recs, err := loadLive(s.store.Keys, ids)
	if err != nil {
		return err
	}
	// All records must still share one public key (the natural key), or this is not the
	// group DetectConflicts reported.
	for _, k := range recs {
		if k.Recipient == "" || k.Recipient != recs[0].Recipient {
			return ErrConflictGone
		}
	}
	sort.SliceStable(recs, func(i, j int) bool { return byUUID(recs[i], recs[j]) })
	survivor := recs[0]
	byID := map[string]*model.Key{}
	for _, k := range recs {
		byID[k.M.UUID] = k
	}
	// Re-point every assignment off a loser onto the survivor, then fold empty fields.
	for _, loser := range recs[1:] {
		for _, a := range s.store.Assignments.List() {
			if a.KeyID == loser.M.UUID {
				a.KeyID = survivor.M.UUID
				_ = s.store.Assignments.Put(a)
			}
		}
		foldKeyFields(survivor, loser)
	}
	// Apply the operator's picks (override the differing fields).
	if src := byID[picks["priv"]]; src != nil {
		survivor.PrivSealed = src.PrivSealed
		survivor.Generation = src.Generation
		survivor.Status = src.Status
	}
	if src := byID[picks["status"]]; src != nil {
		survivor.Status = src.Status
	}
	if src := byID[picks["owner"]]; src != nil {
		survivor.OwnerUserID = src.OwnerUserID
	}
	if src := byID[picks["type"]]; src != nil {
		survivor.Type = src.Type
	}
	if err := s.store.Keys.Put(survivor); err != nil {
		return err
	}
	losers := tombstoneLosers(s.store.Keys, recs[1:], survivor.M.UUID)
	s.dedupAssignments(actor)
	s.auditMerge(ConflictKey, survivor.M.UUID, losers, actor)
	return nil
}

func (s *Service) mergeProjects(ids []string, picks map[string]string, actor string) error {
	recs, err := loadLive(s.store.Projects, ids)
	if err != nil {
		return err
	}
	key := strings.ToLower(strings.TrimSpace(recs[0].Name))
	for _, p := range recs {
		if strings.ToLower(strings.TrimSpace(p.Name)) != key {
			return ErrConflictGone
		}
	}
	sort.SliceStable(recs, func(i, j int) bool { return byUUID(recs[i], recs[j]) })
	survivor := recs[0]
	byID := map[string]*model.Project{}
	for _, p := range recs {
		byID[p.M.UUID] = p
	}
	for _, loser := range recs[1:] {
		for _, a := range s.store.Assignments.List() {
			if a.ProjectID == loser.M.UUID {
				a.ProjectID = survivor.M.UUID
				_ = s.store.Assignments.Put(a)
			}
		}
		foldProjectFields(survivor, loser) // add paths for machines the survivor lacks + fill note
	}
	// Apply per-machine path picks: for each "path_<machineID>" pick, set the survivor's
	// path on that machine to the chosen record's path.
	for fk, srcID := range picks {
		if !strings.HasPrefix(fk, "path_") {
			continue
		}
		mid := strings.TrimPrefix(fk, "path_")
		src := byID[srcID]
		if src == nil {
			continue
		}
		for _, pp := range src.Paths {
			if pp.MachineID == mid {
				setProjectPath(survivor, mid, pp.Path)
			}
		}
	}
	if src := byID[picks["note"]]; src != nil {
		survivor.Note = src.Note
	}
	if err := s.store.Projects.Put(survivor); err != nil {
		return err
	}
	losers := tombstoneLosers(s.store.Projects, recs[1:], survivor.M.UUID)
	s.dedupAssignments(actor)
	s.auditMerge(ConflictProject, survivor.M.UUID, losers, actor)
	return nil
}

func (s *Service) mergeOSUsers(ids []string, picks map[string]string, actor string) error {
	recs, err := loadLive(s.store.OSUsers, ids)
	if err != nil {
		return err
	}
	sort.SliceStable(recs, func(i, j int) bool { return byUUID(recs[i], recs[j]) })
	survivor := recs[0]
	// All must name the same account on the same machine.
	for _, u := range recs {
		if u.MachineID != survivor.MachineID || !s.sameAccount(survivor.MachineID, u.Username, survivor.Username) {
			return ErrConflictGone
		}
	}
	byID := map[string]*model.OSUser{}
	for _, u := range recs {
		byID[u.M.UUID] = u
	}
	for _, loser := range recs[1:] {
		for _, a := range s.store.Assignments.List() {
			if a.OSUserID == loser.M.UUID {
				a.OSUserID = survivor.M.UUID
				_ = s.store.Assignments.Put(a)
			}
		}
		for _, g := range s.store.GlobalSets.List() {
			if replaceRecipient(g, loser.M.UUID, survivor.M.UUID) {
				_ = s.store.GlobalSets.Put(g)
			}
		}
		if survivor.KeyBase == "" {
			survivor.KeyBase = loser.KeyBase
		}
	}
	if src := byID[picks["keybase"]]; src != nil {
		survivor.KeyBase = src.KeyBase
	}
	if err := s.store.OSUsers.Put(survivor); err != nil {
		return err
	}
	losers := tombstoneLosers(s.store.OSUsers, recs[1:], survivor.M.UUID)
	s.dedupAssignments(actor)
	s.auditMerge(ConflictOSUser, survivor.M.UUID, losers, actor)
	return nil
}

func (s *Service) mergeMachines(ids []string, picks map[string]string, actor string) error {
	recs, err := loadLive(s.store.Machines, ids)
	if err != nil {
		return err
	}
	key := strings.ToLower(strings.TrimSpace(recs[0].Name))
	for _, mc := range recs {
		if strings.ToLower(strings.TrimSpace(mc.Name)) != key {
			return ErrConflictGone
		}
	}
	sort.SliceStable(recs, func(i, j int) bool { return machineLess(recs[i], recs[j]) })
	survivor := recs[0]
	byID := map[string]*model.Machine{}
	for _, mc := range recs {
		byID[mc.M.UUID] = mc
	}
	for _, loser := range recs[1:] {
		foldMachineFields(survivor, loser)
	}
	if src := byID[picks["host"]]; src != nil {
		survivor.TailscaleHost = src.TailscaleHost
	}
	if src := byID[picks["port"]]; src != nil {
		survivor.AgentPort = src.AgentPort
	}
	if src := byID[picks["os"]]; src != nil {
		survivor.OS = src.OS
	}
	if src := byID[picks["version"]]; src != nil {
		survivor.Version = src.Version
	}
	if err := s.store.Machines.Put(survivor); err != nil {
		return err
	}
	// Tombstone each loser with a MergedInto redirect and re-point its references to the
	// survivor (the same tombstone-driven re-point the reconcile pass uses, so a
	// reinstalled node can follow the pointer and cfg.LocalMachineID is rewritten by the
	// caller's reconcile pass).
	losers := loserIDs(recs[1:])
	for _, loser := range recs[1:] {
		loser.MergedInto = survivor.M.UUID
		_ = s.store.Machines.Put(loser)
		_ = s.store.Machines.Delete(loser.M.UUID)
		s.repointMachineRefs(loser.M.UUID, survivor.M.UUID, actor)
	}
	s.auditMerge(ConflictMachine, survivor.M.UUID, losers, actor)
	return nil
}

func (s *Service) mergeBackup(ids []string, picks map[string]string, actor string) error {
	recs, err := loadLive(s.store.BackupSettingsColl, ids)
	if err != nil {
		return err
	}
	sort.SliceStable(recs, func(i, j int) bool { return byUUID(recs[i], recs[j]) })
	survivor := recs[0]
	for _, b := range recs {
		if b.MachineID != survivor.MachineID {
			return ErrConflictGone
		}
	}
	byID := map[string]*model.BackupSettings{}
	for _, b := range recs {
		byID[b.M.UUID] = b
	}
	for _, loser := range recs[1:] {
		foldBackupFields(survivor, loser)
	}
	if src := byID[picks["password"]]; src != nil {
		survivor.PasswordSealed = src.PasswordSealed
	}
	if src := byID[picks["dailyat"]]; src != nil {
		survivor.DailyAt = src.DailyAt
	}
	if src := byID[picks["destinations"]]; src != nil {
		survivor.Destinations = src.Destinations
	}
	if src := byID[picks["basename"]]; src != nil {
		survivor.BaseName = src.BaseName
	}
	if src := byID[picks["dateformat"]]; src != nil {
		survivor.DateFormat = src.DateFormat
	}
	if src := byID[picks["dateposition"]]; src != nil {
		survivor.DatePosition = src.DatePosition
	}
	if err := s.store.BackupSettingsColl.Put(survivor); err != nil {
		return err
	}
	losers := tombstoneLosers(s.store.BackupSettingsColl, recs[1:], survivor.M.UUID)
	s.auditMerge(ConflictBackup, survivor.M.UUID, losers, actor)
	return nil
}

func (s *Service) mergeNotify(ids []string, picks map[string]string, actor string) error {
	recs, err := loadLive(s.store.NotificationSettingsColl, ids)
	if err != nil {
		return err
	}
	sort.SliceStable(recs, func(i, j int) bool { return byUUID(recs[i], recs[j]) })
	survivor := recs[0]
	for _, n := range recs {
		if n.MachineID != survivor.MachineID {
			return ErrConflictGone
		}
	}
	byID := map[string]*model.NotificationSettings{}
	for _, n := range recs {
		byID[n.M.UUID] = n
	}
	for _, loser := range recs[1:] {
		foldNotificationFields(survivor, loser)
	}
	if src := byID[picks["telegram"]]; src != nil {
		survivor.TelegramTokenSealed = src.TelegramTokenSealed
		survivor.TelegramChatID = src.TelegramChatID
		survivor.TelegramEnabled = src.TelegramEnabled
	}
	if src := byID[picks["slack"]]; src != nil {
		survivor.SlackWebhookSealed = src.SlackWebhookSealed
		survivor.SlackEnabled = src.SlackEnabled
	}
	if src := byID[picks["events"]]; src != nil && src.Events != nil {
		ev := make(map[string]bool, len(src.Events))
		for k, v := range src.Events {
			ev[k] = v
		}
		survivor.Events = ev
	}
	if err := s.store.NotificationSettingsColl.Put(survivor); err != nil {
		return err
	}
	losers := tombstoneLosers(s.store.NotificationSettingsColl, recs[1:], survivor.M.UUID)
	s.auditMerge(ConflictNotify, survivor.M.UUID, losers, actor)
	return nil
}

func (s *Service) mergeMapViews(ids []string, picks map[string]string, actor string) error {
	recs, err := loadLive(s.store.MapViews, ids)
	if err != nil {
		return err
	}
	key := strings.ToLower(strings.TrimSpace(recs[0].Name))
	for _, v := range recs {
		if strings.ToLower(strings.TrimSpace(v.Name)) != key {
			return ErrConflictGone
		}
	}
	sort.SliceStable(recs, func(i, j int) bool { return byUUID(recs[i], recs[j]) })
	survivor := recs[0]
	byID := map[string]*model.MapView{}
	for _, v := range recs {
		byID[v.M.UUID] = v
	}
	if src := byID[picks["layout"]]; src != nil {
		survivor.GroupBy = append([]string(nil), src.GroupBy...)
		survivor.Leaf = src.Leaf
	}
	if err := s.store.MapViews.Put(survivor); err != nil {
		return err
	}
	losers := tombstoneLosers(s.store.MapViews, recs[1:], survivor.M.UUID)
	s.auditMerge(ConflictMapView, survivor.M.UUID, losers, actor)
	return nil
}

// mergeTombstone folds a loser away durably: it stamps the loser's Meta.MergedInto with
// the survivor's id, persists that (so the redirect replicates), then tombstones it. Every
// later reconcile can then follow the redirect to re-point a reference that still names the
// loser onto the survivor - so a merge never leaves a grant dangling. Used by both the
// automatic lossless dedups and operator-confirmed conflict merges.
func mergeTombstone[T model.Record](c *store.Collection[T], loser T, survivorID string) {
	loser.Meta().MergedInto = survivorID
	_ = c.Put(loser)
	_ = c.Delete(loser.Meta().UUID)
}

// resolveMerged follows a chain of Meta.MergedInto redirects on tombstoned records to the
// surviving live id (the non-machine analogue of resolveMachine). It stops at the first
// live record or a broken pointer and guards against a cycle.
func resolveMerged[T model.Record](c *store.Collection[T], id string) string {
	seen := map[string]bool{}
	cur := id
	for cur != "" && !seen[cur] {
		seen[cur] = true
		rec, ok := c.GetRaw(cur)
		if !ok {
			return cur
		}
		m := rec.Meta()
		if !m.Deleted || m.MergedInto == "" {
			return cur
		}
		cur = m.MergedInto
	}
	return cur
}

// tombstoneLosers folds each loser away with a durable MergedInto redirect to the survivor
// (see mergeTombstone) and returns their ids for the audit row.
func tombstoneLosers[T model.Record](c *store.Collection[T], losers []T, survivorID string) []string {
	ids := make([]string, 0, len(losers))
	for _, l := range losers {
		mergeTombstone(c, l, survivorID)
		ids = append(ids, l.Meta().UUID)
	}
	return ids
}

// loserIDs returns the UUIDs of a loser record set (for the merge audit row).
func loserIDs[T model.Record](losers []T) []string {
	ids := make([]string, 0, len(losers))
	for _, l := range losers {
		ids = append(ids, l.Meta().UUID)
	}
	return ids
}

// auditMerge records a merge resolution by entity + surviving/tombstoned UUIDs only -
// never a secret value.
func (s *Service) auditMerge(entityType, survivorID string, loserIDs []string, actor string) {
	_ = s.audit.Record(actor, "conflict_merge", entityType, audit.OK,
		"kept "+survivorID+", tombstoned "+strings.Join(loserIDs, " "))
}

// sameAccount reports OS-aware account-name equality on a machine.
func (s *Service) sameAccount(machineID, a, b string) bool {
	if s.machineIsWindows(machineID) {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// setProjectPath sets (replacing or appending) the survivor project's path on machineID.
func setProjectPath(p *model.Project, machineID, path string) {
	for i := range p.Paths {
		if p.Paths[i].MachineID == machineID {
			p.Paths[i].Path = path
			return
		}
	}
	p.Paths = append(p.Paths, model.ProjectPath{MachineID: machineID, Path: path})
}

// ---- resolution: keep both ------------------------------------------------

// KeepBothDistinct records the operator's decision that a set of records sharing a
// natural key are intentionally DIFFERENT, writing a replicated DistinctAck so the
// conflict pass stops surfacing them and both nodes converge. It supersedes any existing
// ack that is a subset of this set. It refuses for the per-machine settings kinds, where
// two records cannot both be valid (merge is the only resolution).
func (s *Service) KeepBothDistinct(entityType string, recordIDs []string, actor string) error {
	if entityType == ConflictBackup || entityType == ConflictNotify {
		return ErrKeepBothInvalid
	}
	ids := append([]string(nil), recordIDs...)
	sort.Strings(ids)
	if len(ids) < 2 {
		return ErrConflictGone
	}
	// Re-validate the records still form exactly this live conflict group before writing
	// the marker (consistency with ResolveMerge's guard), so a stale request is refused.
	if _, ok := s.ConflictGroupByIDs(entityType, ids); !ok {
		return ErrConflictGone
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	// Supersede any existing ack of this kind whose set is a subset of the new one.
	for _, ack := range s.store.DistinctAcks.List() {
		if ack.EntityType != entityType {
			continue
		}
		subset := true
		for _, id := range ack.RecordIDs {
			if !want[id] {
				subset = false
				break
			}
		}
		if subset {
			_ = s.store.DistinctAcks.Delete(ack.M.UUID)
		}
	}
	ack := &model.DistinctAck{M: model.Meta{UUID: store.NewID()}, EntityType: entityType, RecordIDs: ids}
	if err := s.store.DistinctAcks.Put(ack); err != nil {
		return err
	}
	_ = s.audit.Record(actor, "conflict_keep_both", entityType, audit.OK, strconv.Itoa(len(ids))+" record(s) kept distinct")
	return nil
}
