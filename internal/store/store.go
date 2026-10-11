// Package store is SopsHQ's persistence layer: a dependency-free JSON document
// store with an in-memory index, atomic writes, and a replication oplog.
//
// Design choices (per the approved plan):
//   - Storage is plain JSON files (one per collection), not SQLite, to keep the
//     build free of third-party modules. The data set is small and writes are
//     rare (human-driven), so an in-memory map guarded by a RWMutex is ample.
//   - Every local mutation is stamped with a Hybrid Logical Clock timestamp and
//     the origin node id, then appended to the oplog so the other machine can
//     pull and apply it.
//   - Conflict resolution is last-writer-wins by HLC timestamp, applied in
//     ApplyRemote. Records are soft-deleted (tombstoned) so deletes replicate.
//
// Secret handling is the caller's responsibility: the store persists whatever
// string it is given. For Key.PrivSealed that string is already vault-sealed.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"sopshq/internal/hlc"
	"sopshq/internal/model"
	"sopshq/internal/seal"
)

// ErrNotFound is returned when a record id is absent (or tombstoned, for Get).
var ErrNotFound = errors.New("store: not found")

// Store aggregates all collections plus the shared clock and oplog. A single
// Store represents this node's whole database.
type Store struct {
	dir     string
	node    string
	clock   *hlc.Clock
	oplog   *Oplog
	crypter *seal.Crypter // nil seals nothing (plaintext, for tests/migration)

	Machines           *Collection[*model.Machine]
	OSUsers            *Collection[*model.OSUser]
	PanelUsers         *Collection[*model.PanelUser]
	Projects           *Collection[*model.Project]
	Keys               *Collection[*model.Key]
	Assignments        *Collection[*model.Assignment]
	GlobalSets         *Collection[*model.GlobalSet]
	BackupSettingsColl *Collection[*model.BackupSettings]
	MapViews           *Collection[*model.MapView]

	NotificationSettingsColl *Collection[*model.NotificationSettings]

	// DistinctAcks holds the operator's "keep both" conflict decisions (see
	// model.DistinctAck): a replicated marker that a set of records sharing a
	// natural key are intentionally distinct, so the conflict pass stops flagging
	// them and both nodes converge on that decision.
	DistinctAcks *Collection[*model.DistinctAck]

	// FieldConflicts holds MACHINE-LOCAL same-field divergences detected during
	// replication (see model.FieldConflict): a record whose SAME field group was
	// changed to different values on both machines concurrently. ApplyRemote keeps
	// the local value and records the peer's candidate here for operator resolution
	// in /conflicts. The collection is localOnly (never replicated); both machines
	// detect the same divergence independently.
	FieldConflicts *Collection[*model.FieldConflict]
}

// Open loads (or initializes) the store under dir for the given node id.
//
// cr is the at-rest crypter: when non-nil (production passes a vault-derived
// key, see vault.DeriveStoreKey + seal.New) every backing file and the oplog are
// AES-256-GCM sealed on write and opened on load, and an existing plaintext file
// is transparently rewritten sealed on first load. When cr is nil the store
// reads and writes plaintext (used by tests and the one-way migration path).
func Open(dir, node string, cr *seal.Crypter) (*Store, error) {
	if node == "" {
		return nil, errors.New("store: empty node id")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: mkdir: %w", err)
	}
	oplog, err := OpenOplog(filepath.Join(dir, "oplog.jsonl"), cr)
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, node: node, clock: hlc.New(node), oplog: oplog, crypter: cr}

	s.Machines, err = newCollection(s, "machine", func() *model.Machine { return &model.Machine{} })
	if err != nil {
		return nil, err
	}
	s.OSUsers, err = newCollection(s, "os_user", func() *model.OSUser { return &model.OSUser{} })
	if err != nil {
		return nil, err
	}
	s.PanelUsers, err = newCollection(s, "panel_user", func() *model.PanelUser { return &model.PanelUser{} })
	if err != nil {
		return nil, err
	}
	// Panel-login accounts are per-machine credentials (username, password hash,
	// sealed TOTP secret, recovery-code hashes). Each machine has its own operator
	// login; they must NOT flow between machines, so this collection is machine-local:
	// its writes are never appended to the oplog, and ApplyEvent ignores any inbound
	// panel_user event. This keeps one machine's admin account from ever appearing on
	// another, which is what a credential must guarantee.
	s.PanelUsers.localOnly = true
	s.Projects, err = newCollection(s, "project", func() *model.Project { return &model.Project{} })
	if err != nil {
		return nil, err
	}
	s.Keys, err = newCollection(s, "key", func() *model.Key { return &model.Key{} })
	if err != nil {
		return nil, err
	}
	s.Assignments, err = newCollection(s, "assignment", func() *model.Assignment { return &model.Assignment{} })
	if err != nil {
		return nil, err
	}
	s.GlobalSets, err = newCollection(s, "global_set", func() *model.GlobalSet { return &model.GlobalSet{} })
	if err != nil {
		return nil, err
	}
	s.BackupSettingsColl, err = newCollection(s, "backup_settings", func() *model.BackupSettings { return &model.BackupSettings{} })
	if err != nil {
		return nil, err
	}
	s.MapViews, err = newCollection(s, "map_view", func() *model.MapView { return &model.MapView{} })
	if err != nil {
		return nil, err
	}
	s.NotificationSettingsColl, err = newCollection(s, "notification_settings", func() *model.NotificationSettings { return &model.NotificationSettings{} })
	if err != nil {
		return nil, err
	}
	s.DistinctAcks, err = newCollection(s, "distinct_ack", func() *model.DistinctAck { return &model.DistinctAck{} })
	if err != nil {
		return nil, err
	}
	s.FieldConflicts, err = newCollection(s, "field_conflict", func() *model.FieldConflict { return &model.FieldConflict{} })
	if err != nil {
		return nil, err
	}
	// Same-field divergences are this machine's private view (each node detects them
	// independently); they never replicate.
	s.FieldConflicts.localOnly = true
	return s, nil
}

// BackupSettingsFor returns the backup-settings record for machineID, creating a
// fresh in-memory default (a new id, the standard filename presets) when none
// exists yet. A freshly created default is NOT persisted; after filling it in,
// persist it via BackupSettingsColl.Put. Because settings are per-machine, each
// machineID gets its own record.
func (s *Store) BackupSettingsFor(machineID string) *model.BackupSettings {
	if rec, err := s.BackupSettingsColl.Find(func(b *model.BackupSettings) bool {
		return b.MachineID == machineID
	}); err == nil {
		return rec
	}
	return &model.BackupSettings{
		M:            model.Meta{UUID: NewID()},
		MachineID:    machineID,
		BaseName:     model.DefaultBackupBaseName,
		DateFormat:   model.DefaultBackupDateFormat,
		DatePosition: model.DefaultBackupDatePosition,
	}
}

// NotificationSettingsFor returns the notification-settings record for machineID,
// creating a fresh in-memory default (a new id, the default per-event toggles,
// every channel off) when none exists yet. A freshly created default is NOT
// persisted; after filling it in, persist it via NotificationSettingsColl.Put.
// Because settings are per-machine, each machineID gets its own record.
func (s *Store) NotificationSettingsFor(machineID string) *model.NotificationSettings {
	if rec, err := s.NotificationSettingsColl.Find(func(n *model.NotificationSettings) bool {
		return n.MachineID == machineID
	}); err == nil {
		return rec
	}
	rec := model.DefaultNotificationSettings(machineID)
	rec.M.UUID = NewID()
	return rec
}

// Node returns this store's node id.
func (s *Store) Node() string { return s.node }

// Dir returns the store's on-disk directory, so machine-local, non-replicated
// bookkeeping (e.g. the reconcile pass's acknowledged-peers set) can live beside
// the record files.
func (s *Store) Dir() string { return s.dir }

// Clock exposes the shared HLC (sync uses it to merge remote timestamps).
func (s *Store) Clock() *hlc.Clock { return s.clock }

// Oplog exposes the replication log (sync uses Since/Head).
func (s *Store) Oplog() *Oplog { return s.oplog }

// Collection is a generic, file-backed set of records of one type.
type Collection[T model.Record] struct {
	kind  string
	path  string
	newFn func() T

	// localOnly marks a collection whose records stay on this machine: they are
	// persisted locally but never appended to the replication oplog, and inbound
	// events of this kind are ignored by ApplyEvent. Used for per-machine credentials
	// (panel logins) that must never appear on another machine.
	localOnly bool

	store *Store

	mu    sync.RWMutex
	items map[string]T
	// saved records, for a Merger record type, each record's field-group
	// fingerprints as of the last save. A local Put diffs the record against this
	// baseline to bump only the version vectors of groups that actually changed. It
	// is empty (and unused) for a non-Merger collection.
	saved map[string]map[string]string
}

// newCollection builds a collection, allocating its backing file path and
// loading any existing records.
func newCollection[T model.Record](s *Store, kind string, newFn func() T) (*Collection[T], error) {
	c := &Collection[T]{
		kind:  kind,
		path:  filepath.Join(s.dir, kind+".json"),
		newFn: newFn,
		store: s,
		items: make(map[string]T),
		saved: make(map[string]map[string]string),
	}
	if err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

// load reads the backing file into the in-memory index, decrypting it when it is
// sealed. A legacy plaintext file is read as-is and, when a crypter is present,
// rewritten sealed in place (the one-way at-rest upgrade).
func (c *Collection[T]) load() error {
	raw, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("store: read %s: %w", c.kind, err)
	}
	cr := c.store.crypter
	sealed := seal.IsSealed(raw)
	b := raw
	if sealed {
		if cr == nil {
			return fmt.Errorf("store: %s is sealed but the vault key is unavailable", c.kind)
		}
		if b, err = cr.Open(raw); err != nil {
			return fmt.Errorf("store: open %s: %w", c.kind, err)
		}
	}
	var list []json.RawMessage
	if err := json.Unmarshal(b, &list); err != nil {
		return fmt.Errorf("store: parse %s: %w", c.kind, err)
	}
	for _, rawRec := range list {
		rec := c.newFn()
		if err := json.Unmarshal(rawRec, rec); err != nil {
			return fmt.Errorf("store: parse %s record: %w", c.kind, err)
		}
		c.items[rec.Meta().UUID] = rec
		// Seed the per-field baseline so the first local Put after load bumps only
		// groups that genuinely change (not every group just because it loaded).
		c.snapshotSaved(rec)
	}
	if !sealed && cr != nil {
		// Migrate a plaintext file forward: rewrite it sealed now.
		return c.save()
	}
	return nil
}

// save atomically rewrites the backing file from the in-memory index, sealing it
// when a crypter is present (temp file + rename, mode 0600).
func (c *Collection[T]) save() error {
	list := make([]T, 0, len(c.items))
	for _, rec := range c.items {
		list = append(list, rec)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal %s: %w", c.kind, err)
	}
	if c.store.crypter != nil {
		if b, err = c.store.crypter.Seal(b); err != nil {
			return fmt.Errorf("store: seal %s: %w", c.kind, err)
		}
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("store: write %s: %w", c.kind, err)
	}
	if err := os.Rename(tmp, c.path); err != nil {
		return fmt.Errorf("store: rename %s: %w", c.kind, err)
	}
	return nil
}

// Put performs a LOCAL write: it stamps the record with a fresh HLC timestamp
// and this node's id, persists, and appends to the oplog. The caller must set
// Meta().UUID (use store.NewID for new records).
func (c *Collection[T]) Put(rec T) error {
	m := rec.Meta()
	if m.UUID == "" {
		return errors.New("store: record has no UUID")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	m.Updated = c.store.clock.Now()
	m.Origin = c.store.node
	// For a per-field-merge record, bump the version vector of every group whose
	// value changed since the last save, so a peer can merge this write field-by-field.
	if mg, ok := any(rec).(model.Merger); ok {
		c.stampLocalVV(rec, mg)
	}
	c.items[m.UUID] = rec
	if err := c.save(); err != nil {
		return err
	}
	c.snapshotSaved(rec)
	if c.localOnly {
		return nil // machine-local: never replicated
	}
	return c.appendOplog(rec)
}

// Delete tombstones a record (soft delete) so the deletion replicates.
func (c *Collection[T]) Delete(uuid string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.items[uuid]
	if !ok {
		return ErrNotFound
	}
	m := rec.Meta()
	m.Deleted = true
	m.Updated = c.store.clock.Now()
	m.Origin = c.store.node
	if err := c.save(); err != nil {
		return err
	}
	if c.localOnly {
		return nil // machine-local: never replicated
	}
	return c.appendOplog(rec)
}

// appendOplog writes the current record snapshot to the replication log. Caller
// holds c.mu.
func (c *Collection[T]) appendOplog(rec T) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("store: marshal oplog %s: %w", c.kind, err)
	}
	m := rec.Meta()
	_, err = c.store.oplog.Append(c.kind, m.UUID, m.Updated, m.Origin, raw)
	return err
}

// Get returns a live (non-deleted) record by id.
func (c *Collection[T]) Get(uuid string) (T, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rec, ok := c.items[uuid]
	if !ok || rec.Meta().Deleted {
		var zero T
		return zero, ErrNotFound
	}
	return rec, nil
}

// List returns all live (non-deleted) records.
func (c *Collection[T]) List() []T {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]T, 0, len(c.items))
	for _, rec := range c.items {
		if !rec.Meta().Deleted {
			out = append(out, rec)
		}
	}
	return out
}

// GetRaw returns a record by id INCLUDING a tombstoned (soft-deleted) one, and
// whether it exists at all. Unlike Get it does not hide a deleted record, so the
// reconcile pass can read a merged-away machine's MergedInto redirect. ok is false
// only when the id is entirely unknown.
func (c *Collection[T]) GetRaw(uuid string) (rec T, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rec, ok = c.items[uuid]
	return rec, ok
}

// All returns every record INCLUDING tombstones, so the reconcile pass can walk
// merge redirects that live on soft-deleted records. Callers that only want live
// records use List.
func (c *Collection[T]) All() []T {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]T, 0, len(c.items))
	for _, rec := range c.items {
		out = append(out, rec)
	}
	return out
}

// Find returns the first live record matching pred, or ErrNotFound.
func (c *Collection[T]) Find(pred func(T) bool) (T, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, rec := range c.items {
		if !rec.Meta().Deleted && pred(rec) {
			return rec, nil
		}
	}
	var zero T
	return zero, ErrNotFound
}

// ApplyRemote applies a record received from a peer. It advances the local clock
// past the remote timestamp, then merges the remote copy into the local one.
//
// For a record type that implements model.Merger AND where neither side is a
// tombstone or a merge redirect, it merges FIELD-GROUP by field-group: concurrent
// edits to DIFFERENT groups both survive, a causal update to one group is taken, and
// a genuine same-group divergence keeps the local value and records a FieldConflict
// for operator resolution (never a silent overwrite). Every other case (a non-Merger
// type, or either side deleted/merged) uses whole-record last-writer-wins by HLC.
//
// It reports whether the local copy changed and whether a conflict was observed.
func (c *Collection[T]) ApplyRemote(rec T) (applied, conflict bool, err error) {
	m := rec.Meta()
	c.store.clock.Update(m.Updated)
	c.mu.Lock()
	defer c.mu.Unlock()
	existing, ok := c.items[m.UUID]
	if !ok {
		// Nothing local yet: adopt the whole remote record (its version vectors ride
		// along in Meta), so a first sync of a per-field record starts converged.
		c.items[m.UUID] = rec
		if err := c.save(); err != nil {
			return false, false, err
		}
		c.snapshotSaved(rec)
		return true, false, nil
	}
	// Per-field merge only for two live (non-tombstone, non-merge) Merger records; the
	// tombstone/merge and non-Merger paths keep whole-record last-writer-wins so the
	// reconcile/dedup machinery is untouched.
	lm, lok := any(existing).(model.Merger)
	rm, rok := any(rec).(model.Merger)
	if lok && rok && !existing.Meta().Deleted && !m.Deleted &&
		existing.Meta().MergedInto == "" && m.MergedInto == "" {
		return c.applyMerger(existing, rec, lm, rm)
	}

	switch m.Updated.Compare(existing.Meta().Updated) {
	case 0:
		return false, false, nil // identical write already applied
	case -1:
		// Remote is older. We keep ours, but flag that the two diverged.
		return false, true, nil
	}
	// Remote is newer; it wins. A conflict existed if origins differ.
	conflict = existing.Meta().Origin != m.Origin
	c.items[m.UUID] = rec
	if err := c.save(); err != nil {
		return false, conflict, err
	}
	c.snapshotSaved(rec)
	return true, conflict, nil
}

// hardDelete removes a record from the collection entirely (map entry + baseline),
// as opposed to Delete which tombstones. It is used only for the machine-local,
// ephemeral FieldConflicts rows, which are never replicated and so need no tombstone.
func (c *Collection[T]) hardDelete(uuid string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.items[uuid]; !ok {
		return ErrNotFound
	}
	delete(c.items, uuid)
	delete(c.saved, uuid)
	return c.save()
}
