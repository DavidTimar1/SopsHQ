package keysvc

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"sopshq/internal/audit"
	"sopshq/internal/keys"
	"sopshq/internal/model"
	"sopshq/internal/place"
	"sopshq/internal/store"
)

// userKeyBase resolves the on-disk key-store base directory for an OS user. An
// explicit KeyBase always wins (existing per-home users are unchanged). Otherwise,
// when this machine has a shared keybase root configured AND the user belongs to this
// machine, the base is derived as "<keybaseRoot>/<username>" - a root-derived user
// carries an EMPTY KeyBase, so nothing machine-local ever replicates. It returns ""
// when neither applies (no base yet), which keeps every empty-KeyBase guard
// meaningful: a user with no resolvable base is still skipped exactly as before.
//
// Machine-locality matters for replication: a root-derived user (empty KeyBase) that
// replicates to a peer resolves to the PEER's own keybaseRoot on that peer, and here on
// its non-local machine resolves to "" (its store is that machine's to manage, not
// this one's), so the two machines never fight over a base derived from a foreign root.
func (s *Service) userKeyBase(u *model.OSUser) string {
	if u == nil {
		return ""
	}
	if u.KeyBase != "" {
		return u.KeyBase
	}
	if s.keybaseRoot != "" && u.MachineID == s.localMachineID {
		return filepath.Join(s.keybaseRoot, u.Username)
	}
	return ""
}

// UserKeyBase is the exported view of userKeyBase for the web layer, so the panel can
// show where a root-derived user's keys actually live.
func (s *Service) UserKeyBase(u *model.OSUser) string { return s.userKeyBase(u) }

// rootDerivedOpts returns placement options (Base + Username + KeybaseRoot) for a
// LOCAL root-derived OS user, or nil when the user is not root-derived (an explicit
// KeyBase, no configured root, or not on this machine). It carries no key material and
// is used by the drift scan to verify the shared-root ACLs.
func (s *Service) rootDerivedOpts(u *model.OSUser) *place.Opts {
	if u == nil || u.KeyBase != "" || s.keybaseRoot == "" || u.MachineID != s.localMachineID {
		return nil
	}
	return &place.Opts{Base: s.userKeyBase(u), Username: u.Username, KeybaseRoot: s.keybaseRoot}
}

// localPlaceOpts builds the placement options for one LOCAL OS user, resolving the
// key-store base and marking a root-derived placement so the placer applies the shared
// keybase root ACLs. For an explicit-KeyBase user (or when no root is configured) the
// KeybaseRoot field stays empty and placement behaves exactly as before.
func (s *Service) localPlaceOpts(u *model.OSUser, pub, priv string) place.Opts {
	o := place.Opts{Base: s.userKeyBase(u), Recipient: pub, Private: priv, Username: u.Username}
	if u.KeyBase == "" && s.keybaseRoot != "" && u.MachineID == s.localMachineID {
		o.KeybaseRoot = s.keybaseRoot
	}
	return o
}

// ---- one-click drift resolution -------------------------------------------
//
// These back the per-row actions on the Drift view. Each one is an explicit,
// audited operator choice, so it does NOT go through the pre-write external-change
// guard (that guard exists to STOP a silent overwrite; here the operator has chosen
// to act on the very file that drifted). Each rewrites the managed file and re-keys
// the secrets, then re-stamps, so the next DriftLocal recomputes the item as clear.

// AdoptReaders makes every public key that already protects a project's secrets on
// disk part of the project's DESIRED set, so no reader is dropped. For each on-disk
// public key not already assigned to the project it either reuses the Key SopsHQ
// already holds (dedup by public key) or adopts it from a local key store, then adds
// a project assignment. It finally rewrites .sops.yaml to the expanded set and
// re-keys the secret files to it. It is the safe default for a public-key mismatch.
//
// It refuses (without changing anything) if an on-disk public key cannot be resolved
// to a private key SopsHQ can see - neither in custody nor in a local key store - so
// it never leaves a half-adopted, undecryptable reader; the operator imports that key
// first, or chooses Re-key to desired (which drops it, with a warning).
func (s *Service) AdoptReaders(projectID, actor string) error {
	if s.localMachineID == "" {
		return ErrNoLocalMachine
	}
	p, err := s.store.Projects.Get(projectID)
	if err != nil {
		return err
	}
	dir := s.localProjectPath(p)
	if dir == "" {
		return ErrProjectNoLocalPath
	}
	readers, present := s.existingReaders(dir)
	// Fail closed, exactly like unionExistingRecipients: if the on-disk state SIGNALS
	// configured public keys but none could be harvested (a format SopsHQ cannot read),
	// do NOT rewrite or re-key - that would silently re-encrypt WITHOUT a reader and lock
	// them out. Refuse so the operator resolves it deliberately.
	if present && len(readers) == 0 {
		return fmt.Errorf("keysvc: could not read the existing public keys in %q; not adopting or re-keying, to avoid dropping a reader", dir)
	}
	desired := map[string]bool{}
	base, _ := s.projectRecipients(p)
	for _, r := range base {
		desired[r.Age] = true
	}
	machineID, osUserID, ok := s.anyProjectAssignment(p)
	if !ok {
		return errors.New("keysvc: assign a key to this project first, then adopt the extra public keys")
	}
	// Pre-validate before mutating: every on-disk public key not already part of the
	// project must resolve to a private key SopsHQ can see, so a failure on a LATER
	// reader cannot leave an EARLIER one half-adopted (a partial, unrollback-able change).
	if err := s.ensureReadersResolvable(readers, desired); err != nil {
		return err
	}
	for _, reader := range readers {
		if desired[reader] {
			continue
		}
		k, exists := s.keyByRecipient(reader)
		if !exists {
			priv, u, found := s.localPrivateForRecipient(reader)
			if !found {
				return fmt.Errorf("keysvc: cannot adopt public key %s: its private key is not in SopsHQ's custody or a local key store; import it first or use Re-key to desired", short(reader))
			}
			k, err = s.recordAdoptedKey(u, priv, reader, "adopted-reader", false, actor)
			if err != nil {
				return err
			}
		}
		if !s.HasAssignment(k.M.UUID, projectID, machineID, osUserID) {
			a := &model.Assignment{
				M:         model.Meta{UUID: store.NewID()},
				KeyID:     k.M.UUID,
				ProjectID: projectID,
				MachineID: machineID,
				OSUserID:  osUserID,
			}
			if err := s.store.Assignments.Put(a); err != nil {
				return err
			}
		}
		desired[reader] = true
	}
	if err := s.rewriteAndRekey(dir, p); err != nil {
		return err
	}
	_ = s.audit.Record(actor, "drift_adopt_readers", p.Name, audit.OK, dir)
	return nil
}

// MatchProjectToDisk makes the project's DESIRED public-key set equal what its
// .sops.yaml already uses on disk, so a public-key mismatch clears with NO reader
// dropped and - when the file already matches - NO unnecessary re-key. It is the
// recommended resolve for a public-key mismatch, especially when the difference is one
// account switching between its own identities (both of which decrypt; see
// accountByPublic): the on-disk key becomes the project's key and the desired-only
// alternate is removed.
//
// For each public key already on disk it ensures the project is assigned a Key with
// that public key (reusing one in custody or adopting one from a local key store,
// exactly like AdoptReaders), and it REMOVES the project's assignments whose key is NOT
// on disk. Removing a desired-only key drops nothing that can currently decrypt: that
// key was never on disk, so no secret is encrypted to it. On-disk readers are never
// dropped.
//
// It refuses (changing nothing) when the on-disk state signals public keys but none can
// be read (fail closed), or when an on-disk public key cannot be resolved to a private
// key SopsHQ can see - the operator imports that key first, or chooses Re-key to desired.
func (s *Service) MatchProjectToDisk(projectID, actor string) error {
	if s.localMachineID == "" {
		return ErrNoLocalMachine
	}
	p, err := s.store.Projects.Get(projectID)
	if err != nil {
		return err
	}
	dir := s.localProjectPath(p)
	if dir == "" {
		return ErrProjectNoLocalPath
	}
	readers, present := s.existingReaders(dir)
	if present && len(readers) == 0 {
		return fmt.Errorf("keysvc: could not read the on-disk public keys in %q; not matching, to avoid dropping a reader", dir)
	}
	if len(readers) == 0 {
		return errors.New("keysvc: this project has no on-disk public keys to match; use Apply to write the config")
	}
	machineID, osUserID, ok := s.anyProjectAssignment(p)
	if !ok {
		return errors.New("keysvc: assign a key to this project first, then match the on-disk keys")
	}
	// Pre-validate before mutating: every on-disk public key must resolve to a private
	// key SopsHQ can see, so a failure on a LATER reader cannot leave an EARLIER one
	// half-adopted/assigned (a partial change with no rollback).
	if err := s.ensureReadersResolvable(readers, nil); err != nil {
		return err
	}
	onDiskKeyIDs := map[string]bool{}
	for _, rec := range readers {
		k, exists := s.keyByRecipient(rec)
		if !exists {
			priv, u, found := s.localPrivateForRecipient(rec)
			if !found {
				return fmt.Errorf("keysvc: cannot match public key %s: its private key is not in SopsHQ's custody or a local key store; import it first or use Re-key to desired", short(rec))
			}
			k, err = s.recordAdoptedKey(u, priv, rec, s.nextAdoptedName(u.Username), false, actor)
			if err != nil {
				return err
			}
		}
		onDiskKeyIDs[k.M.UUID] = true
		if !s.HasAssignment(k.M.UUID, projectID, machineID, osUserID) {
			a := &model.Assignment{
				M:         model.Meta{UUID: store.NewID()},
				KeyID:     k.M.UUID,
				ProjectID: projectID,
				MachineID: machineID,
				OSUserID:  osUserID,
			}
			if err := s.store.Assignments.Put(a); err != nil {
				return err
			}
		}
	}
	// Drop the project's assignments whose key is NOT on disk (a desired-only identity,
	// e.g. the same account's other key), so desired == on-disk. An on-disk reader is
	// never dropped: its key is in onDiskKeyIDs.
	for _, a := range s.store.Assignments.List() {
		if a.ProjectID != projectID || onDiskKeyIDs[a.KeyID] {
			continue
		}
		if err := s.store.Assignments.Delete(a.M.UUID); err != nil {
			return err
		}
	}
	// desired now equals on-disk. When the .sops.yaml already lists exactly this set it
	// is a pure no-op: re-stamp so the write-time guard treats the on-disk files as known
	// and the drift row clears, WITHOUT rewriting the file or re-keying the secrets. Only
	// when the file does not already match (e.g. an unusual layout the drift check reads
	// as a subset) is it rewritten to the matched set and the secrets re-keyed - still to
	// the same readers, so nobody is dropped.
	recips, priv := s.projectRecipients(p)
	sopsPath := filepath.Join(dir, ".sops.yaml")
	var onDiskPubs []string
	if got, rerr := os.ReadFile(sopsPath); rerr == nil {
		onDiskPubs = parseAgeLine(string(got))
	}
	if sameRecipients(recips, onDiskPubs) {
		_ = s.restamp(sopsPath, nil)
		if priv != "" {
			_ = s.restampSecrets(dir, priv)
		}
	} else if err := s.rewriteAndRekey(dir, p); err != nil {
		return err
	}
	_ = s.audit.Record(actor, "drift_match_disk", p.Name, audit.OK, dir)
	return nil
}

// MatchProjectToDiskImportsKey reports whether MatchProjectToDisk would import a
// private key into the vault - that is, whether the folder's on-disk state names a
// public key not yet in SopsHQ's custody (which matching would adopt). The web layer
// uses it to admin-gate only the custody-sensitive case: when every on-disk key is
// already in custody, matching imports nothing and needs no admin session. Read-only.
func (s *Service) MatchProjectToDiskImportsKey(projectID string) bool {
	p, err := s.store.Projects.Get(projectID)
	if err != nil {
		return false
	}
	dir := s.localProjectPath(p)
	if dir == "" {
		return false
	}
	readers, _ := s.existingReaders(dir)
	for _, rec := range readers {
		if _, ok := s.keyByRecipient(rec); !ok {
			return true
		}
	}
	return false
}

// RekeyToDesired rewrites a project's .sops.yaml to EXACTLY the project's assigned
// public keys and re-keys its secret files to that set, dropping any extra public
// key that was on disk. It is destructive on purpose (the dropped public key can no
// longer decrypt), so the view warns and names the dropped keys before calling it.
func (s *Service) RekeyToDesired(projectID, actor string) error {
	return s.writeDesired(projectID, actor, "drift_rekey_desired")
}

// WriteProjectSopsYAML writes a project's .sops.yaml (and re-keys any secret files)
// to the project's assigned public keys. It is the resolve action for a project whose
// .sops.yaml has not been written yet ("Apply" on the Drift view).
func (s *Service) WriteProjectSopsYAML(projectID, actor string) error {
	return s.writeDesired(projectID, actor, "drift_write_sops")
}

// writeDesired writes the project's desired .sops.yaml and re-keys its secrets to
// that exact set, then audits under action. Shared by RekeyToDesired and
// WriteProjectSopsYAML.
func (s *Service) writeDesired(projectID, actor, action string) error {
	if s.localMachineID == "" {
		return ErrNoLocalMachine
	}
	p, err := s.store.Projects.Get(projectID)
	if err != nil {
		return err
	}
	dir := s.localProjectPath(p)
	if dir == "" {
		return ErrProjectNoLocalPath
	}
	recips, _ := s.projectRecipients(p)
	if len(recips) == 0 {
		return ErrProjectNotWired
	}
	if err := s.rewriteAndRekey(dir, p); err != nil {
		return err
	}
	_ = s.audit.Record(actor, action, p.Name, audit.OK, dir)
	return nil
}

// rewriteAndRekey writes .sops.yaml for the project's CURRENT desired public keys,
// runs `sops updatekeys` so existing secret files re-encrypt to that set, then stamps
// both. It bypasses the pre-write guard (the caller is an explicit operator resolve
// action) but stamps the result so future external edits are still caught.
//
// updatekeys runs and must SUCCEED before .sops.yaml is stamped: `sops updatekeys`
// reads .sops.yaml to learn the public keys, so the file has to be written first, but
// the stamp (SopsHQ's "this is what we last wrote" marker) is only committed once the
// secrets have actually been re-keyed to match. A re-key failure surfaces to the
// operator and never loses data (the secrets stay decryptable by their existing set).
func (s *Service) rewriteAndRekey(dir string, p *model.Project) error {
	recips, current := s.projectRecipients(p)
	if err := keys.WriteSopsYAML(dir, recips); err != nil {
		return err
	}
	if current != "" {
		if _, err := keys.UpdateKeysInDir(dir, current); err != nil {
			return fmt.Errorf("keysvc: re-key secrets in %q: %w", p.Name, err)
		}
		_ = s.restampSecrets(dir, current)
	}
	return s.restamp(filepath.Join(dir, ".sops.yaml"), nil)
}

// anyProjectAssignment returns a machine + OS user to hang a new project assignment
// on, preferring the project's LOCAL assignment (so an adopted reader lands on this
// machine) and falling back to any assignment the project already has. ok is false
// only when the project has no assignments at all (in which case there is no drift to
// resolve here).
func (s *Service) anyProjectAssignment(p *model.Project) (machineID, osUserID string, ok bool) {
	var fbM, fbU string
	for _, a := range s.store.Assignments.List() {
		if a.ProjectID != p.M.UUID {
			continue
		}
		if a.MachineID == s.localMachineID {
			return a.MachineID, a.OSUserID, true
		}
		if fbM == "" {
			fbM, fbU = a.MachineID, a.OSUserID
		}
	}
	if fbM != "" {
		return fbM, fbU, true
	}
	return "", "", false
}

// ensureReadersResolvable verifies every on-disk public key in readers can be resolved
// to a private key SopsHQ can see - already in custody (keyByRecipient) or present in a
// local OS-user key store (localPrivateForRecipient) - WITHOUT changing anything. It is
// the pre-flight for the resolve actions that adopt and assign on-disk keys, so a failure
// on a later reader never leaves an earlier one half-applied: the caller runs this first
// and returns its error before any mutation. skip lets a caller ignore public keys it
// already counts as resolved (e.g. a project's own keys). Read-only.
func (s *Service) ensureReadersResolvable(readers []string, skip map[string]bool) error {
	for _, rec := range readers {
		if skip[rec] {
			continue
		}
		if _, ok := s.keyByRecipient(rec); ok {
			continue
		}
		if _, _, found := s.localPrivateForRecipient(rec); !found {
			return fmt.Errorf("keysvc: cannot resolve public key %s: its private key is not in SopsHQ's custody or a local key store; import it first or use Re-key to desired", short(rec))
		}
	}
	return nil
}

// localPrivateForRecipient scans this machine's OS-user key stores for a private key
// whose PUBLIC key equals rec, returning it and the owning OS user. It lets
// AdoptReaders take a public key that is not yet in custody but IS present on disk
// into custody. SECURITY: the returned private key is sealed by the caller and never
// logged.
func (s *Service) localPrivateForRecipient(rec string) (priv string, u *model.OSUser, ok bool) {
	for _, cand := range s.store.OSUsers.List() {
		base := s.userKeyBase(cand)
		if cand.MachineID != s.localMachineID || base == "" {
			continue
		}
		privs, err := place.ReadPrivateKeys(base)
		if err != nil {
			continue
		}
		for _, p := range privs {
			if r, err := keys.RecipientFor(p); err == nil && r == rec {
				return p, cand, true
			}
		}
	}
	return "", nil, false
}

// ---- local folder move -----------------------------------------------------

// MovePlan previews what changing a project's LOCAL folder will do to the
// SopsHQ-managed files. It is built read-only; nothing moves until the operator
// confirms. Only the SopsHQ-managed .sops.yaml and a SopsHQ-tracked secrets file are
// ever moved; a hand-authored .sops.yaml is left exactly where it is.
type MovePlan struct {
	ProjectID    string
	ProjectName  string
	OldPath      string
	NewPath      string
	MoveSops     bool   // a SopsHQ-generated .sops.yaml at the old path will move
	HandAuthored bool   // a .sops.yaml at the old path is hand-authored -> left in place
	MoveSecrets  bool   // a SopsHQ-tracked secrets file at the old path will move
	SecretsName  string // the secrets file name (documentation for the confirm screen)
	DestConflict string // non-empty: a DIFFERENT .sops.yaml already sits at the new path, blocking the move

	// DestSecretsConflict is non-empty when a DIFFERENT secrets file already sits at the
	// new path. Moving would overwrite it and destroy its (unrelated, encrypted) data, so
	// the move is refused until the operator resolves it.
	DestSecretsConflict string
}

// PlanLocalMove previews relocating a project's managed files from its current local
// folder to newPath. It reads only; it never moves anything.
func (s *Service) PlanLocalMove(projectID, newPath string) (MovePlan, error) {
	p, err := s.store.Projects.Get(projectID)
	if err != nil {
		return MovePlan{}, err
	}
	old := s.localProjectPath(p)
	plan := MovePlan{
		ProjectID:   projectID,
		ProjectName: p.Name,
		OldPath:     old,
		NewPath:     newPath,
		SecretsName: keys.SecretFileName,
	}
	oldSops := filepath.Join(old, ".sops.yaml")
	if content, rerr := os.ReadFile(oldSops); rerr == nil {
		if keys.IsManaged(content) {
			plan.MoveSops = true
			if dst, derr := os.ReadFile(filepath.Join(newPath, ".sops.yaml")); derr == nil && !bytes.Equal(content, dst) {
				plan.DestConflict = filepath.Join(newPath, ".sops.yaml")
			}
		} else {
			plan.HandAuthored = true
		}
	}
	oldSecrets := filepath.Join(old, keys.SecretFileName)
	if s.stamps != nil {
		if _, ok := s.stamps.Get(oldSecrets); ok {
			if srcSecrets, serr := os.ReadFile(oldSecrets); serr == nil {
				plan.MoveSecrets = true
				// Moving the secrets file would os.Rename over any file already at the
				// destination. If a DIFFERENT secrets file is there, that is unrelated
				// encrypted data - refuse rather than clobber it.
				if dst, derr := os.ReadFile(filepath.Join(newPath, keys.SecretFileName)); derr == nil && !bytes.Equal(srcSecrets, dst) {
					plan.DestSecretsConflict = filepath.Join(newPath, keys.SecretFileName)
				}
			}
		}
	}
	return plan, nil
}

// MoveLocalPath relocates a project's SopsHQ-managed files from its current local
// folder to newPath, removes them from the old folder, and points the project record
// at newPath - all on the LOCAL machine's filesystem. It never touches a hand-authored
// .sops.yaml or any file SopsHQ does not manage.
//
// It stops safely (no partial or destructive state) when: the old managed file was
// changed outside SopsHQ (returns *ExternalChange so the panel can offer a reconcile
// choice), a DIFFERENT managed file already sits at the new path, or the new folder
// cannot be created or written. All guard and writability checks run BEFORE any file
// is moved.
func (s *Service) MoveLocalPath(projectID, newPath, actor string) error {
	if s.localMachineID == "" {
		return ErrNoLocalMachine
	}
	p, err := s.store.Projects.Get(projectID)
	if err != nil {
		return err
	}
	old := s.localProjectPath(p)
	if old == "" {
		return ErrProjectNoLocalPath
	}
	if samePathClean(old, newPath) {
		return nil // nothing to do
	}
	plan, err := s.PlanLocalMove(projectID, newPath)
	if err != nil {
		return err
	}
	if plan.DestConflict != "" {
		return fmt.Errorf("keysvc: the new folder already has a different .sops.yaml (%s); resolve it from Drift first, then move", plan.DestConflict)
	}
	if plan.DestSecretsConflict != "" {
		return fmt.Errorf("keysvc: the new folder already has a different %s (%s); move or remove it first so its data is not overwritten", keys.SecretFileName, plan.DestSecretsConflict)
	}

	oldSops := filepath.Join(old, ".sops.yaml")
	oldSecrets := filepath.Join(old, keys.SecretFileName)

	// Guard the managed files BEFORE any destructive action.
	if plan.MoveSops {
		if err := s.guardWrite(oldSops, ChangeSopsYAML, p.Name, projectID, "",
			func([]byte, []string) ChangeDiff {
				return ChangeDiff{Note: "the .sops.yaml was changed outside SopsHQ; reconcile it before moving the folder"}
			}); err != nil {
			return err
		}
	}
	if plan.MoveSecrets && s.stamps != nil {
		current, _ := os.ReadFile(oldSecrets)
		if changed, _, had := s.stamps.Check(oldSecrets, current); had && changed {
			return &ExternalChange{Diff: ChangeDiff{
				Kind: ChangeSecretsYAML, Path: oldSecrets, Target: p.Name, ProjectID: projectID,
				Note: "the secrets file was changed outside SopsHQ; reconcile it before moving the folder",
			}}
		}
	}

	// Ensure the destination is usable (safe stop if not).
	if err := os.MkdirAll(newPath, 0o755); err != nil {
		return fmt.Errorf("keysvc: the new folder %s cannot be created: %w", newPath, err)
	}
	if err := checkWritable(newPath); err != nil {
		return fmt.Errorf("keysvc: the new folder %s is not writable: %w", newPath, err)
	}

	// Move exact bytes (never regenerate), then remove the source.
	if plan.MoveSops {
		if err := s.relocateManagedFile(oldSops, filepath.Join(newPath, ".sops.yaml")); err != nil {
			return err
		}
	}
	if plan.MoveSecrets {
		if err := s.relocateManagedFile(oldSecrets, filepath.Join(newPath, keys.SecretFileName)); err != nil {
			return err
		}
	}

	if err := s.setLocalPath(p, newPath); err != nil {
		return err
	}
	_ = s.audit.Record(actor, "project_path_move", p.Name, audit.OK, old+" -> "+newPath)
	return nil
}

// relocateManagedFile copies src's exact bytes to dst (atomic temp+rename), removes
// src, and moves its content stamp from src to dst so the guard keeps working at the
// new path. The bytes are preserved as-is - the file is moved, not regenerated.
func (s *Service) relocateManagedFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("keysvc: read %s: %w", src, err)
	}
	mode := os.FileMode(0o644)
	if fi, serr := os.Stat(src); serr == nil {
		mode = fi.Mode().Perm()
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("keysvc: write %s: %w", dst, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("keysvc: place %s: %w", dst, err)
	}
	if err := os.Remove(src); err != nil {
		return fmt.Errorf("keysvc: remove old %s: %w", src, err)
	}
	if s.stamps != nil {
		var names []string
		if st, ok := s.stamps.Get(src); ok {
			names = st.Names
		}
		_ = s.stamps.Put(dst, data, names)
		_ = s.stamps.Delete(src)
	}
	return nil
}

// setLocalPath points the project's LOCAL machine path at newPath (replacing the
// existing entry, or adding one when none exists).
func (s *Service) setLocalPath(p *model.Project, newPath string) error {
	for i := range p.Paths {
		if p.Paths[i].MachineID == s.localMachineID {
			p.Paths[i].Path = newPath
			return s.store.Projects.Put(p)
		}
	}
	p.Paths = append(p.Paths, model.ProjectPath{MachineID: s.localMachineID, Path: newPath})
	return s.store.Projects.Put(p)
}

// checkWritable verifies a directory can be written to by creating and removing a
// temporary file, so a move fails fast (before touching the old folder) when the new
// folder is read-only.
func checkWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".sopshq-write-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

// samePathClean reports whether two paths point at the same folder after cleaning,
// case-insensitively on Windows to match its file system.
func samePathClean(a, b string) bool {
	ca, cb := filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(ca, cb)
	}
	return ca == cb
}
