package keysvc

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"sopshq/internal/audit"
	"sopshq/internal/keys"
	"sopshq/internal/model"
	"sopshq/internal/place"
	"sopshq/internal/store"
)

// ErrWiringConflict is returned by EnsureProjectWired when wiring WOULD touch
// something that already exists on disk or in the store. Rather than overwriting
// silently, the caller (the panel) must inspect the conflict (InspectWiring) and
// re-drive wiring with an explicit per-item decision (WireProjectResolved). This
// is the heart of the "never clobber without a choice" guarantee.
var ErrWiringConflict = errors.New("keysvc: project already has SOPS/age state - choose reuse or re-create")

// WiringInspection reports, for one project on the local machine, every
// pre-existing artifact that wiring would otherwise overwrite. It carries only
// NON-secret facts (paths, presence flags, the public recipient) so it is safe to
// render in the panel and to keep in memory.
//
// The panel turns each "*Exists" item into a REUSE / RE-CREATE choice.
type WiringInspection struct {
	ProjectID   string
	ProjectName string
	OSUsername  string
	KeyBase     string // the key-store base SopsHQ would use
	ProjectDir  string // the project folder whose .sops.yaml SopsHQ would write

	// On-disk findings (from place.Inspect), all non-secret.
	Disk place.Inspection

	// RecordExists is true when SopsHQ already has a generated key assigned to this
	// project (its own custody state). Re-creating means generating a NEW keypair,
	// which can orphan secrets encrypted only to the old one.
	RecordExists bool
	// RecordKeyName / RecordRecipient describe that existing record (public, safe).
	RecordKeyName   string
	RecordRecipient string
}

// AnyExisting reports whether wiring this project would touch any pre-existing
// artifact (on disk or in the store). When false, wiring proceeds with no prompt.
func (w WiringInspection) AnyExisting() bool {
	return w.Disk.AnyExisting() || w.RecordExists
}

// WiringDecision is the operator's choice for one artifact. The zero value
// (DecideReuse) is the safe default: adopt what exists rather than overwrite it.
type WiringDecision int

const (
	// DecideReuse adopts the existing artifact (import the on-disk key into custody,
	// keep the existing .sops.yaml, leave SOPS_AGE_KEY_FILE as it is). Non-destructive.
	DecideReuse WiringDecision = iota
	// DecideRecreate replaces the artifact (generate a new keypair, overwrite
	// keys.txt and .sops.yaml, re-point SOPS_AGE_KEY_FILE). Explicit, confirmed
	// overwrite that may orphan secrets encrypted to the old key.
	DecideRecreate
)

// WiringChoices carries the operator's per-artifact decisions back from the panel.
// Each field applies only when the matching artifact actually exists; when an
// artifact does not exist the field is ignored.
type WiringChoices struct {
	// Key decides what to do with the existing key material (an on-disk keys.txt
	// and/or an existing SopsHQ key record for this project). REUSE imports the
	// on-disk private key into the vault; RE-CREATE generates a fresh keypair.
	Key WiringDecision
	// SopsYAML decides the existing .sops.yaml. REUSE leaves it untouched; RE-CREATE
	// lets Apply rewrite it from the assigned recipients.
	SopsYAML WiringDecision
	// EnvKeyFile decides an already-set SOPS_AGE_KEY_FILE that points elsewhere.
	// REUSE leaves the operator's env var as it is (placement skips re-pointing it);
	// RE-CREATE allows placement to persist SopsHQ's path.
	EnvKeyFile WiringDecision
}

// InspectWiring reports the pre-existing state wiring this project would touch on
// the local machine, WITHOUT changing anything. It resolves the OS user / key
// base the way EnsureProjectWired would, then runs the non-destructive
// place.Inspect and checks the store for an existing assigned key.
//
// It requires a designated local machine and a project with a local folder; those
// preconditions surface as the same sentinel errors EnsureProjectWired uses.
func (s *Service) InspectWiring(projectID string) (WiringInspection, error) {
	var insp WiringInspection
	if s.localMachineID == "" {
		return insp, ErrNoLocalMachine
	}
	p, err := s.store.Projects.Get(projectID)
	if err != nil {
		return insp, err
	}
	dir := s.localProjectPath(p)
	if dir == "" {
		return insp, ErrProjectNoLocalPath
	}

	insp.ProjectID = p.M.UUID
	insp.ProjectName = p.Name
	insp.ProjectDir = dir

	username, keyBase := s.plannedOSUser()
	insp.OSUsername = username
	insp.KeyBase = keyBase

	insp.Disk = place.Inspect(keyBase, dir)

	if k := s.assignedGeneratedKey(p); k != nil {
		insp.RecordExists = true
		insp.RecordKeyName = k.Name
		insp.RecordRecipient = k.Recipient
	}
	return insp, nil
}

// plannedOSUser returns the OS username and key-store base wiring would use: the
// existing local OS user if one is recorded, else the process account's defaults.
// It does NOT create the user (that is a write; this is read-only).
func (s *Service) plannedOSUser() (username, keyBase string) {
	for _, u := range s.store.OSUsers.List() {
		if u.MachineID == s.localMachineID {
			return u.Username, s.userKeyBase(u)
		}
	}
	username, home := currentOSUser()
	return username, defaultKeyBase(home)
}

// assignedGeneratedKey returns the first GENERATED key assigned to the project, or
// nil. Used to detect existing SopsHQ custody state for the project.
func (s *Service) assignedGeneratedKey(p *model.Project) *model.Key {
	for _, a := range s.store.Assignments.List() {
		if a.ProjectID != p.M.UUID {
			continue
		}
		if k, err := s.store.Keys.Get(a.KeyID); err == nil && k.Recipient != "" {
			return k
		}
	}
	return nil
}

// EnsureProjectWired performs the onboarding glue so a project the operator just
// created becomes editable in one action - SAFELY. It is the safe default entry
// point used by the "Wire this project" button.
//
// Behavior:
//   - If the project is already wired locally (a generated key is assigned and its
//     private opens), it is a no-op and returns nil (idempotent).
//   - Otherwise it INSPECTS what already exists at the target. If anything exists
//     (a non-empty keys.txt, a SOPS_AGE_KEY_FILE pointing elsewhere, an existing
//     .sops.yaml, or an existing assigned key record), it does NOT act: it returns
//     ErrWiringConflict so the caller shows the reuse/re-create review screen.
//   - If nothing exists, it wires cleanly (the original behavior): create/find the
//     OS user, generate a shared key, assign it, and Apply.
//
// To proceed past a conflict, the caller gathers the operator's choices and calls
// WireProjectResolved.
func (s *Service) EnsureProjectWired(projectID, actor string) error {
	if s.localMachineID == "" {
		return ErrNoLocalMachine
	}
	p, err := s.store.Projects.Get(projectID)
	if err != nil {
		return err
	}
	if s.localProjectPath(p) == "" {
		return ErrProjectNoLocalPath
	}
	if s.projectPriv(p) != "" {
		return nil // already wired
	}
	if _, err := s.localOSUserID(); err != nil {
		return err
	}

	insp, err := s.InspectWiring(projectID)
	if err != nil {
		return err
	}
	if insp.AnyExisting() {
		return ErrWiringConflict
	}

	// Nothing pre-exists: wire cleanly with fresh material (REUSE/RE-CREATE both
	// reduce to "generate fresh" when there is nothing to adopt).
	return s.wire(projectID, actor, WiringChoices{Key: DecideRecreate})
}

// WireProjectResolved wires a project honoring the operator's explicit per-artifact
// decisions. It is the only path that may overwrite pre-existing state, and only
// for the artifacts the operator chose to RE-CREATE. It is idempotent on an
// already-wired project (no-op).
func (s *Service) WireProjectResolved(projectID string, choices WiringChoices, actor string) error {
	if s.localMachineID == "" {
		return ErrNoLocalMachine
	}
	p, err := s.store.Projects.Get(projectID)
	if err != nil {
		return err
	}
	if s.localProjectPath(p) == "" {
		return ErrProjectNoLocalPath
	}
	if s.projectPriv(p) != "" {
		return nil // already wired
	}
	if _, err := s.localOSUserID(); err != nil {
		return err
	}
	return s.wire(projectID, actor, choices)
}

// wire is the shared implementation behind the clean path and the resolved path.
// It creates/finds the OS user, obtains the project key (imported from disk when
// the operator chose REUSE and an on-disk key exists, else freshly generated),
// assigns it, and applies. Apply writes .sops.yaml and places the private key.
//
// When the operator chose REUSE for the env var, placement must NOT re-point
// SOPS_AGE_KEY_FILE; that is honored by not running the discovery wiring for this
// wire (WriteKeyStore only). When RE-CREATE, the normal placer (with discovery)
// runs.
func (s *Service) wire(projectID string, actor string, choices WiringChoices) error {
	p, err := s.store.Projects.Get(projectID)
	if err != nil {
		return err
	}

	osUserID, err := s.localOSUserID()
	if err != nil {
		return err
	}
	u, err := s.store.OSUsers.Get(osUserID)
	if err != nil {
		return fmt.Errorf("keysvc: load OS user: %w", err)
	}

	// Obtain the project key(s). REUSE matches the folder's existing on-disk SOPS
	// state: when the project folder already carries a .sops.yaml (or encrypted
	// secrets) that names public keys, the project is assigned EXACTLY those public
	// keys, so the desired set equals what is on disk and no phantom drift appears -
	// a keys.txt holding several identities never forces an arbitrary "first
	// identity" pick. On a fresh folder (no on-disk readers) REUSE adopts the single
	// on-disk private key; RE-CREATE mints a fresh "project-<name>" key.
	dir := s.localProjectPath(p)
	disk := place.Inspect(s.userKeyBase(u), dir)
	reuseOnDiskKey := choices.Key == DecideReuse && disk.KeysTxtExists
	var wiredKeys []*model.Key
	if reuseOnDiskKey {
		wiredKeys, err = s.reuseKeysMatchingDisk(dir, u, p.Name, actor)
		if err != nil {
			return err
		}
	} else {
		now := time.Now().Unix()
		k := &model.Key{
			M:         model.Meta{UUID: store.NewID()},
			Name:      "project-" + p.Name,
			Type:      model.KeyShared,
			Status:    model.KeyActive,
			CreatedAt: now,
			EditedAt:  now,
		}
		if err := s.store.Keys.Put(k); err != nil {
			return fmt.Errorf("keysvc: create project key: %w", err)
		}
		// Roll back the empty Key record if generation fails, so a failed wire does
		// not litter the Keys list with a half-made "not generated" entry.
		if err := s.Generate(k.M.UUID, actor); err != nil {
			_ = s.store.Keys.Delete(k.M.UUID)
			return fmt.Errorf("keysvc: generate project key: %w", err)
		}
		wiredKeys = []*model.Key{k}
	}

	// Link the project + user + machine to EACH obtained key, idempotently: reusing a
	// key already assigned for this exact project/user/machine must not add a duplicate
	// Assignment row.
	for _, k := range wiredKeys {
		if s.HasAssignment(k.M.UUID, p.M.UUID, s.localMachineID, osUserID) {
			continue
		}
		a := &model.Assignment{
			M:         model.Meta{UUID: store.NewID()},
			KeyID:     k.M.UUID,
			ProjectID: p.M.UUID,
			MachineID: s.localMachineID,
			OSUserID:  osUserID,
		}
		if err := s.store.Assignments.Put(a); err != nil {
			return fmt.Errorf("keysvc: assign project key: %w", err)
		}
	}

	// Placement strategy. Use the non-destructive applyReusing path whenever the
	// operator chose to PRESERVE any existing artifact:
	//
	//   - the key was ADOPTED from the on-disk keys.txt (REUSE): that file is already
	//     the source of truth and MUST be left byte-identical, so placement must NOT
	//     rewrite it (a rewrite would also normalize a comment-headed age-keygen file
	//     to a bare key);
	//   - a SOPS_AGE_KEY_FILE that points elsewhere is kept: do not re-point it;
	//   - an existing .sops.yaml is kept: do not overwrite it.
	//
	// Otherwise (clean target, or every artifact set to RE-CREATE) run the full
	// placer, which writes the key store, re-points discovery, and writes .sops.yaml.
	keepEnv := choices.EnvKeyFile == DecideReuse && disk.EnvPointsElsewhere
	keepSopsYAML := choices.SopsYAML == DecideReuse && disk.SopsYAMLExists
	if reuseOnDiskKey || keepEnv || keepSopsYAML {
		if err := s.applyReusing(actor, choices, reuseOnDiskKey, keepEnv); err != nil {
			return err
		}
	} else if _, err := s.ApplyLocal(actor, false); err != nil {
		return fmt.Errorf("keysvc: apply after wiring: %w", err)
	}

	names := make([]string, len(wiredKeys))
	for i, k := range wiredKeys {
		names[i] = k.Name
	}
	_ = s.audit.Record(actor, "project_wire", p.Name, audit.OK, "key(s) "+strings.Join(names, ","))
	return nil
}

// applyReusing performs the placement side of wiring when the operator chose to
// preserve at least one existing artifact. It honors the operator's choices that
// ApplyLocal cannot express:
//
//   - adoptedKey: when true the project key was ADOPTED from the on-disk keys.txt,
//     which is therefore already correct. Placement SKIPS rewriting that key store
//     entirely, leaving the file byte-identical (so a comment-headed age-keygen
//     file stays in its original shape and secrets stay decryptable).
//   - keepEnv: when true (and the key was NOT adopted) the key store is written
//     with WriteKeyStore ONLY (no junction/setx/bashrc), so the operator's existing
//     SOPS_AGE_KEY_FILE is left exactly where it points. When false, the full
//     placer runs (it re-points discovery), since there is no env var to protect.
//   - choices.SopsYAML == DecideReuse: an existing .sops.yaml is left untouched.
//
// It re-keys nothing for an adopted key because the on-disk key already matches
// the assigned recipient; it does re-key when it (re)writes a .sops.yaml.
func (s *Service) applyReusing(actor string, choices WiringChoices, adoptedKey, keepEnv bool) error {
	for _, a := range s.store.Assignments.List() {
		if a.MachineID != s.localMachineID {
			continue
		}
		k, err := s.store.Keys.Get(a.KeyID)
		if err != nil || k.Recipient == "" {
			continue
		}
		u, err := s.store.OSUsers.Get(a.OSUserID)
		if err != nil || s.userKeyBase(u) == "" {
			continue
		}
		if adoptedKey {
			// The on-disk key.txt IS the adopted key; do not touch it. But still ENSURE
			// discovery exists: repair a missing junction/symlink or an unset/dangling
			// SOPS_AGE_KEY_FILE so the adopted key is actually findable, while leaving a
			// deliberate different pointer in place (EnsureDiscovery is repair-only).
			_ = s.audit.Record(actor, "key_place", k.Name, audit.OK, "user "+u.Username+" (reuse, on-disk key kept)")
			s.ensureDiscovery(u, actor)
			continue
		}
		priv, err := s.unsealPriv(k)
		if err != nil {
			return err
		}
		opts := s.localPlaceOpts(u, k.Recipient, priv)
		if keepEnv {
			// WriteKeyStore only, then repair-only discovery: the operator's existing
			// SOPS_AGE_KEY_FILE that points elsewhere is left exactly as it was (a
			// conflict EnsureDiscovery reports but never overwrites), while a missing
			// junction/symlink is still created so the key is findable.
			if err := s.guardedPlace(opts, a.OSUserID, u.Username, place.WriteKeyStore); err != nil {
				return fmt.Errorf("keysvc: write key store (reuse): %w", err)
			}
			s.ensureDiscovery(u, actor)
			_ = s.audit.Record(actor, "key_place", k.Name, audit.OK, "user "+u.Username+" (reuse, no env change)")
		} else {
			if err := s.guardedPlace(opts, a.OSUserID, u.Username, s.placer); err != nil {
				return fmt.Errorf("keysvc: place key (reuse): %w", err)
			}
			_ = s.audit.Record(actor, "key_place", k.Name, audit.OK, "user "+u.Username)
		}
	}

	for _, p := range s.store.Projects.List() {
		dir := s.localProjectPath(p)
		if dir == "" {
			continue
		}
		recips, current := s.projectRecipients(p)
		if len(recips) == 0 {
			continue
		}
		disk := place.Inspect(s.projectKeyBase(p), dir)
		if choices.SopsYAML == DecideReuse && disk.SopsYAMLExists {
			continue // keep the operator's existing .sops.yaml untouched
		}
		// Re-writing .sops.yaml in a reuse context must never drop a reader the
		// secrets are already encrypted to: fold every age public key already on disk
		// (from .sops.yaml AND the encrypted secrets metadata) into the recipient set
		// before writing, and fail closed if those readers cannot be read.
		union, uerr := s.unionExistingRecipients(dir, recips)
		if uerr != nil {
			return uerr
		}
		recips = union
		if err := s.guardedSopsYAML(dir, p.M.UUID, p.Name, recips); err != nil {
			return err
		}
		_ = s.audit.Record(actor, "sops_yaml_write", p.Name, audit.OK, dir)
		if current != "" {
			if _, err := s.guardedUpdateKeys(dir, current, p.M.UUID, p.Name); err != nil {
				return fmt.Errorf("keysvc: updatekeys in %q: %w", p.Name, err)
			}
		}
	}
	return nil
}

// ensureDiscovery repairs any missing or broken sops-discovery artifacts for one OS
// user's keystore (an unset/dangling SOPS_AGE_KEY_FILE, an absent junction/symlink)
// WITHOUT clobbering a deliberate different setup. Repair-only, so it is safe to call
// in the reuse/adopt path. Each artifact's outcome is audited by user + state; the
// report carries no secret.
func (s *Service) ensureDiscovery(u *model.OSUser, actor string) {
	base := s.userKeyBase(u)
	if base == "" {
		return
	}
	rep := s.discoverer(place.Opts{Base: base, Username: u.Username})
	for _, it := range rep.Items {
		_ = s.audit.Record(actor, "discovery_ensure", u.Username, audit.OK, it.Artifact+": "+it.State)
	}
}

// EnsureDiscoveryForOSUser repairs the sops-discovery artifacts for one local OS
// user's keystore and returns the per-artifact report for display. It is the service
// behind the panel's "Fix discovery" button. Repair-only: a deliberate different
// SOPS_AGE_KEY_FILE or junction/symlink is reported as a conflict, never overwritten.
func (s *Service) EnsureDiscoveryForOSUser(osUserID, actor string) (place.DiscoveryReport, error) {
	if s.localMachineID == "" {
		return place.DiscoveryReport{}, ErrNoLocalMachine
	}
	u, err := s.store.OSUsers.Get(osUserID)
	if err != nil {
		return place.DiscoveryReport{}, err
	}
	if u.MachineID != s.localMachineID {
		return place.DiscoveryReport{}, errors.New("keysvc: OS user is not on the local machine")
	}
	base := s.userKeyBase(u)
	if base == "" {
		return place.DiscoveryReport{}, errors.New("keysvc: OS user has no keystore base")
	}
	rep := s.discoverer(place.Opts{Base: base, Username: u.Username})
	for _, it := range rep.Items {
		_ = s.audit.Record(actor, "discovery_fix", u.Username, audit.OK, it.Artifact+": "+it.State)
	}
	return rep, nil
}

// DiscoveryStatusForOSUser returns the read-only discovery status for one local OS
// user's keystore, for the OS-users page. It changes nothing on disk. It reports an
// empty (not-wired) status when the user has no keystore base.
func (s *Service) DiscoveryStatusForOSUser(u *model.OSUser) place.DiscoveryStatus {
	base := s.userKeyBase(u)
	if base == "" {
		return place.DiscoveryStatus{EnvName: "SOPS_AGE_KEY_FILE", Verdict: place.VerdictNotWired}
	}
	return place.InspectDiscovery(place.Opts{Base: base, Username: u.Username})
}

// projectKeyBase resolves the key-store base for a project's local assignment, for
// the .sops.yaml existence check. Empty when none is assigned locally.
func (s *Service) projectKeyBase(p *model.Project) string {
	for _, a := range s.store.Assignments.List() {
		if a.ProjectID != p.M.UUID || a.MachineID != s.localMachineID {
			continue
		}
		if u, err := s.store.OSUsers.Get(a.OSUserID); err == nil {
			return s.userKeyBase(u)
		}
	}
	return ""
}

// keyByRecipient returns the existing non-deleted Key in custody whose PUBLIC key
// (Recipient) equals recipient, so callers keep ONE Key record per distinct public
// key instead of importing a duplicate. ok is false when none matches (and always
// for an empty recipient, which is not yet a real public key).
func (s *Service) keyByRecipient(recipient string) (key *model.Key, ok bool) {
	if recipient == "" {
		return nil, false
	}
	for _, k := range s.store.Keys.List() {
		if k.Recipient == recipient {
			return k, true
		}
	}
	return nil, false
}

// obtainReusedKey returns the Key in custody for the on-disk private key at keyBase:
// an existing record when its public key is already held (dedup by public key), else
// a fresh "project-<projectName>" Key with the on-disk key imported into it. The
// on-disk file is only READ, never modified, so existing secrets stay decryptable. On
// a failed import of a freshly created record it rolls that record back.
//
// SECURITY: the private key is read into memory, sealed, and discarded. It is never
// logged; the audit row records the key NAME only.
func (s *Service) obtainReusedKey(keyBase, projectName, actor string) (*model.Key, error) {
	priv, err := place.ReadPrivateKey(keyBase)
	if err != nil {
		return nil, fmt.Errorf("keysvc: read existing key: %w", err)
	}
	rec, err := keys.RecipientFor(priv)
	if err != nil {
		return nil, fmt.Errorf("keysvc: derive recipient: %w", err)
	}
	if existing, ok := s.keyByRecipient(rec); ok {
		return existing, nil
	}
	now := time.Now().Unix()
	k := &model.Key{
		M:         model.Meta{UUID: store.NewID()},
		Name:      "project-" + projectName,
		Type:      model.KeyShared,
		Status:    model.KeyActive,
		CreatedAt: now,
		EditedAt:  now,
	}
	if err := s.store.Keys.Put(k); err != nil {
		return nil, fmt.Errorf("keysvc: create project key: %w", err)
	}
	if err := s.importPrivate(k, priv, actor); err != nil {
		_ = s.store.Keys.Delete(k.M.UUID)
		return nil, err
	}
	return k, nil
}

// reuseKeysMatchingDisk returns the Keys in custody the project should be assigned so
// its desired public-key set equals what the folder's on-disk SOPS state already uses.
// It harvests every public key currently protecting the folder (existingReaders:
// .sops.yaml plus the encrypted secrets metadata, tolerant of any YAML layout), and
// for each one either reuses the Key already in custody (dedup by public key) or, when
// only the matching PRIVATE key sits in the OS user's key store, adopts it read-only
// into custody. A harvested public key with neither an in-custody Key nor a local
// private key is a reader SopsHQ cannot manage (for example a colleague's key): it is
// left on disk (reuse never rewrites .sops.yaml, so it is not dropped) and audited by
// public key, not assigned.
//
// When the folder carries no on-disk readers (a fresh folder), it falls back to
// adopting the single on-disk private key - the original reuse behavior. It also falls
// back when every on-disk reader is unmanageable, so the project still gets a usable
// key rather than none.
//
// CALLER CONTRACT: this only chooses which Keys the project is ASSIGNED; it never writes
// .sops.yaml. Its "leave an unmanageable reader on disk" guarantee holds ONLY because its
// caller (wire -> applyReusing) either keeps the existing .sops.yaml or, when it must
// rewrite one, unions in every on-disk reader via unionExistingRecipients (which fails
// closed). Call it only from a path where that apply-time union runs, so a future
// refactor cannot drop an unmanaged reader by rewriting .sops.yaml without the union.
func (s *Service) reuseKeysMatchingDisk(dir string, u *model.OSUser, projectName, actor string) ([]*model.Key, error) {
	base := s.userKeyBase(u)
	readers, present := s.existingReaders(dir)
	if !present || len(readers) == 0 {
		k, err := s.obtainReusedKey(base, projectName, actor)
		if err != nil {
			return nil, err
		}
		return []*model.Key{k}, nil
	}
	var privByRec map[string]string // lazily read from the OS user's key store
	var out []*model.Key
	seen := map[string]bool{}
	for _, rec := range readers {
		if seen[rec] {
			continue
		}
		seen[rec] = true
		if k, ok := s.keyByRecipient(rec); ok {
			out = append(out, k)
			continue
		}
		// Not in custody: adopt it from the OS user's key store when its private key is
		// present there. Derive the recipient of every on-disk identity once.
		if privByRec == nil {
			privByRec = map[string]string{}
			if privs, rerr := place.ReadPrivateKeys(base); rerr == nil {
				for _, priv := range privs {
					if r, derr := keys.RecipientFor(priv); derr == nil {
						privByRec[r] = priv
					}
				}
			}
		}
		if priv, ok := privByRec[rec]; ok {
			k, err := s.recordAdoptedKey(u, priv, rec, s.nextAdoptedName(u.Username), true, actor)
			if err != nil {
				return nil, err
			}
			out = append(out, k)
			continue
		}
		// A reader SopsHQ has no key for: it stays on disk (never dropped). Surface it
		// by public key in the audit rather than silently ignoring it.
		_ = s.audit.Record(actor, "project_wire_reader_unmanaged", projectName, audit.OK, "public key "+short(rec))
	}
	if len(out) == 0 {
		k, err := s.obtainReusedKey(base, projectName, actor)
		if err != nil {
			return nil, err
		}
		return []*model.Key{k}, nil
	}
	return out, nil
}

// nextAdoptedName returns a Key name for a freshly adopted key that does not collide
// with an existing Key name, following the adopted-<user>[-N] convention: "adopted-bob"
// when free, else "adopted-bob-2", "adopted-bob-3", and so on.
func (s *Service) nextAdoptedName(username string) string {
	existing := map[string]bool{}
	for _, k := range s.store.Keys.List() {
		existing[k.Name] = true
	}
	base := "adopted-" + username
	if !existing[base] {
		return base
	}
	for i := 2; ; i++ {
		name := fmt.Sprintf("adopted-%s-%d", username, i)
		if !existing[name] {
			return name
		}
	}
}

// recordAdoptedKey records an already-read on-disk private key (whose public key is
// rec) as a Key in custody, then - when createAssignment is true - links it to the
// user and their machine with an Assignment so it shows up on the Keys page and is
// usable app-wide. It DEDUPS by public key: when a Key with rec is already held it
// reuses that record (naming a fresh "adopted-<username>" one only when none exists)
// and only adds the Assignment when it is not already present. The on-disk file is
// only READ, never modified (adopt = read + record). On a failure while creating a
// FRESH record it rolls that record back; a reused pre-existing record is left intact.
//
// It is the ONE shared adopt path: every page that points SopsHQ at a keystore which
// already holds a key (adding an OS user, reconciling an externally-changed keys.txt)
// runs through here rather than re-implementing import. SECURITY: the private key is
// sealed and discarded; only the key NAME is audited.
func (s *Service) recordAdoptedKey(u *model.OSUser, priv, rec, name string, createAssignment bool, actor string) (*model.Key, error) {
	k, exists := s.keyByRecipient(rec)
	created := false
	if !exists {
		now := time.Now().Unix()
		k = &model.Key{
			M:         model.Meta{UUID: store.NewID()},
			Name:      name,
			Type:      model.KeyShared,
			Status:    model.KeyActive,
			CreatedAt: now,
			EditedAt:  now,
		}
		if err := s.store.Keys.Put(k); err != nil {
			return nil, err
		}
		if err := s.importPrivate(k, priv, actor); err != nil {
			_ = s.store.Keys.Delete(k.M.UUID)
			return nil, err
		}
		created = true
	}
	if createAssignment && !s.HasAssignment(k.M.UUID, "", u.MachineID, u.M.UUID) {
		a := &model.Assignment{
			M:         model.Meta{UUID: store.NewID()},
			KeyID:     k.M.UUID,
			MachineID: u.MachineID,
			OSUserID:  u.M.UUID,
		}
		if err := s.store.Assignments.Put(a); err != nil {
			if created {
				_ = s.store.Keys.Delete(k.M.UUID)
			}
			return nil, err
		}
	}
	return k, nil
}

// AdoptExistingKeyForOSUser imports EVERY private key already sitting at a LOCAL OS
// user's keystore (<KeyBase>/keys.txt) into SopsHQ's custody as an "adopted-<user>"
// Key plus an Assignment linking it to the user + machine - WITHOUT modifying the
// on-disk file. A real keys.txt may hold SEVERAL identities (age tries each); adopting
// only the first would let a later Apply, which rebuilds the user's key store from the
// vault, DROP the others and orphan secrets encrypted to them. So all identities are
// adopted (deduped by public key), and the placement path already writes a user's full
// key set back, so nothing is lost.
//
// It returns firstName (the primary adopted key's name) and count (how many were
// imported). It is a safe no-op returning count=0 (nil error) when there is nothing to
// adopt: the user is not on this machine, has no keystore base, already has a key in
// custody, or its keystore holds no readable age key. A real failure (e.g. age-keygen
// missing so a public key cannot be derived) returns the error. Private keys are never
// logged; only the key NAMES are audited.
func (s *Service) AdoptExistingKeyForOSUser(osUserID, actor string) (firstName string, count int, err error) {
	u, err := s.store.OSUsers.Get(osUserID)
	if err != nil {
		return "", 0, err
	}
	base := s.userKeyBase(u)
	if s.localMachineID == "" || u.MachineID != s.localMachineID || base == "" {
		return "", 0, nil // a remote keystore (or none) cannot be inspected from here
	}
	if s.userGeneratedKey(osUserID) != nil {
		return "", 0, nil // this user already has a key in custody
	}
	privs, rerr := place.ReadPrivateKeys(base)
	if rerr != nil || len(privs) == 0 {
		return "", 0, nil // no readable age key on disk - nothing to adopt
	}
	// Derive every identity's public key in ONE age-keygen exec (the whole key file on
	// stdin). age-keygen -y prints one recipient per input identity in order, so recs[i]
	// is the public key of privs[i]. If the counts do not line up (an unexpected shape),
	// fall back to per-key derivation so the pairing is never guessed.
	recs, derr := keys.RecipientsFor(strings.Join(privs, "\n"))
	if derr != nil {
		return "", 0, derr
	}
	if len(recs) != len(privs) {
		recs = recs[:0]
		for _, priv := range privs {
			rec, perr := keys.RecipientFor(priv)
			if perr != nil {
				return "", 0, perr
			}
			recs = append(recs, rec)
		}
	}
	seen := map[string]bool{}
	for i, priv := range privs {
		rec := recs[i]
		if seen[rec] {
			continue // the same identity listed twice - import it once
		}
		seen[rec] = true
		name := "adopted-" + u.Username
		if count > 0 {
			name = fmt.Sprintf("adopted-%s-%d", u.Username, count+1)
		}
		k, err := s.recordAdoptedKey(u, priv, rec, name, true, actor)
		if err != nil {
			return "", 0, err
		}
		if count == 0 {
			firstName = k.Name
		}
		count++
	}
	return firstName, count, nil
}

// ProjectHasImportableState reports whether the project's LOCAL folder already holds
// SOPS state worth ADOPTING rather than generating fresh - a project .sops.yaml, or a
// private key already at the target keystore. It is read-only and returns false when
// the project is not local or has no local folder. The panel uses it to offer
// "Import the existing setup" (which routes through the safe reuse/re-create review)
// instead of the plain "generate a key" prompt. It intentionally keys off the same
// signals the safe-wiring guard treats as pre-existing state, so choosing Import
// always lands on the review screen and never silently overwrites existing files.
func (s *Service) ProjectHasImportableState(projectID string) bool {
	if s.localMachineID == "" {
		return false
	}
	p, err := s.store.Projects.Get(projectID)
	if err != nil {
		return false
	}
	dir := s.localProjectPath(p)
	if dir == "" {
		return false
	}
	_, keyBase := s.plannedOSUser()
	disk := place.Inspect(keyBase, dir)
	return disk.SopsYAMLExists || disk.KeysTxtExists
}

// importPrivate seals a private key into a key record and derives its recipient.
// Split out so it is unit-testable without an on-disk file.
func (s *Service) importPrivate(k *model.Key, priv, actor string) error {
	if k.Recipient != "" {
		return errors.New("keysvc: key already generated (cannot import over it)")
	}
	rec, err := keys.RecipientFor(priv)
	if err != nil {
		return fmt.Errorf("keysvc: derive recipient: %w", err)
	}
	sealed, err := s.vault.Seal([]byte(priv))
	if err != nil {
		return fmt.Errorf("keysvc: seal: %w", err)
	}
	k.Recipient = rec
	k.PrivSealed = sealed
	k.Generation = 1
	k.Status = model.KeyActive
	k.EditedAt = time.Now().Unix()
	if k.CreatedAt == 0 {
		k.CreatedAt = k.EditedAt
	}
	if err := s.store.Keys.Put(k); err != nil {
		return err
	}
	_ = s.audit.Record(actor, "key_import", k.Name, audit.OK, "adopted existing on-disk key")
	return nil
}
