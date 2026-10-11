package keysvc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"sopshq/internal/audit"
	"sopshq/internal/keys"
	"sopshq/internal/model"
	"sopshq/internal/place"
)

// ErrNoLocalMachine is returned by ApplyLocal when this node has not been linked
// to a Machine record yet.
var ErrNoLocalMachine = errors.New("keysvc: no local machine designated")

// Action kinds recorded in ApplyReport.Actions. The web layer renders each line
// as "did" or "would" based on whether the apply ran with the dry flag.
const (
	ActionKeyPlaced      = "key-placed"
	ActionProjectWired   = "project-wired"
	ActionSecretsRekeyed = "secrets-rekeyed"
	ActionSkipped        = "skipped"
)

// scopeThisMachine labels actions performed in-process by ApplyLocal. ApplyAll
// labels each action with the target machine's name instead.
const scopeThisMachine = "this machine"

// ApplyAction is one line of the per-item action log: exactly what an apply did,
// or (on a dry run) what it would do. It carries only names, paths, and counts -
// never a secret value, private key, passphrase, or token - so it is safe to
// render in the dashboard and write to logs.
type ApplyAction struct {
	Scope  string // where it happened: "this machine" or a remote machine name
	Kind   string // one of: key-placed, project-wired, secrets-rekeyed, skipped
	Target string // who/what it acted on: user@machine, project name, skipped item
	Detail string // supporting fact: key-store path, .sops.yaml path, count, reason
	OK     bool   // true for a done/would-do action, false for a skip
}

// ApplyReport summarizes what ApplyLocal did, for display and audit.
type ApplyReport struct {
	KeysPlaced    int           // private keys written into user stores
	ProjectsWired int           // .sops.yaml files written
	FilesRekeyed  int           // secret files updated via sops updatekeys
	Skipped       []string      // human-readable notes about things not done
	Actions       []ApplyAction // per-item log of every placement, wire, rekey, skip
}

// placedKey records one private key written into an OS user's key store and bumps
// the KeysPlaced total, so the number of key-placed actions equals KeysPlaced.
func (rep *ApplyReport) placedKey(scope, target, detail string) {
	rep.KeysPlaced++
	rep.Actions = append(rep.Actions, ApplyAction{Scope: scope, Kind: ActionKeyPlaced, Target: target, Detail: detail, OK: true})
}

// wiredProject records one .sops.yaml written for a project and bumps the
// ProjectsWired total, so the number of project-wired actions equals ProjectsWired.
func (rep *ApplyReport) wiredProject(scope, project, sopsPath string) {
	rep.ProjectsWired++
	rep.Actions = append(rep.Actions, ApplyAction{Scope: scope, Kind: ActionProjectWired, Target: project, Detail: sopsPath, OK: true})
}

// rekeyedSecrets records one project's secret files re-encrypted to the current
// recipient set. n is added to the running FilesRekeyed total; a single action
// stands for the whole project, so the number of secrets-rekeyed actions is the
// number of projects re-keyed, not the file total (a project re-keying 3 files is
// one action but FilesRekeyed += 3).
func (rep *ApplyReport) rekeyedSecrets(scope, project string, n int) {
	rep.FilesRekeyed += n
	rep.Actions = append(rep.Actions, ApplyAction{Scope: scope, Kind: ActionSecretsRekeyed, Target: project, Detail: fmt.Sprintf("%d file(s)", n), OK: true})
}

// skip records something the apply did not do, with the reason. The reason is
// also appended to Skipped so callers that read the aggregate notes keep working.
func (rep *ApplyReport) skip(scope, target, reason string) {
	rep.Skipped = append(rep.Skipped, reason)
	rep.Actions = append(rep.Actions, ApplyAction{Scope: scope, Kind: ActionSkipped, Target: target, Detail: reason, OK: false})
}

// ApplyLocal reconciles on-disk state for THIS machine with the desired state in
// the store:
//
//   - For every assignment on the local machine whose key is generated, it places
//     that key's private material into the OS user's key store.
//   - For every project that has assignments and a folder path on this machine,
//     it writes .sops.yaml with the recipients of all keys assigned to that
//     project (on any machine, since the encrypted file is shared), then runs
//     `sops updatekeys` on the project's existing secret files.
//
// It is idempotent and safe to re-run. dryRun computes the report without
// touching disk.
func (s *Service) ApplyLocal(actor string, dryRun bool) (ApplyReport, error) {
	var rep ApplyReport
	if s.localMachineID == "" {
		return rep, ErrNoLocalMachine
	}
	localName := s.localMachineID
	if mc, err := s.store.Machines.Get(s.localMachineID); err == nil {
		localName = mc.Name
	}

	// 1) Place private keys, grouped per OS user. A user assigned several project
	//    keys holds ALL of them in one keys.txt (age tries each), so we write the
	//    user's full set once instead of letting each assignment overwrite the file.
	for _, u := range s.localPlacementUsers(&rep) {
		priv, pub, names, err := s.userKeyMaterial(s.localMachineID, u.M.UUID)
		if err != nil {
			return rep, err
		}
		target := u.Username + "@" + localName
		keyFile := place.KeyFile(s.userKeyBase(u))
		for _, name := range names {
			rep.placedKey(scopeThisMachine, target, name+" -> "+keyFile)
		}
		if dryRun {
			continue
		}
		if err := s.guardedPlace(s.localPlaceOpts(u, pub, priv), u.M.UUID, target, s.placer); err != nil {
			return rep, fmt.Errorf("place keys for %q: %w", u.Username, err)
		}
		_ = s.audit.Record(actor, "key_place", strings.Join(names, ","), audit.OK, "user "+u.Username)
	}

	// 2) Write each local project's .sops.yaml and re-key its secret files.
	for _, p := range s.store.Projects.List() {
		dir := s.localProjectPath(p)
		if dir == "" {
			continue // project has no folder on this machine
		}
		recips, current := s.projectRecipients(p)
		if len(recips) == 0 {
			continue // no generated keys assigned to this project yet
		}
		sopsPath := filepath.Join(dir, ".sops.yaml")
		if dryRun {
			rep.wiredProject(scopeThisMachine, p.Name, sopsPath)
			continue
		}
		if _, err := os.Stat(dir); err != nil {
			rep.skip(scopeThisMachine, p.Name, fmt.Sprintf("project %q path not present: %s", p.Name, dir))
			continue
		}
		if err := s.guardedSopsYAML(dir, p.M.UUID, p.Name, recips); err != nil {
			return rep, err
		}
		_ = s.audit.Record(actor, "sops_yaml_write", p.Name, audit.OK, dir)
		rep.wiredProject(scopeThisMachine, p.Name, sopsPath)

		// Re-key existing secret files so they encrypt to the current set. Needs a
		// current recipient's private key to decrypt first.
		if current != "" {
			n, err := s.guardedUpdateKeys(dir, current, p.M.UUID, p.Name)
			if err != nil {
				return rep, fmt.Errorf("updatekeys in %q: %w", p.Name, err)
			}
			if n > 0 {
				rep.rekeyedSecrets(scopeThisMachine, p.Name, n)
			}
		}
	}

	_ = s.audit.Record(actor, "apply_local", s.localMachineID, audit.OK,
		fmt.Sprintf("placed=%d wired=%d rekeyed=%d", rep.KeysPlaced, rep.ProjectsWired, rep.FilesRekeyed))
	return rep, nil
}

// RotateLocal performs a safe, two-phase rotation of one key on the local
// machine, so existing secret files never become undecryptable mid-rotation:
//
//	Phase A: write .sops.yaml listing BOTH the old and new recipient, then
//	         `sops updatekeys` (decrypting with the OLD key) so files re-encrypt
//	         to the union.
//	Phase B: place the NEW private key into the assigned local users' stores and
//	         update the stored key record to the new keypair (bumping generation).
//	Phase C: write .sops.yaml with the old recipient dropped, then `updatekeys`
//	         (decrypting with the NEW key) so the old key can no longer decrypt.
//
// Projects this key is assigned to but which have no local folder are skipped
// here; the machine that holds the folder rotates them itself.
func (s *Service) RotateLocal(keyID, actor string) error {
	if s.localMachineID == "" {
		return ErrNoLocalMachine
	}
	k, err := s.store.Keys.Get(keyID)
	if err != nil {
		return err
	}
	oldRecipient := k.Recipient
	oldPriv, err := s.unsealPriv(k)
	if err != nil {
		return err
	}
	newKp, err := s.generate()
	if err != nil {
		return err
	}

	affected := s.localProjectsForKey(keyID)
	k.Status = model.KeyRotating
	_ = s.store.Keys.Put(k)

	// Phase A: union(old, new) recipients; decrypt with old.
	for _, p := range affected {
		dir := s.localProjectPath(p)
		recips, _ := s.projectRecipients(p) // includes the old recipient
		recips = append(recips, keys.Recipient{Label: k.Name + " (new)", Age: newKp.Recipient})
		if err := s.guardedSopsYAML(dir, p.M.UUID, p.Name, recips); err != nil {
			return err
		}
		if _, err := s.guardedUpdateKeys(dir, oldPriv, p.M.UUID, p.Name); err != nil {
			return fmt.Errorf("rotate phase A updatekeys in %q: %w", p.Name, err)
		}
	}

	// Phase B: commit the new keypair to the store, THEN re-place each affected
	// local user's FULL key set, so the rotated key and the user's other project
	// keys all land in keys.txt instead of overwriting one another.
	sealed, err := s.vault.Seal([]byte(newKp.Private))
	if err != nil {
		return fmt.Errorf("keysvc: seal: %w", err)
	}
	k.Recipient = newKp.Recipient
	k.PrivSealed = sealed
	k.Generation++
	k.Status = model.KeyActive
	k.EditedAt = time.Now().Unix()
	if err := s.store.Keys.Put(k); err != nil {
		return err
	}
	for _, u := range s.localUsersForKey(keyID) {
		if err := s.placeLocalUser(u, actor); err != nil {
			return fmt.Errorf("place rotated key for %q: %w", u.Username, err)
		}
	}

	// Phase C: drop the old recipient; decrypt with the new key.
	for _, p := range affected {
		dir := s.localProjectPath(p)
		recips, _ := s.projectRecipients(p) // now reflects the new recipient
		if err := s.guardedSopsYAML(dir, p.M.UUID, p.Name, recips); err != nil {
			return err
		}
		if _, err := s.guardedUpdateKeys(dir, newKp.Private, p.M.UUID, p.Name); err != nil {
			return fmt.Errorf("rotate phase C updatekeys in %q: %w", p.Name, err)
		}
	}

	_ = s.audit.Record(actor, "key_rotate", k.Name,
		audit.OK, fmt.Sprintf("generation %d (old %s retired)", k.Generation, short(oldRecipient)))
	return nil
}

// localPlacementUsers returns the distinct local OS users that have at least one
// generated key assigned, in a deterministic order. It appends a skip note to rep
// for each assignment that cannot be placed (missing key/user, ungenerated key, or
// no key-store base), so the report still explains what was left out.
func (s *Service) localPlacementUsers(rep *ApplyReport) []*model.OSUser {
	seen := map[string]bool{}
	var users []*model.OSUser
	for _, a := range s.store.Assignments.List() {
		if a.MachineID != s.localMachineID {
			continue
		}
		k, err := s.store.Keys.Get(a.KeyID)
		if err != nil {
			rep.skip(scopeThisMachine, "assignment", "assignment references a missing key")
			continue
		}
		if k.Recipient == "" {
			rep.skip(scopeThisMachine, k.Name, fmt.Sprintf("key %q not generated yet", k.Name))
			continue
		}
		u, err := s.store.OSUsers.Get(a.OSUserID)
		if err != nil {
			rep.skip(scopeThisMachine, "assignment", "assignment references a missing OS user")
			continue
		}
		if s.userKeyBase(u) == "" {
			rep.skip(scopeThisMachine, u.Username, fmt.Sprintf("OS user %q has no key-store base", u.Username))
			continue
		}
		if seen[u.M.UUID] {
			continue
		}
		seen[u.M.UUID] = true
		users = append(users, u)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].M.UUID < users[j].M.UUID })
	return users
}

// localUsersForKey returns the distinct local OS users assigned a given key.
func (s *Service) localUsersForKey(keyID string) []*model.OSUser {
	seen := map[string]bool{}
	var users []*model.OSUser
	for _, a := range s.store.Assignments.List() {
		if a.MachineID != s.localMachineID || a.KeyID != keyID {
			continue
		}
		u, err := s.store.OSUsers.Get(a.OSUserID)
		if err != nil || s.userKeyBase(u) == "" || seen[u.M.UUID] {
			continue
		}
		seen[u.M.UUID] = true
		users = append(users, u)
	}
	return users
}

// userKeyMaterial builds the key-store contents for one OS user on one machine:
// keys.txt = every GENERATED key assigned to that user there (deduped by recipient,
// sorted for stable output), one private key per line, so a user in several projects
// keeps ALL their keys and sops can decrypt any of them; pubBlob = the matching
// recipients; names = the key names (for the audit row and the placed-count). All
// empty when the user has no generated key assigned.
//
// SECURITY: privBlob holds private keys; the caller places it and never logs it.
func (s *Service) userKeyMaterial(machineID, userID string) (privBlob, pubBlob string, names []string, err error) {
	type ent struct{ rec, priv, name string }
	var ents []ent
	seen := map[string]bool{}
	for _, a := range s.store.Assignments.List() {
		if a.MachineID != machineID || a.OSUserID != userID {
			continue
		}
		k, err := s.store.Keys.Get(a.KeyID)
		if err != nil || k.Recipient == "" || seen[k.Recipient] {
			continue
		}
		priv, err := s.unsealPriv(k)
		if err != nil {
			return "", "", nil, err
		}
		seen[k.Recipient] = true
		ents = append(ents, ent{k.Recipient, priv, k.Name})
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].rec < ents[j].rec })
	var privs, pubs []string
	for _, e := range ents {
		privs = append(privs, e.priv)
		pubs = append(pubs, e.rec)
		names = append(names, e.name)
	}
	return strings.Join(privs, "\n"), strings.Join(pubs, "\n"), names, nil
}

// placeLocalUser (re)writes the full key set for one local OS user (the rotated key
// plus the user's other project keys), so a placement never clobbers the others.
func (s *Service) placeLocalUser(u *model.OSUser, actor string) error {
	priv, pub, names, err := s.userKeyMaterial(s.localMachineID, u.M.UUID)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return nil
	}
	if err := s.guardedPlace(s.localPlaceOpts(u, pub, priv), u.M.UUID, u.Username, s.placer); err != nil {
		return err
	}
	_ = s.audit.Record(actor, "key_place", strings.Join(names, ","), audit.OK, "user "+u.Username)
	return nil
}

// localProjectsForKey returns the projects that have this key assigned AND a
// folder on the local machine.
func (s *Service) localProjectsForKey(keyID string) []*model.Project {
	want := map[string]bool{}
	for _, a := range s.store.Assignments.List() {
		if a.KeyID == keyID {
			want[a.ProjectID] = true
		}
	}
	var out []*model.Project
	for _, p := range s.store.Projects.List() {
		if want[p.M.UUID] && s.localProjectPath(p) != "" {
			out = append(out, p)
		}
	}
	return out
}

// short trims a recipient for a compact audit detail.
func short(s string) string {
	if len(s) > 14 {
		return s[:14] + "..."
	}
	return s
}

// localProjectPath returns this machine's folder for a project, or "".
func (s *Service) localProjectPath(p *model.Project) string {
	for _, pp := range p.Paths {
		if pp.MachineID == s.localMachineID {
			return pp.Path
		}
	}
	return ""
}

// ageRecipientRe matches an age v1 public recipient: bech32 "age1" followed by its
// 58-character data+checksum body. It is used to harvest recipients from a project's
// on-disk SOPS state regardless of YAML layout - inline list, folded scalar, block
// sequence, several creation_rules - and from the sops metadata block of the encrypted
// secrets file, where each real recipient is listed. Values in a secrets file are
// ENC[...] ciphertext and never contain an age1 token, so the scan has no false hits.
var ageRecipientRe = regexp.MustCompile(`age1[0-9a-z]{58,}`)

// existingReaders collects every age public recipient currently protecting a
// project's secrets, from BOTH the on-disk .sops.yaml (any layout, all creation_rules)
// and the sops metadata of its encrypted secrets file(s) - the authoritative record of
// who can actually decrypt right now. It is layout-agnostic: it scans for the age1
// token rather than parsing YAML, so a folded scalar or block sequence cannot hide a
// reader.
//
// present reports whether the on-disk state SIGNALS configured recipients (an "age:"
// key or an "age1" token appears in either file) even if none could be harvested, so a
// caller can fail closed rather than silently rewrite a reduced reader set.
func (s *Service) existingReaders(dir string) (readers []string, present bool) {
	seen := map[string]bool{}
	scan := func(text string) {
		if strings.Contains(text, "age:") || strings.Contains(text, "age1") {
			present = true
		}
		for _, m := range ageRecipientRe.FindAllString(text, -1) {
			if !seen[m] {
				seen[m] = true
				readers = append(readers, m)
			}
		}
	}
	if data, err := os.ReadFile(filepath.Join(dir, ".sops.yaml")); err == nil {
		scan(string(data))
	}
	// The encrypted secrets file(s) list each real recipient in their sops metadata.
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !secretsFileRe.MatchString(e.Name()) {
				continue
			}
			if data, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil {
				scan(string(data))
			}
		}
	}
	return readers, present
}

// secretsFileRe matches the encrypted secret files a project's .sops.yaml governs
// (secrets.yaml, secrets.prod.yml, ...), the same convention SopsCreationRuleRegex
// uses. Anchored to the full base name.
var secretsFileRe = regexp.MustCompile(`^` + keys.SopsCreationRuleRegex)

// unionExistingRecipients returns the project's desired recipients PLUS every age
// public key that ALREADY protects the project's secrets on disk (from .sops.yaml and
// the encrypted secrets metadata). It is the safeguard for the REUSE path: when a
// reused key's .sops.yaml is (re)written, this guarantees SopsHQ never DROPS a public
// key that current secrets were encrypted to (another reader the operator already
// had), which would make those secrets permanently undecryptable for that reader.
//
// It FAILS CLOSED: if the on-disk state clearly signals configured recipients but no
// valid age recipient could be harvested (a format SopsHQ cannot read), it refuses to
// rewrite rather than silently produce a reduced set, returning an error surfaced to
// the operator. Extra keys carry an "existing reader" label for the comment block.
func (s *Service) unionExistingRecipients(dir string, recips []keys.Recipient) ([]keys.Recipient, error) {
	readers, present := s.existingReaders(dir)
	if present && len(readers) == 0 {
		return nil, fmt.Errorf("keysvc: could not read the existing readers of %q; not rewriting .sops.yaml to avoid locking one out", dir)
	}
	have := make(map[string]bool, len(recips))
	for _, r := range recips {
		have[r.Age] = true
	}
	out := append([]keys.Recipient(nil), recips...)
	for _, age := range readers {
		if have[age] {
			continue
		}
		have[age] = true
		out = append(out, keys.Recipient{Label: "existing reader", Age: age})
	}
	return out, nil
}

// projectRecipients returns the recipient list for a project (all generated keys
// assigned to it, on any machine, deduped) and the private identities usable to
// decrypt its secret files for `sops updatekeys`.
//
// The identities are EVERY assigned key SopsHQ can unseal, newline-joined into one
// SOPS_AGE_KEY value (the age identity-file format sops accepts). A re-key must
// decrypt the file as it is CURRENTLY encrypted - to whichever subset of the
// assigned keys is on disk right now - and only then re-encrypt to the full desired
// set. Handing sops every assigned identity lets it decrypt with the one that fits,
// regardless of which keys the file was last encrypted to or the order assignments
// happen to be stored in. The identities are only ever used to decrypt; the
// re-encryption target is the written .sops.yaml, so extra identities are harmless.
func (s *Service) projectRecipients(p *model.Project) ([]keys.Recipient, string) {
	seen := map[string]bool{}
	var recips []keys.Recipient
	var privs []string
	for _, a := range s.store.Assignments.List() {
		if a.ProjectID != p.M.UUID {
			continue
		}
		k, err := s.store.Keys.Get(a.KeyID)
		if err != nil || k.Recipient == "" || seen[k.Recipient] {
			continue
		}
		seen[k.Recipient] = true
		recips = append(recips, keys.Recipient{Label: k.Name, Age: k.Recipient})
		if priv, err := s.unsealPriv(k); err == nil {
			privs = append(privs, priv)
		}
	}
	return recips, strings.Join(privs, "\n")
}
