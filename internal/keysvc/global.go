package keysvc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"sopshq/internal/audit"
	"sopshq/internal/keys"
	"sopshq/internal/model"
	"sopshq/internal/place"
	"sopshq/internal/store"
)

// Global (shared) secrets: a NAMED set of name=value pairs, encrypted to one or
// more OS users on this machine, so each can decrypt with their OWN key (no shared
// private key). A one-reader set is the "your own global secrets" case.
//
// A set is built by selecting one or more per_user KEYS, each OWNED by a local OS
// user (Key.Type == per_user and Key.OwnerUserID set). The set is encrypted to each
// selected key's owner; those owners are the set's readers (GlobalSet.RecipientUserIDs).
//
// Each set is a directory <keybase>/global/<set name>/ holding secrets.yaml (the
// encrypted values) + .sops.yaml (the reader keys), placed into EVERY owner's
// keystore. The copies are byte-identical (encrypted to the same key list), so each
// user reads their own copy with their own key - no cross-account file permissions
// and no shared key. SopsHQ keeps NO copy of a value (encrypt-and-forget); the
// GlobalSet record only tracks the name + owner reader ids.
//
// Apps consume a set the standard sops way:
//   sops exec-env <keybase>/global/<set>/secrets.yaml '<command>'
// (the recipient's private key is placed by normal project Apply).

var setNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

var (
	// ErrGlobalNotLocal means the set (or a recipient) lives on another machine;
	// global secret files are written to local disk, so only local sets/users apply.
	ErrGlobalNotLocal = errors.New("keysvc: global secrets can only be edited for OS users on this machine")
	// ErrNoUserKeyBase means an owner OS user has no key-store base.
	ErrNoUserKeyBase = errors.New("keysvc: an owner OS user has no key-store base")
	// ErrNoUserKey means an owner OS user owns no generated per-user key, so there is
	// nothing to encrypt the set to. A DEFINED key that merely lacks its keypair is NOT
	// this error at creation time - it is generated on use.
	ErrNoUserKey = errors.New("keysvc: an owner OS user owns no generated per-user key")
	// ErrKeyNotPerUser means a selected key is not a per_user key, so it has no single
	// owner to make a set reader.
	ErrKeyNotPerUser = errors.New("keysvc: a selected key is not a per-user key")
	// ErrKeyNoOwner means a selected per_user key has no owner OS user set.
	ErrKeyNoOwner = errors.New("keysvc: a selected per-user key has no owner OS user")
	// ErrBadSetName means the set name is empty or uses characters outside the safe
	// set (it doubles as the on-disk directory name).
	ErrBadSetName = errors.New("keysvc: set name must use only letters, digits, '_' and '-'")
	// ErrNoRecipients means a set was created with no usable per_user key selected.
	ErrNoRecipients = errors.New("keysvc: choose at least one per-user key")
	// ErrSetExists means a set with that name already exists on this machine.
	ErrSetExists = errors.New("keysvc: a global secret set with that name already exists")
)

// GlobalRecipient is one reader of a set: their username and the exact path their
// apps point `sops exec-env` at.
type GlobalRecipient struct {
	Username    string
	ConsumePath string
}

// userGeneratedKey returns the first GENERATED key assigned to the OS user, or
// nil. Its private (in the user's keystore after Apply) is what decrypts a set the
// user is a recipient of, so the set is encrypted to its recipient.
func (s *Service) userGeneratedKey(osUserID string) *model.Key {
	for _, a := range s.store.Assignments.List() {
		if a.OSUserID != osUserID {
			continue
		}
		if k, err := s.store.Keys.Get(a.KeyID); err == nil && k.Recipient != "" {
			return k
		}
	}
	return nil
}

// ownedGeneratedKey returns the GENERATED per_user key OWNED by the OS user, or nil.
// Its private (in the owner's keystore after placement) is what decrypts a set the
// owner reads, so the set is encrypted to it. When an owner owns more than one
// generated per_user key the pick is deterministic (lowest key name), so every
// resolve of the same set encrypts to the same key.
func (s *Service) ownedGeneratedKey(osUserID string) *model.Key {
	var best *model.Key
	for _, k := range s.store.Keys.List() {
		if k.Type != model.KeyPerUser || k.OwnerUserID != osUserID || k.Recipient == "" {
			continue
		}
		if best == nil || k.Name < best.Name {
			best = k
		}
	}
	return best
}

// ownedKey returns a per_user key OWNED by the OS user, preferring one already
// generated but falling back to a defined-but-ungenerated one. It returns nil only
// when the user owns NO per_user key at all. The Global page uses it so an owner
// whose key is defined but not yet minted is still eligible; the keypair is minted
// on use (EnsureGenerated) when the set is actually created.
func (s *Service) ownedKey(osUserID string) *model.Key {
	if k := s.ownedGeneratedKey(osUserID); k != nil {
		return k
	}
	var pending *model.Key
	for _, k := range s.store.Keys.List() {
		if k.Type != model.KeyPerUser || k.OwnerUserID != osUserID {
			continue
		}
		if pending == nil || k.Name < pending.Name {
			pending = k
		}
	}
	return pending
}

// setResolved is the on-disk view of a set: every recipient's dir, the recipient
// list (for .sops.yaml), and a "primary" dir + unsealed private SopsHQ uses to
// read/write the set (any recipient's key works since the file is encrypted to
// all). After a write, the primary copy is synced to the other dirs.
type setResolved struct {
	set         *model.GlobalSet
	dirs        []string
	usernames   []string
	rootDerived []bool // per recipient: true when the store is under keybase_root (needs an ACL)
	recipients  []keys.Recipient
	primaryDir  string
	priv        string
}

// resolveSet validates a set and computes its on-disk placement. It requires the
// set and every recipient to be local, with a key-store base and an assigned
// generated key.
func (s *Service) resolveSet(setID string) (*setResolved, error) {
	if s.localMachineID == "" {
		return nil, ErrNoLocalMachine
	}
	set, err := s.store.GlobalSets.Get(setID)
	if err != nil {
		return nil, err
	}
	if set.MachineID != s.localMachineID {
		return nil, ErrGlobalNotLocal
	}
	if len(set.RecipientUserIDs) == 0 {
		return nil, ErrNoRecipients
	}
	r := &setResolved{set: set}
	for i, uid := range set.RecipientUserIDs {
		u, err := s.store.OSUsers.Get(uid)
		if err != nil {
			return nil, err
		}
		if u.MachineID != s.localMachineID {
			return nil, ErrGlobalNotLocal
		}
		base := s.userKeyBase(u)
		if base == "" {
			return nil, fmt.Errorf("%w (%s)", ErrNoUserKeyBase, u.Username)
		}
		k := s.ownedGeneratedKey(uid)
		if k == nil {
			return nil, fmt.Errorf("%w (%s)", ErrNoUserKey, u.Username)
		}
		dir := filepath.Join(base, "global", set.Name)
		r.dirs = append(r.dirs, dir)
		r.usernames = append(r.usernames, u.Username)
		r.rootDerived = append(r.rootDerived, s.rootDerivedOpts(u) != nil)
		r.recipients = append(r.recipients, keys.Recipient{Label: u.Username, Age: k.Recipient})
		if i == 0 {
			priv, err := s.unsealPriv(k)
			if err != nil {
				return nil, err
			}
			r.primaryDir = dir
			r.priv = priv
		}
	}
	return r, nil
}

// ensureSetDirs makes each recipient's set dir and writes the (identical)
// .sops.yaml listing all recipients, so the keys.* sops helpers find a creation
// rule and each copy decrypts for its own user.
func (s *Service) ensureSetDirs(r *setResolved) error {
	for i, d := range r.dirs {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
		if err := keys.WriteSopsYAML(d, r.recipients); err != nil {
			return err
		}
		if r.rootDerived[i] {
			if err := s.applyGlobalSetACL(r.usernames[i], d); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyGlobalSetACL grants a root-derived recipient traverse+read on the shared-set
// dirs so "sops -d" on their own copy works. The dirs ("<base>/global" and
// "<base>/global/<set>") and the secret files inside are owned 0700/0600 by the SopsHQ
// account, so - like the key store itself - the recipient needs an explicit POSIX ACL.
// setDir is "<base>/global/<set>"; its parent "<base>/global" also needs traverse. This
// runs ONLY for root-derived recipients (per-home users are unchanged) and fails loud:
// an ACL that cannot be applied or verified returns an error rather than leaving a copy
// the recipient cannot read.
func (s *Service) applyGlobalSetACL(username, setDir string) error {
	var files []string
	for _, name := range []string{keys.SecretFileName, ".sops.yaml"} {
		p := filepath.Join(setDir, name)
		if _, err := os.Stat(p); err == nil {
			files = append(files, p)
		}
	}
	return place.ApplyGlobalSetACL(place.GlobalSetACLOpts{
		Username:  username,
		GlobalDir: filepath.Dir(setDir),
		SetDir:    setDir,
		Files:     files,
	})
}

// syncSet copies the primary secrets.yaml (byte-identical ciphertext) into every
// other recipient's dir atomically, so all copies stay in lockstep.
func (s *Service) syncSet(r *setResolved) error {
	data, err := os.ReadFile(filepath.Join(r.primaryDir, keys.SecretFileName))
	if err != nil {
		return err
	}
	for _, d := range r.dirs {
		if d == r.primaryDir {
			continue
		}
		dst := filepath.Join(d, keys.SecretFileName)
		tmp := dst + ".tmp"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, dst); err != nil {
			return err
		}
	}
	return nil
}

// GlobalSets returns the sets on this machine, sorted by name.
func (s *Service) GlobalSets() []*model.GlobalSet {
	var out []*model.GlobalSet
	for _, g := range s.store.GlobalSets.List() {
		if g.MachineID == s.localMachineID {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// GlobalKeyCandidate is one per_user key selectable when creating a set: the key and
// its owning local OS user, so the panel can show "key name (owner username)".
type GlobalKeyCandidate struct {
	KeyID         string
	KeyName       string
	OwnerUserID   string
	OwnerUsername string
}

// GlobalKeyCandidates returns the per_user keys eligible to build a set: each is
// OWNED by a local OS user who has a key-store base. A key whose keypair is not yet
// generated still counts - its keypair is minted when the set is created, so a
// defined key never blocks set creation. Sorted by owner username then key name.
func (s *Service) GlobalKeyCandidates() []GlobalKeyCandidate {
	var out []GlobalKeyCandidate
	for _, k := range s.store.Keys.List() {
		if k.Type != model.KeyPerUser || k.OwnerUserID == "" {
			continue
		}
		u, err := s.store.OSUsers.Get(k.OwnerUserID)
		if err != nil || u.MachineID != s.localMachineID || s.userKeyBase(u) == "" {
			continue
		}
		out = append(out, GlobalKeyCandidate{
			KeyID: k.M.UUID, KeyName: k.Name, OwnerUserID: u.M.UUID, OwnerUsername: u.Username,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OwnerUsername != out[j].OwnerUsername {
			return out[i].OwnerUsername < out[j].OwnerUsername
		}
		return out[i].KeyName < out[j].KeyName
	})
	return out
}

// GlobalSetRecipients returns each recipient's username + consume path for display.
func (s *Service) GlobalSetRecipients(set *model.GlobalSet) []GlobalRecipient {
	var out []GlobalRecipient
	for _, uid := range set.RecipientUserIDs {
		u, err := s.store.OSUsers.Get(uid)
		if err != nil {
			continue
		}
		path := ""
		if base := s.userKeyBase(u); base != "" {
			path = filepath.Join(base, "global", set.Name, keys.SecretFileName)
		}
		out = append(out, GlobalRecipient{Username: u.Username, ConsumePath: path})
	}
	return out
}

// CreateGlobalSet creates a named set by SELECTING one or more per_user keys. Each
// key must be a per_user key OWNED by a local OS user with a key-store base; the set
// is encrypted to each key's OWNER, and those owners become the set's readers. A
// selected key whose keypair is not yet generated is minted on use (EnsureGenerated),
// so a defined key does not block creation. Several keys => several owners => a
// byte-identical copy in each owner's keystore. The set's dirs/.sops.yaml are written
// so it is ready to hold secrets.
func (s *Service) CreateGlobalSet(name string, keyIDs []string, actor string) (*model.GlobalSet, error) {
	if s.localMachineID == "" {
		return nil, ErrNoLocalMachine
	}
	name = strings.TrimSpace(name)
	if !setNameRe.MatchString(name) {
		return nil, ErrBadSetName
	}
	for _, g := range s.store.GlobalSets.List() {
		if g.MachineID == s.localMachineID && strings.EqualFold(g.Name, name) {
			return nil, ErrSetExists
		}
	}
	seenOwner := map[string]bool{}
	seenKey := map[string]bool{}
	var owners []string
	for _, keyID := range keyIDs {
		if keyID == "" || seenKey[keyID] {
			continue
		}
		seenKey[keyID] = true
		k, err := s.store.Keys.Get(keyID)
		if err != nil {
			return nil, err
		}
		if k.Type != model.KeyPerUser {
			return nil, fmt.Errorf("%w (%s)", ErrKeyNotPerUser, k.Name)
		}
		if k.OwnerUserID == "" {
			return nil, fmt.Errorf("%w (%s)", ErrKeyNoOwner, k.Name)
		}
		u, err := s.store.OSUsers.Get(k.OwnerUserID)
		if err != nil {
			return nil, err
		}
		if u.MachineID != s.localMachineID {
			return nil, ErrGlobalNotLocal
		}
		if s.userKeyBase(u) == "" {
			return nil, fmt.Errorf("%w (%s)", ErrNoUserKeyBase, u.Username)
		}
		// Mint the keypair now if the selected key is still defined-only, so a set built
		// from a fresh per_user key works without a separate Generate step.
		if err := s.EnsureGenerated(k.M.UUID, actor); err != nil {
			return nil, fmt.Errorf("keysvc: generate key %s: %w", k.Name, err)
		}
		if !seenOwner[u.M.UUID] {
			seenOwner[u.M.UUID] = true
			owners = append(owners, u.M.UUID)
		}
	}
	if len(owners) == 0 {
		return nil, ErrNoRecipients
	}
	set := &model.GlobalSet{
		M:                model.Meta{UUID: store.NewID()},
		Name:             name,
		MachineID:        s.localMachineID,
		RecipientUserIDs: owners,
	}
	if err := s.store.GlobalSets.Put(set); err != nil {
		return nil, fmt.Errorf("keysvc: save global set: %w", err)
	}
	if r, err := s.resolveSet(set.M.UUID); err == nil {
		_ = s.ensureSetDirs(r)
	}
	_ = s.audit.Record(actor, "global_set_create", name, audit.OK, fmt.Sprintf("%d reader(s)", len(owners)))
	return set, nil
}

// DeleteGlobalSet removes a set record and its on-disk copies (best effort).
func (s *Service) DeleteGlobalSet(setID, actor string) error {
	set, err := s.store.GlobalSets.Get(setID)
	if err != nil {
		return err
	}
	if r, err := s.resolveSet(setID); err == nil {
		for _, d := range r.dirs {
			_ = os.RemoveAll(d)
		}
	}
	if err := s.store.GlobalSets.Delete(setID); err != nil {
		return err
	}
	_ = s.audit.Record(actor, "global_set_delete", set.Name, audit.OK, "")
	return nil
}

// ListGlobalSecrets returns the NAMES in a set, sorted. Empty with no error means
// none yet.
func (s *Service) ListGlobalSecrets(setID string) ([]string, error) {
	r, err := s.resolveSet(setID)
	if err != nil {
		return nil, err
	}
	return keys.ListSecretNames(r.primaryDir, r.priv)
}

// SetGlobalSecret sets name=value in a set (creating the encrypted file on first
// use) and re-encrypts, then syncs the copy to every recipient. The VALUE is never
// logged or audited; the audit row records the set + NAME only.
func (s *Service) SetGlobalSecret(setID, name, value, actor string) error {
	r, err := s.resolveSet(setID)
	if err != nil {
		return err
	}
	if err := s.ensureSetDirs(r); err != nil {
		return err
	}
	target := r.set.Name + " / " + name
	if err := keys.SetSecret(r.primaryDir, name, value, r.priv); err != nil {
		_ = s.audit.Record(actor, "global_secret_set", target, audit.Failed, "")
		return err
	}
	if err := s.syncSet(r); err != nil {
		_ = s.audit.Record(actor, "global_secret_set", target, audit.Failed, "sync")
		return err
	}
	_ = s.audit.Record(actor, "global_secret_set", target, audit.OK, "")
	return nil
}

// RevealGlobalSecret decrypts ONE value for display and records a
// global_secret_reveal audit event by NAME (never the value).
func (s *Service) RevealGlobalSecret(setID, name, actor string) (string, error) {
	r, err := s.resolveSet(setID)
	if err != nil {
		return "", err
	}
	target := r.set.Name + " / " + name
	v, err := keys.GetSecretValue(r.primaryDir, name, r.priv)
	if err != nil {
		_ = s.audit.Record(actor, "global_secret_reveal", target, audit.Failed, "")
		return "", err
	}
	_ = s.audit.Record(actor, "global_secret_reveal", target, audit.OK, "")
	return v, nil
}

// DeleteGlobalSecret removes a secret from a set and re-syncs every copy.
func (s *Service) DeleteGlobalSecret(setID, name, actor string) error {
	r, err := s.resolveSet(setID)
	if err != nil {
		return err
	}
	target := r.set.Name + " / " + name
	if err := keys.UnsetSecret(r.primaryDir, name, r.priv); err != nil {
		_ = s.audit.Record(actor, "global_secret_delete", target, audit.Failed, "")
		return err
	}
	if err := s.syncSet(r); err != nil {
		_ = s.audit.Record(actor, "global_secret_delete", target, audit.Failed, "sync")
		return err
	}
	_ = s.audit.Record(actor, "global_secret_delete", target, audit.OK, "")
	return nil
}
