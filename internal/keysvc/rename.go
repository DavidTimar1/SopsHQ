package keysvc

import (
	"errors"
	"fmt"
	"strings"

	"sopshq/internal/audit"
)

// Renaming a key changes its NAME only - the human label shown on the Keys page.
// The crypto (the public key and the sealed private key) is untouched, and every
// caller resolves a key by UUID or public key, never by name, so a rename cannot
// break placement or decryption. The new name is written into .sops.yaml as a
// per-line comment on the next Apply; drift compares public keys, not comments, so
// a rename never registers as real drift.

var (
	// ErrKeyNameEmpty means the trimmed key name is empty.
	ErrKeyNameEmpty = errors.New("keysvc: key name is required")
	// ErrKeyNameTaken means another live key already uses that name (compared
	// case-insensitively after trimming).
	ErrKeyNameTaken = errors.New("keysvc: a key with that name already exists")
)

// keyNameTaken reports whether a live (non-tombstoned) key already uses name,
// comparing case-insensitively after trimming surrounding whitespace. excludeID,
// when non-empty, is skipped so a key never collides with itself. Deleted keys are
// tombstoned and hidden by the store's List, so a deleted key's name is free to
// reuse.
func (s *Service) keyNameTaken(name, excludeID string) bool {
	name = strings.TrimSpace(name)
	for _, k := range s.store.Keys.List() {
		if k.M.UUID == excludeID {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k.Name), name) {
			return true
		}
	}
	return false
}

// RenameKey changes a key's display name (label) only. It trims newName, rejects an
// empty name with ErrKeyNameEmpty, and rejects a name already held by ANOTHER live
// key (case-insensitive) with ErrKeyNameTaken. On success it stores the key through
// Put (which stamps the HLC clock and appends to the oplog so the rename replicates)
// and audits the change by key UUID and new name. No key material is touched or
// logged.
func (s *Service) RenameKey(keyID, newName, actor string) error {
	newName = strings.TrimSpace(newName)
	if newName == "" {
		return ErrKeyNameEmpty
	}
	if s.keyNameTaken(newName, keyID) {
		return ErrKeyNameTaken
	}
	k, err := s.store.Keys.Get(keyID)
	if err != nil {
		return err
	}
	k.Name = newName
	if err := s.store.Keys.Put(k); err != nil {
		return fmt.Errorf("keysvc: save key: %w", err)
	}
	_ = s.audit.Record(actor, "key_rename", k.M.UUID, audit.OK, "renamed to "+newName)
	return nil
}
