// Package stamps records a SHA-384 content stamp per managed file so SopsHQ can
// tell when a file it manages was changed OUTSIDE SopsHQ between two of its own
// writes. The managed files are each project's key store (keys.txt), each
// project's .sops.yaml, and each project's secrets.yaml.
//
// It is a MACHINE-LOCAL sidecar: it is NOT part of the replicated store and NOT
// the vault. It holds only one-way content hashes plus, for a secrets.yaml, the
// set of secret NAMES last seen - never a secret value, a private key, or a
// recipient. Because the managed files live on this machine, the stamps are this
// machine's business alone and are never sent to a peer.
//
// SECURITY: a SHA-384 hash is one-way and cannot be reversed to the content, so
// stamping a keys.txt (which holds a private key) leaks nothing. Names are
// documentation, not values. Nothing here is ever logged.
package stamps

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Stamp is what SopsHQ recorded the last time it wrote a managed file.
type Stamp struct {
	// SHA384 is the hex-encoded SHA-384 of the file content at the recording.
	SHA384 string `json:"sha384"`
	// WrittenAt is the Unix-second time the stamp was recorded.
	WrittenAt int64 `json:"written_at"`
	// Names is the set of secret NAMES last seen in a secrets.yaml (sorted by the
	// caller). It is omitted for keys.txt and .sops.yaml, which diff against the
	// known desired state instead of a recorded name-set.
	Names []string `json:"names,omitempty"`
}

// Store is the machine-local stamp sidecar. All access is guarded by a RWMutex
// and every change is persisted to a JSON file with an atomic temp+rename write.
type Store struct {
	mu   sync.RWMutex
	path string
	m    map[string]Stamp
}

// key normalizes a file path into a stable map key so the same managed file maps
// to one stamp regardless of separator style or "." segments.
func key(path string) string { return filepath.Clean(path) }

// sum returns the hex SHA-384 of content. SHA-384 matches the project's hashing
// choice and is quantum-safe for content fingerprinting.
func sum(content []byte) string {
	h := sha512.Sum384(content)
	return hex.EncodeToString(h[:])
}

// Open loads the stamp sidecar at path, or starts empty if the file does not
// exist yet. A malformed file is an error (it is SopsHQ's own data and a parse
// failure should surface, not be silently discarded).
func Open(path string) (*Store, error) {
	s := &Store{path: path, m: map[string]Stamp{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("stamps: read %s: %w", path, err)
	}
	if len(raw) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(raw, &s.m); err != nil {
		return nil, fmt.Errorf("stamps: parse %s: %w", path, err)
	}
	return s, nil
}

// Get returns the recorded stamp for a managed file, if any.
func (s *Store) Get(path string) (Stamp, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.m[key(path)]
	return st, ok
}

// Put hashes content and records it as the new stamp for path, persisting the
// sidecar. names is the secret name-set for a secrets.yaml (nil otherwise).
func (s *Store) Put(path string, content []byte, names []string) error {
	st := Stamp{SHA384: sum(content), WrittenAt: time.Now().Unix(), Names: names}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key(path)] = st
	return s.save()
}

// Check reports whether the current on-disk content differs from the recorded
// stamp for path. prevNames is the recorded name-set (for a secrets.yaml diff);
// hadStamp is false when SopsHQ has never stamped this path, in which case the
// caller treats the current content as a baseline and proceeds.
func (s *Store) Check(path string, current []byte) (changed bool, prevNames []string, hadStamp bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.m[key(path)]
	if !ok {
		return false, nil, false
	}
	return sum(current) != st.SHA384, st.Names, true
}

// Delete drops the stamp for a managed file (e.g. when the file is removed),
// persisting the sidecar. Deleting an absent path is a no-op.
func (s *Store) Delete(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[key(path)]; !ok {
		return nil
	}
	delete(s.m, key(path))
	return s.save()
}

// save writes the sidecar to disk atomically (temp file + rename, 0600). The
// caller holds the write lock.
func (s *Store) save() error {
	b, err := json.MarshalIndent(s.m, "", "  ")
	if err != nil {
		return fmt.Errorf("stamps: marshal: %w", err)
	}
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("stamps: mkdir: %w", err)
		}
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("stamps: write: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("stamps: rename: %w", err)
	}
	return nil
}
