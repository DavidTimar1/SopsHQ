package permmap

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"sopshq/internal/seal"
)

// Snapshot is one complete scan: when it ran, which roots it covered, and every
// collected Entry. It is the unit the Store persists (latest + baseline).
type Snapshot struct {
	ScannedAt time.Time `json:"scanned_at"`
	Roots     []string  `json:"roots"`
	Entries   []Entry   `json:"-"` // streamed as JSONL lines, not nested in the header
}

// snapHeader is the first JSONL line of a stored snapshot: the scan metadata and
// the entry count. It has no "path" field, which distinguishes it from the Entry
// lines that follow when reading.
type snapHeader struct {
	ScannedAt time.Time `json:"scanned_at"`
	Roots     []string  `json:"roots"`
	Count     int       `json:"count"`
}

// Store persists the permission map's machine-local snapshots: the latest scan
// and the operator-set baseline. Each is written as gzip-compressed JSONL and
// then VAULT-SEALED (AES-256-GCM via seal.Crypter), so the on-disk file is
// unreadable without the unlocked vault. The data reveals the full filesystem
// layout and who can access what, so it is machine-local and NEVER flows through
// the replicating record store.
type Store struct {
	dir string
	cr  *seal.Crypter
}

const (
	latestFile   = "latest.jsonl.gz.sealed"
	baselineFile = "baseline.jsonl.gz.sealed"
)

// OpenStore prepares the permission-map storage under <dataDir>/permmap, creating
// the directory (0700) if needed. cr seals and opens every snapshot file; it must
// be derived from the unlocked vault (see vault.DeriveStoreKey).
func OpenStore(dataDir string, cr *seal.Crypter) (*Store, error) {
	if cr == nil {
		return nil, fmt.Errorf("permmap: nil crypter")
	}
	dir := filepath.Join(dataDir, "permmap")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("permmap: mkdir: %w", err)
	}
	return &Store{dir: dir, cr: cr}, nil
}

// WriteLatest stores snap as the latest scan, replacing any previous one.
func (s *Store) WriteLatest(snap *Snapshot) error { return s.write(latestFile, snap) }

// WriteBaseline stores snap as the reference baseline the daily drift diffs
// against. The operator sets it deliberately.
func (s *Store) WriteBaseline(snap *Snapshot) error { return s.write(baselineFile, snap) }

// ReadLatest returns the latest stored scan, or (nil, nil) when none exists yet.
func (s *Store) ReadLatest() (*Snapshot, error) { return s.read(latestFile) }

// ReadBaseline returns the stored baseline, or (nil, nil) when none exists yet.
func (s *Store) ReadBaseline() (*Snapshot, error) { return s.read(baselineFile) }

// PromoteLatestToBaseline copies the current latest scan into the baseline slot.
// It errors when there is no latest scan to promote.
func (s *Store) PromoteLatestToBaseline() error {
	snap, err := s.ReadLatest()
	if err != nil {
		return err
	}
	if snap == nil {
		return fmt.Errorf("permmap: no scan to set as baseline")
	}
	return s.WriteBaseline(snap)
}

// write encodes snap to gzip-JSONL, seals it, and writes it atomically (temp file
// + rename) with 0600 permissions.
func (s *Store) write(name string, snap *Snapshot) error {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	enc := json.NewEncoder(zw)
	if err := enc.Encode(snapHeader{ScannedAt: snap.ScannedAt, Roots: snap.Roots, Count: len(snap.Entries)}); err != nil {
		return fmt.Errorf("permmap: encode header: %w", err)
	}
	for i := range snap.Entries {
		if err := enc.Encode(snap.Entries[i]); err != nil {
			return fmt.Errorf("permmap: encode entry: %w", err)
		}
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("permmap: gzip close: %w", err)
	}
	sealed, err := s.cr.Seal(gz.Bytes())
	if err != nil {
		return fmt.Errorf("permmap: seal: %w", err)
	}
	path := filepath.Join(s.dir, name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		return fmt.Errorf("permmap: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("permmap: rename: %w", err)
	}
	return nil
}

// read opens a sealed gzip-JSONL snapshot file. It returns (nil, nil) when the
// file is absent, so a first run before any scan is not an error.
func (s *Store) read(name string) (*Snapshot, error) {
	blob, err := os.ReadFile(filepath.Join(s.dir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("permmap: read: %w", err)
	}
	plain, err := s.cr.Open(blob)
	if err != nil {
		return nil, fmt.Errorf("permmap: open: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return nil, fmt.Errorf("permmap: gunzip: %w", err)
	}
	defer zr.Close()

	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024) // allow long path lines
	snap := &Snapshot{}
	first := true
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if first {
			var h snapHeader
			if err := json.Unmarshal(line, &h); err != nil {
				return nil, fmt.Errorf("permmap: decode header: %w", err)
			}
			snap.ScannedAt = h.ScannedAt
			snap.Roots = h.Roots
			if h.Count > 0 {
				snap.Entries = make([]Entry, 0, h.Count)
			}
			first = false
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("permmap: decode entry: %w", err)
		}
		snap.Entries = append(snap.Entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("permmap: scan: %w", err)
	}
	return snap, nil
}
