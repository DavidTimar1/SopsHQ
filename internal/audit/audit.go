// Package audit provides an append-only audit log for SopsHQ.
//
// Every consequential action -- login, key create/rotate/delete, assignment
// change, a push to a machine, a replication conflict -- is recorded here with
// who did it, what they touched, on which node, and the outcome. The log is
// append-only JSONL so it is cheap to write and tamper-evident by inspection.
//
// SECURITY: audit entries reference keys and users by name/UUID only. NEVER pass
// a private key, passphrase, or TOTP secret into Detail. At rest the whole log
// is AES-256-GCM sealed under a vault-derived key (see seal + vault), so it is
// only readable after the operator unlocks the vault; it is never encrypted with
// a secret value itself.
package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"sopshq/internal/seal"
)

// Outcome is the result of an audited action.
type Outcome string

const (
	OK     Outcome = "ok"
	Failed Outcome = "failed"
	Denied Outcome = "denied"
)

// Entry is one audit record.
type Entry struct {
	Time    int64   `json:"time"` // Unix seconds
	Actor   string  `json:"actor"`
	Action  string  `json:"action"`
	Target  string  `json:"target"`
	Node    string  `json:"node"`
	Outcome Outcome `json:"outcome"`
	Detail  string  `json:"detail,omitempty"`
}

// Log is a goroutine-safe append-only audit log.
type Log struct {
	path    string
	node    string
	now     func() time.Time
	crypter *seal.Crypter // nil -> plaintext JSONL (tests/migration)
	mu      sync.Mutex
}

// Open returns a Log writing to path, tagging entries with the given node id.
//
// cr is the at-rest crypter: when non-nil (production passes a vault-derived
// key, see vault.DeriveStoreKey + seal.New) the whole log is AES-256-GCM sealed
// on every write and opened on read, and an existing plaintext log is rewritten
// sealed on the first append. When cr is nil the log is plain JSONL (tests and
// the one-way migration path).
func Open(path, node string, cr *seal.Crypter) *Log {
	return &Log{path: path, node: node, now: time.Now, crypter: cr}
}

// Path returns the file the audit log is written to.
func (l *Log) Path() string { return l.path }

// Record appends an entry. Errors are returned but callers usually log-and-go:
// auditing must not block the primary action.
func (l *Log) Record(actor, action, target string, outcome Outcome, detail string) error {
	e := Entry{
		Time:    l.now().Unix(),
		Actor:   actor,
		Action:  action,
		Target:  target,
		Node:    l.node,
		Outcome: outcome,
		Detail:  detail,
	}
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// Whole-file seal: read+decrypt the current JSONL, append the new line, and
	// atomically rewrite the (sealed) file. This also migrates a legacy plaintext
	// log forward on its first append.
	plain, err := l.readRawLocked()
	if err != nil {
		return err
	}
	plain = append(plain, line...)
	plain = append(plain, '\n')
	return l.writeRawLocked(l.path, plain)
}

// readRawLocked reads the log file and returns its plaintext JSONL bytes,
// decrypting when the file is sealed. A missing file yields no bytes and no
// error. The caller must hold l.mu.
func (l *Log) readRawLocked() ([]byte, error) {
	raw, err := os.ReadFile(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: read: %w", err)
	}
	if seal.IsSealed(raw) {
		if l.crypter == nil {
			return nil, fmt.Errorf("audit: log is sealed but the vault key is unavailable")
		}
		plain, err := l.crypter.Open(raw)
		if err != nil {
			return nil, fmt.Errorf("audit: open: %w", err)
		}
		return plain, nil
	}
	return raw, nil
}

// writeRawLocked atomically writes path from the plaintext JSONL, sealing it when
// a crypter is present (temp file + rename, mode 0600). The caller must hold l.mu.
func (l *Log) writeRawLocked(path string, plain []byte) error {
	out := plain
	if l.crypter != nil {
		sealed, err := l.crypter.Seal(plain)
		if err != nil {
			return fmt.Errorf("audit: seal: %w", err)
		}
		out = sealed
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("audit: rename: %w", err)
	}
	return nil
}

// Recent returns up to limit most-recent entries, newest first.
func (l *Log) Recent(limit int) ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.readAllLocked()
	if err != nil {
		return nil, err
	}
	// Reverse into newest-first, capped at limit.
	out := make([]Entry, 0, limit)
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, all[i])
	}
	return out, nil
}

// readAllLocked returns every entry in file order (oldest first). A missing file
// yields no entries and no error. The caller must hold l.mu.
func (l *Log) readAllLocked() ([]Entry, error) {
	plain, err := l.readRawLocked()
	if err != nil {
		return nil, err
	}
	var all []Entry
	sc := bufio.NewScanner(bytes.NewReader(plain))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("audit: parse: %w", err)
		}
		all = append(all, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("audit: scan: %w", err)
	}
	return all, nil
}

// writeJSONL atomically rewrites path to contain exactly entries as JSONL,
// sealing the file when a crypter is present (temp file + rename, mode 0600). An
// empty slice writes (and atomically installs) an empty - but still sealed -
// file. The caller must hold l.mu.
func (l *Log) writeJSONL(path string, entries []Entry) error {
	var buf bytes.Buffer
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("audit: marshal: %w", err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return l.writeRawLocked(path, buf.Bytes())
}

// Count returns how many entries the log currently holds.
func (l *Log) Count() (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.readAllLocked()
	if err != nil {
		return 0, err
	}
	return len(all), nil
}

// PurgeAll removes every entry, atomically truncating the log to empty. It
// returns how many entries were removed.
func (l *Log) PurgeAll() (removed int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.readAllLocked()
	if err != nil {
		return 0, err
	}
	if len(all) == 0 {
		return 0, nil
	}
	if err := l.writeJSONL(l.path, nil); err != nil {
		return 0, err
	}
	return len(all), nil
}

// PurgeBefore removes entries whose timestamp is on or before t and keeps the
// rest, rewriting the log atomically. The cutoff is INCLUSIVE (e.Time <= t) at
// one-second resolution, since entries are stamped in Unix seconds: an entry in
// the same second as t is removed. It returns how many entries were removed.
func (l *Log) PurgeBefore(t time.Time) (removed int, err error) {
	cutoff := t.Unix()
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.readAllLocked()
	if err != nil {
		return 0, err
	}
	kept := make([]Entry, 0, len(all))
	for _, e := range all {
		if e.Time <= cutoff {
			removed++
			continue
		}
		kept = append(kept, e)
	}
	if removed == 0 {
		return 0, nil
	}
	if err := l.writeJSONL(l.path, kept); err != nil {
		return 0, err
	}
	return removed, nil
}

// ExportBefore writes the entries that PurgeBefore(t) would remove (timestamp on
// or before t, same inclusive one-second rule) to destPath, atomically (temp
// file + rename, mode 0600). The archive is sealed with the same vault-derived
// key as the live log when one is configured, so an exported archive is only
// readable after the vault is unlocked, consistent with the log itself. It does
// NOT modify the log: a caller archives with ExportBefore and then deletes with
// PurgeBefore. It returns how many entries were written (zero writes an empty
// file).
func (l *Log) ExportBefore(t time.Time, destPath string) (written int, err error) {
	cutoff := t.Unix()
	l.mu.Lock()
	defer l.mu.Unlock()
	all, err := l.readAllLocked()
	if err != nil {
		return 0, err
	}
	var out []Entry
	for _, e := range all {
		if e.Time <= cutoff {
			out = append(out, e)
		}
	}
	if err := l.writeJSONL(destPath, out); err != nil {
		return 0, err
	}
	return len(out), nil
}

// PurgeAllBy performs PurgeAll and then records the purge action by actor and
// the number of entries removed. The recorded entry carries only the count, no
// entry payload.
func (l *Log) PurgeAllBy(actor string) (removed int, err error) {
	removed, err = l.PurgeAll()
	if err != nil {
		return removed, err
	}
	if rErr := l.Record(actor, "audit_purge_all", "audit", OK, fmt.Sprintf("removed %d", removed)); rErr != nil {
		return removed, rErr
	}
	return removed, nil
}

// PurgeBeforeBy performs PurgeBefore(t) and then records the purge action by
// actor, the number of entries removed, and the cutoff. The recorded entry
// carries only the count and cutoff, no entry payload.
func (l *Log) PurgeBeforeBy(actor string, t time.Time) (removed int, err error) {
	removed, err = l.PurgeBefore(t)
	if err != nil {
		return removed, err
	}
	detail := fmt.Sprintf("removed %d on or before %s", removed, t.UTC().Format(time.RFC3339))
	if rErr := l.Record(actor, "audit_purge_before", "audit", OK, detail); rErr != nil {
		return removed, rErr
	}
	return removed, nil
}
