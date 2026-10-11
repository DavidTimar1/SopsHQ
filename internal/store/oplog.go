package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"sopshq/internal/hlc"
	"sopshq/internal/seal"
)

// Event is one replicated mutation. The full record snapshot travels in Record
// so a peer can apply last-writer-wins without needing prior state.
//
// SECURITY NOTE: Record is the verbatim stored record. For Key records it
// contains the vault-SEALED private key (PrivSealed), never plaintext. The oplog
// is therefore safe to persist and to ship to peers that share the vault
// passphrase. Never widen this to carry opened secrets.
type Event struct {
	Seq    int64           `json:"seq"`
	Kind   string          `json:"kind"`
	UUID   string          `json:"uuid"`
	TS     hlc.Timestamp   `json:"ts"`
	Origin string          `json:"origin"`
	Record json.RawMessage `json:"record"`
}

// Oplog is an append-only JSONL log of locally originated mutations. Peers pull
// events with Seq greater than their per-peer watermark.
//
// On disk the whole log is AES-256-GCM sealed when a crypter is present: an
// append reads+decrypts the current JSONL, appends the new line, and atomically
// rewrites the sealed file. At this volume (human-driven mutations) the
// rewrite-on-append cost is negligible, and it keeps the file unreadable as
// plaintext at rest. The wire format peers exchange is unchanged: Since returns
// decrypted Events.
type Oplog struct {
	path    string
	crypter *seal.Crypter // nil -> plaintext JSONL (tests/migration)
	mu      sync.Mutex
	seq     int64
}

// OpenOplog opens (or creates) the oplog file and recovers the last sequence
// number so new appends continue monotonically. A legacy plaintext log is
// migrated forward (rewritten sealed) when a crypter is present.
func OpenOplog(path string, cr *seal.Crypter) (*Oplog, error) {
	o := &Oplog{path: path, crypter: cr}
	plain, wasSealed, err := o.readPlainLocked()
	if err != nil {
		return nil, err
	}
	if err := o.scanSeq(plain); err != nil {
		return nil, err
	}
	if !wasSealed && cr != nil && len(plain) > 0 {
		// Migrate a plaintext log forward: rewrite it sealed now.
		if err := o.writePlainLocked(plain); err != nil {
			return nil, err
		}
	}
	return o, nil
}

// scanSeq advances o.seq past the highest sequence number in the plaintext JSONL.
func (o *Oplog) scanSeq(plain []byte) error {
	sc := bufio.NewScanner(bytes.NewReader(plain))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return fmt.Errorf("oplog: parse: %w", err)
		}
		if ev.Seq > o.seq {
			o.seq = ev.Seq
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("oplog: scan: %w", err)
	}
	return nil
}

// readPlainLocked reads the oplog file and returns its plaintext JSONL bytes,
// decrypting when the file is sealed. A missing file yields (nil, false, nil).
// The caller must hold o.mu (or be in a single-threaded construction path).
func (o *Oplog) readPlainLocked() (plain []byte, wasSealed bool, err error) {
	raw, err := os.ReadFile(o.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("oplog: read: %w", err)
	}
	if seal.IsSealed(raw) {
		if o.crypter == nil {
			return nil, true, fmt.Errorf("oplog: sealed but the vault key is unavailable")
		}
		plain, err = o.crypter.Open(raw)
		if err != nil {
			return nil, true, fmt.Errorf("oplog: open: %w", err)
		}
		return plain, true, nil
	}
	return raw, false, nil
}

// writePlainLocked atomically rewrites the oplog file from the plaintext JSONL,
// sealing it when a crypter is present. The caller must hold o.mu.
func (o *Oplog) writePlainLocked(plain []byte) error {
	out := plain
	if o.crypter != nil {
		sealed, err := o.crypter.Seal(plain)
		if err != nil {
			return fmt.Errorf("oplog: seal: %w", err)
		}
		out = sealed
	}
	tmp := o.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return fmt.Errorf("oplog: write: %w", err)
	}
	if err := os.Rename(tmp, o.path); err != nil {
		return fmt.Errorf("oplog: rename: %w", err)
	}
	return nil
}

// Append assigns the next sequence number and writes the event durably.
func (o *Oplog) Append(kind, uuid string, ts hlc.Timestamp, origin string, record json.RawMessage) (Event, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seq++
	ev := Event{Seq: o.seq, Kind: kind, UUID: uuid, TS: ts, Origin: origin, Record: record}
	line, err := json.Marshal(ev)
	if err != nil {
		o.seq--
		return Event{}, fmt.Errorf("oplog: marshal: %w", err)
	}
	plain, _, err := o.readPlainLocked()
	if err != nil {
		o.seq--
		return Event{}, err
	}
	plain = append(plain, line...)
	plain = append(plain, '\n')
	if err := o.writePlainLocked(plain); err != nil {
		o.seq--
		return Event{}, err
	}
	return ev, nil
}

// Since returns all events with Seq strictly greater than after, in order. Used
// by a peer pulling changes from its last watermark.
func (o *Oplog) Since(after int64) ([]Event, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	plain, _, err := o.readPlainLocked()
	if err != nil {
		return nil, err
	}
	var out []Event
	sc := bufio.NewScanner(bytes.NewReader(plain))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return nil, fmt.Errorf("oplog: parse: %w", err)
		}
		if ev.Seq > after {
			out = append(out, ev)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("oplog: scan: %w", err)
	}
	return out, nil
}
