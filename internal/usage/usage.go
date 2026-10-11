// Package usage records BEST-EFFORT key-usage (decryption) events.
//
// SopsHQ is a control plane, not a decrypt gateway: once a key is placed, sops
// decrypts locally with no involvement from SopsHQ. So usage cannot be observed
// authoritatively. This log captures only events that a machine voluntarily
// REPORTS - typically from an opt-in `sops` wrapper (a shim) that posts each
// invocation. It is therefore best-effort and bypassable, and it is intentionally
// NOT replicated (a replicated last-writer-wins counter would lose increments);
// each node keeps its own log.
//
// SECURITY: an event records who ran sops, on which file, and a source label -
// NEVER any key material.
package usage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Event is one reported key-usage (decrypt) occurrence.
type Event struct {
	Time   int64  `json:"time"` // Unix seconds
	User   string `json:"user"`
	Path   string `json:"path"`             // file or dir the operation targeted
	KeyID  string `json:"key_id,omitempty"` // explicit key, if the reporter knew it
	Source string `json:"source"`           // e.g. "sops-shim"
}

// Log is a goroutine-safe append-only usage log.
type Log struct {
	path string
	now  func() time.Time
	mu   sync.Mutex
}

// Open returns a Log backed by path.
func Open(path string) *Log { return &Log{path: path, now: time.Now} }

// Record appends a usage event, stamping the time if unset.
func (l *Log) Record(ev Event) error {
	if ev.Time == 0 {
		ev.Time = l.now().Unix()
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("usage: marshal: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("usage: open: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("usage: write: %w", err)
	}
	return nil
}

// All returns every recorded event in chronological (file) order.
func (l *Log) All() ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("usage: open: %w", err)
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return nil, fmt.Errorf("usage: parse: %w", err)
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("usage: scan: %w", err)
	}
	return out, nil
}

// Recent returns up to limit most-recent events, newest first.
func (l *Log) Recent(limit int) ([]Event, error) {
	all, err := l.All()
	if err != nil {
		return nil, err
	}
	out := make([]Event, 0, limit)
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, all[i])
	}
	return out, nil
}
