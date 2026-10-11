// Package repl implements SopsHQ's multi-master replication: each node pulls the
// other node's operation log over the agent channel (plain HTTP over Tailscale,
// authenticated by the shared transfer key) and applies the events with
// last-writer-wins.
//
// Why pull (not push)? A node's oplog contains only its OWN locally-originated
// mutations (applying a peer's event does not re-log it), so pulling a peer's
// oplog never echoes back and the two nodes converge without loops. With two
// nodes and rare, human-driven writes, eventual consistency via LWW is enough -
// no consensus protocol.
//
// SECURITY: replicated Key records carry the vault-SEALED private key, which
// travels only inside the encrypted agent channel and is opened only on a node
// that holds the same vault key. Conflicts are surfaced in the audit log,
// never silently dropped.
package repl

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"sopshq/internal/audit"
	"sopshq/internal/store"
)

// OplogSource is the peer side of replication (satisfied by *agent.Client).
type OplogSource interface {
	Oplog(since int64) ([]store.Event, error)
}

// Result summarizes one pull from a peer.
type Result struct {
	Pulled    int
	Applied   int
	Conflicts int
}

// Status reports the outcome of the most recent pull attempt for one peer, for the
// panel to display. AtUnix is 0 when no pull has been attempted this run.
type Status struct {
	AtUnix    int64
	Pulled    int
	Applied   int
	Conflicts int
	Err       string
}

// Syncer pulls peer oplogs and applies them, tracking a per-peer watermark (the
// highest peer Seq applied) so pulls resume incrementally.
type Syncer struct {
	store  *store.Store
	audit  *audit.Log
	wmPath string

	mu         sync.Mutex
	watermarks map[string]int64  // peer id -> last applied Seq
	status     map[string]Status // peer id -> last pull outcome (this run)
}

// NewSyncer builds a Syncer, loading any persisted watermarks from dataDir.
func NewSyncer(st *store.Store, a *audit.Log, dataDir string) *Syncer {
	s := &Syncer{
		store:      st,
		audit:      a,
		wmPath:     filepath.Join(dataDir, "watermarks.json"),
		watermarks: map[string]int64{},
		status:     map[string]Status{},
	}
	if b, err := os.ReadFile(s.wmPath); err == nil {
		_ = json.Unmarshal(b, &s.watermarks)
	}
	return s
}

// Status returns the most recent pull outcome for a peer (zero value if none yet).
func (s *Syncer) Status(peerID string) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status[peerID]
}

// setStatus records the outcome of a pull attempt for the panel to display.
func (s *Syncer) setStatus(peerID string, res Result, err error) {
	st := Status{AtUnix: time.Now().Unix(), Pulled: res.Pulled, Applied: res.Applied, Conflicts: res.Conflicts}
	if err != nil {
		st.Err = err.Error()
	}
	s.mu.Lock()
	s.status[peerID] = st
	s.mu.Unlock()
}

// Watermark returns the last applied Seq for a peer.
func (s *Syncer) Watermark(peerID string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.watermarks[peerID]
}

// Pull fetches a peer's events past our watermark and applies them with
// last-writer-wins. Conflicts are written to the audit log. The watermark
// advances to the highest Seq successfully processed.
func (s *Syncer) Pull(peerID, peerName string, src OplogSource) (Result, error) {
	var res Result
	since := s.Watermark(peerID)
	events, err := src.Oplog(since)
	if err != nil {
		wrapped := fmt.Errorf("repl: pull %s: %w", peerName, err)
		s.setStatus(peerID, res, wrapped)
		return res, wrapped
	}
	res.Pulled = len(events)
	// Apply in Seq order so the watermark advances monotonically.
	sort.Slice(events, func(i, j int) bool { return events[i].Seq < events[j].Seq })

	maxSeq := since
	for _, ev := range events {
		applied, conflict, err := s.store.ApplyEvent(ev)
		if err != nil {
			// A single bad event must not wedge replication; record and skip it,
			// but do not advance past it so it can be retried after a fix.
			_ = s.audit.Record("system", "replication_error", ev.Kind+":"+ev.UUID, audit.Failed, err.Error())
			break
		}
		if ev.Seq > maxSeq {
			maxSeq = ev.Seq
		}
		if applied {
			res.Applied++
		}
		if conflict {
			res.Conflicts++
			_ = s.audit.Record("system", "replication_conflict", ev.Kind+":"+ev.UUID, audit.OK,
				"last-writer-wins from "+peerName)
		}
	}
	if maxSeq > since {
		s.setWatermark(peerID, maxSeq)
	}
	s.setStatus(peerID, res, nil)
	return res, nil
}

// setWatermark records and persists the peer's last applied Seq.
func (s *Syncer) setWatermark(peerID string, seq int64) {
	s.mu.Lock()
	s.watermarks[peerID] = seq
	snapshot := make(map[string]int64, len(s.watermarks))
	for k, v := range s.watermarks {
		snapshot[k] = v
	}
	s.mu.Unlock()

	b, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return
	}
	tmp := s.wmPath + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, s.wmPath)
	}
}
