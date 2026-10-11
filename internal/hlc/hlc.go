// Package hlc implements a Hybrid Logical Clock.
//
// Why not just a wall-clock timestamp? SopsHQ runs multi-master across its peer
// machines, whose clocks can drift apart. If we resolved "who wrote last" purely
// by wall time, a machine with a fast clock would always win and an out-of-order
// pair of edits could be misordered. An HLC combines physical time with a logical
// counter so that:
//
//   - timestamps still track real time closely (good for humans reading logs),
//   - but causality is preserved even under clock skew, and
//   - every event gets a UNIQUE, TOTALLY ORDERED timestamp (wall, then logical,
//     then node id as the final tiebreak).
//
// This gives last-writer-wins conflict resolution a deterministic, skew-tolerant
// notion of "last".
//
// Reference: Kulkarni et al., "Logical Physical Clocks" (2014).
package hlc

import (
	"fmt"
	"sync"
	"time"
)

// Timestamp is a single HLC reading. It is comparable and JSON-friendly.
type Timestamp struct {
	// Wall is physical time in Unix milliseconds.
	Wall int64 `json:"wall"`
	// Logical is the counter that breaks ties within the same Wall value.
	Logical uint32 `json:"logical"`
	// Node is the id of the clock that produced this timestamp (final tiebreak,
	// and useful provenance).
	Node string `json:"node"`
}

// Zero reports whether t is the zero timestamp (never set).
func (t Timestamp) Zero() bool { return t.Wall == 0 && t.Logical == 0 }

// After reports whether t is strictly greater than o in the total order
// (Wall, then Logical, then Node). This is the "is t the newer write?" check
// used by last-writer-wins.
func (t Timestamp) After(o Timestamp) bool { return t.Compare(o) > 0 }

// Compare returns -1, 0, or 1 ordering t against o.
func (t Timestamp) Compare(o Timestamp) int {
	switch {
	case t.Wall != o.Wall:
		if t.Wall < o.Wall {
			return -1
		}
		return 1
	case t.Logical != o.Logical:
		if t.Logical < o.Logical {
			return -1
		}
		return 1
	case t.Node != o.Node:
		if t.Node < o.Node {
			return -1
		}
		return 1
	default:
		return 0
	}
}

// String renders a sortable, human-readable form.
func (t Timestamp) String() string {
	return fmt.Sprintf("%d.%d@%s", t.Wall, t.Logical, t.Node)
}

// Clock is a goroutine-safe HLC bound to a node id. The zero value is not
// usable; build one with New.
type Clock struct {
	node string
	now  func() time.Time
	mu   sync.Mutex
	last Timestamp
}

// New returns a Clock for the given node id using the real wall clock.
func New(node string) *Clock { return &Clock{node: node, now: time.Now} }

// newWith is used by tests to inject a controllable clock.
func newWith(node string, now func() time.Time) *Clock {
	return &Clock{node: node, now: now}
}

// Now returns the next local HLC timestamp, advancing the clock. Two calls never
// return equal timestamps from the same Clock.
func (c *Clock) Now() Timestamp {
	c.mu.Lock()
	defer c.mu.Unlock()
	physical := c.now().UnixMilli()
	if physical > c.last.Wall {
		c.last = Timestamp{Wall: physical, Logical: 0, Node: c.node}
	} else {
		// Physical time did not advance past our last reading; bump the logical
		// counter to keep timestamps strictly increasing.
		c.last = Timestamp{Wall: c.last.Wall, Logical: c.last.Logical + 1, Node: c.node}
	}
	return c.last
}

// Update merges a timestamp received from a remote node, advancing the local
// clock so subsequent Now() calls are causally after the remote event. Call this
// for every inbound replication event before applying it.
func (c *Clock) Update(remote Timestamp) Timestamp {
	c.mu.Lock()
	defer c.mu.Unlock()
	physical := c.now().UnixMilli()
	maxWall := physical
	if c.last.Wall > maxWall {
		maxWall = c.last.Wall
	}
	if remote.Wall > maxWall {
		maxWall = remote.Wall
	}
	var logical uint32
	switch {
	case maxWall == c.last.Wall && maxWall == remote.Wall:
		logical = max32(c.last.Logical, remote.Logical) + 1
	case maxWall == c.last.Wall:
		logical = c.last.Logical + 1
	case maxWall == remote.Wall:
		logical = remote.Logical + 1
	default:
		logical = 0
	}
	c.last = Timestamp{Wall: maxWall, Logical: logical, Node: c.node}
	return c.last
}

func max32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}
