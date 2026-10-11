package hlc

import (
	"testing"
	"time"
)

func TestNowStrictlyIncreasingEvenWhenWallStuck(t *testing.T) {
	fixed := time.UnixMilli(1_000_000)
	c := newWith("nodeA", func() time.Time { return fixed })
	prev := c.Now()
	for i := 0; i < 100; i++ {
		cur := c.Now()
		if !cur.After(prev) {
			t.Fatalf("timestamp not strictly increasing: %s then %s", prev, cur)
		}
		prev = cur
	}
}

func TestNowTracksWallTime(t *testing.T) {
	now := time.UnixMilli(2_000_000)
	c := newWith("nodeA", func() time.Time { return now })
	a := c.Now()
	now = time.UnixMilli(2_000_005)
	b := c.Now()
	if b.Wall != 2_000_005 || b.Logical != 0 {
		t.Fatalf("expected wall to advance and logical reset, got %s", b)
	}
	if !b.After(a) {
		t.Fatal("later wall time should sort after")
	}
}

func TestUpdateMergesRemote(t *testing.T) {
	local := time.UnixMilli(1000)
	c := newWith("nodeA", func() time.Time { return local })
	// Remote event from the future relative to our wall clock.
	remote := Timestamp{Wall: 5000, Logical: 7, Node: "nodeB"}
	merged := c.Update(remote)
	if merged.Wall != 5000 {
		t.Fatalf("merged wall should adopt remote future: %s", merged)
	}
	if !merged.After(remote) {
		t.Fatalf("after Update, local clock must be causally after remote: %s vs %s", merged, remote)
	}
	// Subsequent Now must be after the merged value too.
	next := c.Now()
	if !next.After(merged) {
		t.Fatalf("Now after Update must advance: %s vs %s", next, merged)
	}
}

func TestCompareTiebreakByNode(t *testing.T) {
	a := Timestamp{Wall: 10, Logical: 2, Node: "nodeA"}
	b := Timestamp{Wall: 10, Logical: 2, Node: "nodeB"}
	if a.Compare(b) != -1 || b.Compare(a) != 1 {
		t.Fatal("equal wall+logical should tiebreak by node id")
	}
	if a.Compare(a) != 0 {
		t.Fatal("identical timestamps should compare equal")
	}
}
