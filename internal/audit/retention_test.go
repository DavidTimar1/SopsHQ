package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// base is a fixed reference instant; tests stamp entries at base+offset seconds.
var base = time.Unix(1_700_000_000, 0)

// recordAt appends one entry stamped at ts by overriding the log's clock.
func recordAt(t *testing.T, l *Log, ts time.Time) {
	t.Helper()
	l.now = func() time.Time { return ts }
	if err := l.Record("actor", "act", "tgt", OK, ""); err != nil {
		t.Fatalf("Record: %v", err)
	}
}

// readJSONL parses a JSONL file into entries in file order (oldest first).
func readJSONL(t *testing.T, path string) []Entry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return out
}

// offsets returns each entry's seconds past base.
func offsets(entries []Entry) []int64 {
	out := make([]int64, len(entries))
	for i, e := range entries {
		out[i] = e.Time - base.Unix()
	}
	return out
}

func TestPurgeBeforeBoundary(t *testing.T) {
	// Three entries at base+0s, +10s, +20s; the cutoff rule is inclusive (<=).
	cases := []struct {
		name         string
		cutoffOffset time.Duration
		wantRemoved  int
		wantKept     []int64
	}{
		{"cutoff before all keeps all", -1 * time.Second, 0, []int64{0, 10, 20}},
		{"cutoff equals middle removes it (inclusive)", 10 * time.Second, 2, []int64{20}},
		{"cutoff after all removes all", 100 * time.Second, 3, []int64{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			l := Open(path, "n", nil)
			for _, off := range []int64{0, 10, 20} {
				recordAt(t, l, base.Add(time.Duration(off)*time.Second))
			}
			removed, err := l.PurgeBefore(base.Add(tc.cutoffOffset))
			if err != nil {
				t.Fatalf("PurgeBefore: %v", err)
			}
			if removed != tc.wantRemoved {
				t.Fatalf("removed = %d, want %d", removed, tc.wantRemoved)
			}
			got := offsets(readJSONL(t, path))
			if len(got) != len(tc.wantKept) {
				t.Fatalf("kept offsets = %v, want %v", got, tc.wantKept)
			}
			for i := range got {
				if got[i] != tc.wantKept[i] {
					t.Fatalf("kept offsets = %v, want %v", got, tc.wantKept)
				}
			}
			n, err := l.Count()
			if err != nil {
				t.Fatalf("Count: %v", err)
			}
			if n != len(tc.wantKept) {
				t.Fatalf("Count = %d, want %d", n, len(tc.wantKept))
			}
		})
	}
}

func TestPurgeAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := Open(path, "n", nil)
	for _, off := range []int64{0, 5, 10, 15} {
		recordAt(t, l, base.Add(time.Duration(off)*time.Second))
	}
	removed, err := l.PurgeAll()
	if err != nil {
		t.Fatalf("PurgeAll: %v", err)
	}
	if removed != 4 {
		t.Fatalf("removed = %d, want 4", removed)
	}
	n, err := l.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 0 {
		t.Fatalf("Count after purge = %d, want 0", n)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Size() != 0 {
		t.Fatalf("file size after PurgeAll = %d, want 0", fi.Size())
	}
	// A second purge over an empty log removes nothing.
	removed, err = l.PurgeAll()
	if err != nil {
		t.Fatalf("PurgeAll (empty): %v", err)
	}
	if removed != 0 {
		t.Fatalf("removed over empty log = %d, want 0", removed)
	}
}

func TestCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := Open(path, "n", nil)
	// Absent file counts as zero.
	n, err := l.Count()
	if err != nil {
		t.Fatalf("Count (absent): %v", err)
	}
	if n != 0 {
		t.Fatalf("Count on absent log = %d, want 0", n)
	}
	for i := 0; i < 3; i++ {
		recordAt(t, l, base.Add(time.Duration(i)*time.Second))
	}
	if n, err = l.Count(); err != nil || n != 3 {
		t.Fatalf("Count = %d (err %v), want 3", n, err)
	}
}

func TestExportBeforeThenPurge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	dest := filepath.Join(dir, "archive", "audit-archive.jsonl")
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		t.Fatalf("mkdir archive: %v", err)
	}
	l := Open(path, "n", nil)
	for _, off := range []int64{0, 10, 20} {
		recordAt(t, l, base.Add(time.Duration(off)*time.Second))
	}
	cutoff := base.Add(10 * time.Second)

	written, err := l.ExportBefore(cutoff, dest)
	if err != nil {
		t.Fatalf("ExportBefore: %v", err)
	}
	if written != 2 {
		t.Fatalf("written = %d, want 2", written)
	}
	// Export does not mutate the live log.
	if n, _ := l.Count(); n != 3 {
		t.Fatalf("live log Count after export = %d, want 3", n)
	}
	// The archive holds exactly the entries that PurgeBefore would remove.
	gotArchive := offsets(readJSONL(t, dest))
	if len(gotArchive) != 2 || gotArchive[0] != 0 || gotArchive[1] != 10 {
		t.Fatalf("archive offsets = %v, want [0 10]", gotArchive)
	}

	removed, err := l.PurgeBefore(cutoff)
	if err != nil {
		t.Fatalf("PurgeBefore: %v", err)
	}
	if removed != written {
		t.Fatalf("removed = %d, want %d (== written)", removed, written)
	}
	gotLive := offsets(readJSONL(t, path))
	if len(gotLive) != 1 || gotLive[0] != 20 {
		t.Fatalf("live offsets after purge = %v, want [20]", gotLive)
	}
}

func TestRewriteIsAtomicAndPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l := Open(path, "n", nil)
	for _, off := range []int64{0, 10, 20} {
		recordAt(t, l, base.Add(time.Duration(off)*time.Second))
	}
	if _, err := l.PurgeBefore(base.Add(10 * time.Second)); err != nil {
		t.Fatalf("PurgeBefore: %v", err)
	}
	// The temp file used for the atomic rename must not survive a happy path.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file lingered: stat err = %v", err)
	}
	assertPrivate(t, path)
}

func TestExportFileIsPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	dest := filepath.Join(dir, "archive.jsonl")
	l := Open(path, "n", nil)
	recordAt(t, l, base)
	if _, err := l.ExportBefore(base, dest); err != nil {
		t.Fatalf("ExportBefore: %v", err)
	}
	if _, err := os.Stat(dest + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("export temp file lingered: stat err = %v", err)
	}
	assertPrivate(t, dest)
}

// assertPrivate checks a file is owner-only (0600) on platforms with POSIX
// permission bits. Windows does not model 0600, so the check is skipped there.
func assertPrivate(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode of %s = %o, want 600", path, perm)
	}
}

func TestPurgeRecordsAction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := Open(path, "n", nil)
	for _, off := range []int64{0, 10, 20} {
		recordAt(t, l, base.Add(time.Duration(off)*time.Second))
	}
	// Restore a real clock so the recorded purge entry sorts newest.
	l.now = time.Now
	removed, err := l.PurgeBeforeBy("alice", base.Add(10*time.Second))
	if err != nil {
		t.Fatalf("PurgeBeforeBy: %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2", removed)
	}
	recent, err := l.Recent(10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(recent) != 2 {
		t.Fatalf("entries after purge = %d, want 2 (kept + purge record)", len(recent))
	}
	got := recent[0]
	if got.Action != "audit_purge_before" || got.Actor != "alice" {
		t.Fatalf("purge record wrong: %+v", got)
	}
	if got.Detail == "" {
		t.Fatalf("purge record should carry a count detail")
	}
}
