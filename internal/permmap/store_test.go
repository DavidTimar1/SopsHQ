package permmap

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"sopshq/internal/seal"
)

// testCrypter builds a Crypter from a fixed all-zero key for deterministic tests.
func testCrypter(t *testing.T) *seal.Crypter {
	t.Helper()
	cr, err := seal.New(make([]byte, seal.KeyLen))
	if err != nil {
		t.Fatalf("seal.New: %v", err)
	}
	return cr
}

func sampleEntries() []Entry {
	return []Entry{
		{Path: "/etc", Type: "d", Owner: "root", Group: "root", Mode: "0755"},
		{Path: "/etc/shadow", Type: "f", Owner: "root", Group: "shadow", Mode: "0640",
			ACL: []string{"u:alice:r--"}, HasACL: true, ACLOverride: true},
		{Path: "/tmp/world", Type: "f", Owner: "root", Group: "root", Mode: "0777",
			WorldWritable: true, Dangerous: true},
		{Path: "/usr/bin/sudo", Type: "f", Owner: "root", Group: "root", Mode: "4755",
			Setuid: true, SuidSgid: true, Dangerous: true},
	}
}

func TestStoreRoundTrip(t *testing.T) {
	st, err := OpenStore(t.TempDir(), testCrypter(t))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if got, err := st.ReadLatest(); err != nil || got != nil {
		t.Fatalf("ReadLatest before any write: got %v, %v; want nil, nil", got, err)
	}
	if got, err := st.ReadBaseline(); err != nil || got != nil {
		t.Fatalf("ReadBaseline before any write: got %v, %v; want nil, nil", got, err)
	}

	when := time.Date(2026, 6, 28, 3, 30, 0, 0, time.UTC)
	snap := &Snapshot{ScannedAt: when, Roots: []string{"/etc", "/usr"}, Entries: sampleEntries()}
	if err := st.WriteLatest(snap); err != nil {
		t.Fatalf("WriteLatest: %v", err)
	}
	got, err := st.ReadLatest()
	if err != nil {
		t.Fatalf("ReadLatest: %v", err)
	}
	if !got.ScannedAt.Equal(when) {
		t.Errorf("ScannedAt = %v, want %v", got.ScannedAt, when)
	}
	if len(got.Roots) != 2 || got.Roots[0] != "/etc" {
		t.Errorf("Roots = %v, want [/etc /usr]", got.Roots)
	}
	if len(got.Entries) != len(snap.Entries) {
		t.Fatalf("Entries len = %d, want %d", len(got.Entries), len(snap.Entries))
	}
	if got.Entries[1].Path != "/etc/shadow" || !got.Entries[1].HasACL {
		t.Errorf("entry[1] round-tripped wrong: %+v", got.Entries[1])
	}

	if err := st.PromoteLatestToBaseline(); err != nil {
		t.Fatalf("PromoteLatestToBaseline: %v", err)
	}
	base, err := st.ReadBaseline()
	if err != nil || base == nil || len(base.Entries) != len(snap.Entries) {
		t.Fatalf("ReadBaseline after promote: %v, %+v", err, base)
	}
}

func TestStoreSealedOnDisk(t *testing.T) {
	dir := t.TempDir()
	st, _ := OpenStore(dir, testCrypter(t))
	snap := &Snapshot{ScannedAt: time.Unix(0, 0).UTC(), Entries: sampleEntries()}
	if err := st.WriteLatest(snap); err != nil {
		t.Fatalf("WriteLatest: %v", err)
	}
	// A wrong-key crypter must not be able to open the sealed file.
	wrong := make([]byte, seal.KeyLen)
	wrong[0] = 1
	cr, _ := seal.New(wrong)
	bad := &Store{dir: st.dir, cr: cr}
	if _, err := bad.ReadLatest(); err == nil {
		t.Fatal("ReadLatest with wrong key: want error, got nil")
	}
}

func TestPromoteWithoutScanFails(t *testing.T) {
	st, _ := OpenStore(t.TempDir(), testCrypter(t))
	if err := st.PromoteLatestToBaseline(); err == nil {
		t.Fatal("PromoteLatestToBaseline with no scan: want error, got nil")
	}
}

func TestCompare(t *testing.T) {
	baseline := []Entry{
		{Path: "/a", Owner: "root", Group: "root", Mode: "0644"},
		{Path: "/b", Owner: "root", Group: "root", Mode: "0600"},
		{Path: "/gone", Owner: "root", Group: "root", Mode: "0700"},
	}
	latest := []Entry{
		{Path: "/a", Owner: "root", Group: "root", Mode: "0644"},                                        // unchanged
		{Path: "/b", Owner: "alice", Group: "root", Mode: "0666", WorldWritable: true, Dangerous: true}, // changed
		{Path: "/new", Owner: "root", Group: "root", Mode: "0755"},                                      // added
	}
	d := Compare(baseline, latest)
	if d.Empty() {
		t.Fatal("Compare reported empty for a real change")
	}
	if len(d.Added) != 1 || d.Added[0].Path != "/new" {
		t.Errorf("Added = %+v, want [/new]", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].Path != "/gone" {
		t.Errorf("Removed = %+v, want [/gone]", d.Removed)
	}
	if len(d.Changed) != 1 || d.Changed[0].Path != "/b" {
		t.Fatalf("Changed = %+v, want [/b]", d.Changed)
	}
	fields := map[string]AttrChange{}
	for _, a := range d.Changed[0].Attrs {
		fields[a.Field] = a
	}
	if fields["owner"].Before != "root" || fields["owner"].After != "alice" {
		t.Errorf("owner change = %+v, want root->alice", fields["owner"])
	}
	if _, ok := fields["world_writable"]; !ok {
		t.Error("expected world_writable change to be reported")
	}
	if d.Total() != 3 {
		t.Errorf("Total = %d, want 3", d.Total())
	}
}

func TestQueryAndSummarize(t *testing.T) {
	entries := sampleEntries()
	c := Summarize(entries)
	if c.Total != 4 || c.Dangerous != 2 || c.WorldWritable != 1 || c.HasACL != 1 || c.SuidSgid != 1 {
		t.Errorf("Summarize = %+v", c)
	}

	dang, total := Query(entries, FilterDangerous, "", 0)
	if total != 2 || len(dang) != 2 {
		t.Errorf("dangerous query: got %d/%d, want 2/2", len(dang), total)
	}

	// Free-text search across path/owner/group/acl.
	hits, total := Query(entries, FilterAll, "alice", 0)
	if total != 1 || hits[0].Path != "/etc/shadow" {
		t.Errorf("search alice: got %+v (total %d), want /etc/shadow", hits, total)
	}

	// Limit caps the returned slice but not the reported total.
	capped, total := Query(entries, FilterAll, "", 2)
	if len(capped) != 2 || total != 4 {
		t.Errorf("limit 2: got %d shown, %d total; want 2, 4", len(capped), total)
	}
}

func TestEnableInstructions(t *testing.T) {
	out := EnableInstructions("scanbot", []string{"/etc", "/home"})
	for _, want := range []string{"useradd", "scanbot", "nologin", "getfacl", "/etc /home", "sudoers"} {
		if !strings.Contains(out, want) {
			t.Errorf("EnableInstructions missing %q in:\n%s", want, out)
		}
	}
	// A blank user name falls back to the default rather than emitting an empty name.
	if !strings.Contains(EnableInstructions("", nil), "sopshq-scan") {
		t.Error("EnableInstructions with blank user should use the default name")
	}
}

func TestCheckScanUserOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("CheckScanUser probes real accounts on Linux")
	}
	st := CheckScanUser("anyone")
	if st.Platform || st.Usable {
		t.Errorf("off Linux: Platform/Usable should be false, got %+v", st)
	}
	if st.Detail == "" {
		t.Error("off Linux: expected a Detail explanation")
	}
}
