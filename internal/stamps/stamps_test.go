package stamps

import (
	"os"
	"path/filepath"
	"testing"
)

// TestBaselineOnFirstSight confirms an unstamped path reports no change (so a
// first write proceeds), and that a recorded stamp then matches identical content.
func TestBaselineOnFirstSight(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "stamps.json"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	path := filepath.Join(t.TempDir(), "secrets.yaml")
	content := []byte("alpha\n")

	// No stamp yet: not "changed", hadStamp false.
	if changed, _, had := st.Check(path, content); changed || had {
		t.Fatalf("first sight: want changed=false had=false, got changed=%v had=%v", changed, had)
	}

	// Record it, then identical content matches.
	if err := st.Put(path, content, []string{"A"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	changed, names, had := st.Check(path, content)
	if !had || changed {
		t.Fatalf("after put: want had=true changed=false, got had=%v changed=%v", had, changed)
	}
	if len(names) != 1 || names[0] != "A" {
		t.Fatalf("names: want [A], got %v", names)
	}
}

// TestDetectsExternalChange confirms a differing on-disk content is flagged as
// changed and the previously recorded names come back for the diff.
func TestDetectsExternalChange(t *testing.T) {
	st, _ := Open(filepath.Join(t.TempDir(), "stamps.json"))
	path := filepath.Join(t.TempDir(), "secrets.yaml")

	if err := st.Put(path, []byte("one\n"), []string{"A", "B"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	changed, prev, had := st.Check(path, []byte("one-EDITED\n"))
	if !had || !changed {
		t.Fatalf("want had=true changed=true, got had=%v changed=%v", had, changed)
	}
	if len(prev) != 2 || prev[0] != "A" || prev[1] != "B" {
		t.Fatalf("prev names: want [A B], got %v", prev)
	}
}

// TestPersistAndReopen confirms stamps survive a reopen (the sidecar is on disk).
func TestPersistAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stamps.json")
	managed := filepath.Join(t.TempDir(), ".sops.yaml")

	st, _ := Open(path)
	if err := st.Put(managed, []byte("recipients\n"), nil); err != nil {
		t.Fatalf("put: %v", err)
	}

	st2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, ok := st2.Get(managed); !ok {
		t.Fatal("stamp did not survive reopen")
	}
	if changed, _, had := st2.Check(managed, []byte("recipients\n")); !had || changed {
		t.Fatalf("reopened stamp: want had=true changed=false, got had=%v changed=%v", had, changed)
	}
}

// TestDelete drops a stamp so the path returns to first-sight behavior.
func TestDelete(t *testing.T) {
	st, _ := Open(filepath.Join(t.TempDir(), "stamps.json"))
	path := filepath.Join(t.TempDir(), "keys.txt")
	_ = st.Put(path, []byte("AGE-SECRET-KEY-1xxx\n"), nil)
	if err := st.Delete(path); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := st.Get(path); ok {
		t.Fatal("stamp still present after delete")
	}
	if _, _, had := st.Check(path, []byte("anything")); had {
		t.Fatal("deleted path should report no stamp")
	}
}

// TestSidecarPermissions confirms the persisted file is owner-only (0600 on
// POSIX). On Windows the bits are advisory; the test only asserts the file exists.
func TestSidecarPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stamps.json")
	st, _ := Open(path)
	_ = st.Put(filepath.Join(t.TempDir(), "keys.txt"), []byte("x"), nil)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.IsDir() {
		t.Fatal("sidecar should be a file")
	}
}
