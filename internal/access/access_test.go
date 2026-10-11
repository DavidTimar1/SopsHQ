package access

import (
	"path/filepath"
	"testing"
)

// TestPermits exercises the pure Unix permission rule, including owner precedence
// (owner bits apply to the owner even when group/other are more permissive).
func TestPermits(t *testing.T) {
	cases := []struct {
		name             string
		fuid, fgid, mode uint32
		uid              int
		gids             map[int]bool
		need             uint32
		want             bool
	}{
		{"owner read+exec", 1000, 1000, 0o500, 1000, map[int]bool{1000: true}, 0o5, true},
		{"owner precedence: owner has none though group/other do", 1000, 1000, 0o077, 1000, map[int]bool{1000: true}, 0o5, false},
		{"group read+exec", 1000, 2000, 0o050, 1001, map[int]bool{2000: true}, 0o5, true},
		{"group lacks (owner-only)", 1000, 2000, 0o500, 1001, map[int]bool{2000: true}, 0o5, false},
		{"other read+exec", 1000, 2000, 0o005, 1001, map[int]bool{3000: true}, 0o5, true},
		{"other lacks", 1000, 2000, 0o050, 1001, map[int]bool{3000: true}, 0o5, false},
		{"traverse: other has x", 1000, 2000, 0o711, 1001, map[int]bool{3000: true}, 0o1, true},
		{"traverse: other no x", 1000, 2000, 0o710, 1001, map[int]bool{3000: true}, 0o1, false},
	}
	for _, c := range cases {
		if got := permits(c.fuid, c.fgid, c.mode, c.uid, c.gids, c.need); got != c.want {
			t.Errorf("%s: permits = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestAncestorPaths checks the root-first parent chain (each entry is the parent of
// the next, the last is the input).
func TestAncestorPaths(t *testing.T) {
	abs, err := filepath.Abs(filepath.Join("a", "b", "c"))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	out := ancestorPaths(abs)
	if len(out) < 2 {
		t.Fatalf("too few components: %v", out)
	}
	if out[len(out)-1] != filepath.Clean(abs) {
		t.Fatalf("last = %s, want %s", out[len(out)-1], filepath.Clean(abs))
	}
	for i := 0; i+1 < len(out); i++ {
		if filepath.Dir(out[i+1]) != out[i] {
			t.Fatalf("chain break at %d: parent(%s)=%s != %s", i, out[i+1], filepath.Dir(out[i+1]), out[i])
		}
	}
}
