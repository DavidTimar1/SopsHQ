package usageshim

import (
	"os"
	"strings"
	"testing"
)

func TestPrependPathIdempotent(t *testing.T) {
	sep := string(os.PathListSeparator)
	base := "a" + sep + "b"
	want := "shim" + sep + "a" + sep + "b"
	got := prependPath(base, "shim")
	if got != want {
		t.Fatalf("prependPath = %q, want %q", got, want)
	}
	if again := prependPath(got, "shim"); again != want {
		t.Fatalf("prependPath not idempotent: %q", again)
	}
}

func TestRemovePathEntry(t *testing.T) {
	sep := string(os.PathListSeparator)
	got := removePathEntry("shim"+sep+"a"+sep+"shim"+sep+"b", "shim")
	want := "a" + sep + "b"
	if got != want {
		t.Fatalf("removePathEntry = %q, want %q", got, want)
	}
}

func TestUpsertAndRemoveBlock(t *testing.T) {
	orig := "line1\nline2\n"
	withBlock := upsertBlock(orig, "export X=1")
	if !strings.Contains(withBlock, blockBegin) || !strings.Contains(withBlock, "export X=1") {
		t.Fatalf("block not inserted: %q", withBlock)
	}
	// Upsert again with a new body -> exactly one block, old body gone.
	replaced := upsertBlock(withBlock, "export Y=2")
	if strings.Count(replaced, blockBegin) != 1 {
		t.Fatalf("expected one block, got: %q", replaced)
	}
	if strings.Contains(replaced, "export X=1") || !strings.Contains(replaced, "export Y=2") {
		t.Fatalf("block not replaced cleanly: %q", replaced)
	}
	// Remove leaves the original lines and no markers.
	removed := removeBlock(replaced)
	if strings.Contains(removed, blockBegin) || strings.Contains(removed, blockEnd) {
		t.Fatalf("block not removed: %q", removed)
	}
	if !strings.Contains(removed, "line1") || !strings.Contains(removed, "line2") {
		t.Fatalf("removeBlock lost original content: %q", removed)
	}
}
