//go:build linux

package place

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

// TestPlaceDiscoverySelfOnly proves the self-only discovery gate on Linux: a placement
// for the process user itself wires the ~/.bashrc export and the ~/.config/sops/age
// symlink in that home, while a placement for a DIFFERENT user writes only the key store
// and never touches a home. It cannot create a second real OS account (needed for the
// ACL grant), so it exercises the discovery-skip decision with no KeybaseRoot; the full
// live cross-user ACL proof needs a second real account and is not run here.
func TestPlaceDiscoverySelfOnly(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skipf("cannot resolve current user: %v", err)
	}

	// Enable the real discovery side effects for this test only (TestMain disables them
	// for the whole binary); restore afterward so no later test writes to a home.
	prev := effectsDisabled
	effectsDisabled = false
	t.Cleanup(func() { effectsDisabled = prev })

	const recip = "age1exampleexampleexampleexampleexampleexampleexampleex"
	const priv = "AGE-SECRET-KEY-1EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE"

	// --- Self placement: discovery IS wired in the (temp) home. ---
	selfHome := t.TempDir()
	t.Setenv("HOME", selfHome)
	selfBase := filepath.Join(t.TempDir(), "self")
	if err := Place(Opts{Base: selfBase, Recipient: recip, Private: priv}); err != nil {
		t.Fatalf("self Place: %v", err)
	}
	if _, err := os.Stat(KeyFile(selfBase)); err != nil {
		t.Fatalf("self placement must write keys.txt: %v", err)
	}
	if _, err := os.Stat(filepath.Join(selfHome, ".bashrc")); err != nil {
		t.Fatalf("self placement must write ~/.bashrc: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(selfHome, ".config", "sops", "age", "keys.txt")); err != nil {
		t.Fatalf("self placement must write the ~/.config/sops/age symlink: %v", err)
	}

	// --- Cross-user placement: key store written, NO home touched. ---
	otherHome := t.TempDir()
	t.Setenv("HOME", otherHome) // any stray discovery write would land here
	otherBase := filepath.Join(t.TempDir(), "other")
	target := bareUsername(cur.Username) + "-not-a-real-account"
	if err := Place(Opts{Base: otherBase, Recipient: recip, Private: priv, Username: target}); err != nil {
		t.Fatalf("cross-user Place should write the key store and skip discovery: %v", err)
	}
	if _, err := os.Stat(KeyFile(otherBase)); err != nil {
		t.Fatalf("cross-user placement must still write keys.txt: %v", err)
	}
	if _, err := os.Stat(filepath.Join(otherHome, ".bashrc")); !os.IsNotExist(err) {
		t.Fatalf("cross-user placement must NOT write ~/.bashrc (stat err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(otherHome, ".config")); !os.IsNotExist(err) {
		t.Fatalf("cross-user placement must NOT create ~/.config (stat err=%v)", err)
	}
}

// TestInspectDiscoveryNotApplicableCrossUser proves the read-only inspector reports N/A
// for a cross-user keystore WITHOUT reading the target user's home, and does not raise a
// permission error.
func TestInspectDiscoveryNotApplicableCrossUser(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skipf("cannot resolve current user: %v", err)
	}
	target := bareUsername(cur.Username) + "-not-a-real-account"
	st := InspectDiscovery(Opts{Base: filepath.Join(t.TempDir(), target), Username: target})
	if st.Verdict != VerdictNotApplicable {
		t.Fatalf("cross-user InspectDiscovery verdict = %q, want %q", st.Verdict, VerdictNotApplicable)
	}

	rep := EnsureDiscovery(Opts{Base: filepath.Join(t.TempDir(), target), Username: target})
	if rep.HasError() || rep.HasConflict() {
		t.Fatalf("cross-user EnsureDiscovery should be benign, got %+v", rep.Items)
	}
	if len(rep.Items) != 1 || rep.Items[0].State != DiscoveryNotApplicable {
		t.Fatalf("cross-user EnsureDiscovery = %+v, want one not-applicable item", rep.Items)
	}
}
