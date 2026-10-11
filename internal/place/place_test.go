package place

import (
	"os"
	"os/user"
	"strings"
	"testing"
)

// TestIsSelfPlacement checks the self-placement predicate that gates home discovery
// wiring: an empty username is self; the current process user is self; a different user
// is not. Cross-platform (Windows compares case-insensitively and ignores a DOMAIN\
// prefix, Linux is exact), so it asserts only the three-way truth table.
func TestIsSelfPlacement(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skipf("cannot resolve current user: %v", err)
	}

	if self, err := isSelfPlacement(Opts{Username: ""}); err != nil || !self {
		t.Fatalf("empty username should be self (self=%v err=%v)", self, err)
	}
	if self, err := isSelfPlacement(Opts{Username: cur.Username}); err != nil || !self {
		t.Fatalf("current username %q should be self (self=%v err=%v)", cur.Username, self, err)
	}
	if self, err := isSelfPlacement(Opts{Username: bareUsername(cur.Username) + "-not-a-real-account"}); err != nil || self {
		t.Fatalf("a different username should NOT be self (self=%v err=%v)", self, err)
	}
}

func TestWriteKeyStoreCreatesFiles(t *testing.T) {
	base := t.TempDir()
	priv := "AGE-SECRET-KEY-1EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE"
	rec := "age1exampleexampleexampleexampleexampleexampleexampleex"
	if err := WriteKeyStore(Opts{Base: base, Private: priv, Recipient: rec}); err != nil {
		t.Fatalf("WriteKeyStore: %v", err)
	}
	gotKey, err := os.ReadFile(KeyFile(base))
	if err != nil {
		t.Fatalf("read keys.txt: %v", err)
	}
	if strings.TrimSpace(string(gotKey)) != priv {
		t.Fatalf("keys.txt content mismatch: %q", gotKey)
	}
	gotPub, err := os.ReadFile(PubFile(base))
	if err != nil {
		t.Fatalf("read keys.pub: %v", err)
	}
	if strings.TrimSpace(string(gotPub)) != rec {
		t.Fatalf("keys.pub content mismatch: %q", gotPub)
	}
}

func TestWriteKeyStoreIdempotent(t *testing.T) {
	base := t.TempDir()
	o := Opts{Base: base, Private: "AGE-SECRET-KEY-1AAAA", Recipient: "age1aaaa"}
	if err := WriteKeyStore(o); err != nil {
		t.Fatalf("first write: %v", err)
	}
	// Rotate to a new key; re-running converges to the new content.
	o.Private = "AGE-SECRET-KEY-1BBBB"
	o.Recipient = "age1bbbb"
	if err := WriteKeyStore(o); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, _ := os.ReadFile(KeyFile(base))
	if strings.TrimSpace(string(got)) != "AGE-SECRET-KEY-1BBBB" {
		t.Fatalf("expected converged content, got %q", got)
	}
}

func TestWriteKeyStoreValidates(t *testing.T) {
	if err := WriteKeyStore(Opts{Base: "", Private: "x", Recipient: "y"}); err == nil {
		t.Fatal("expected error on empty base")
	}
	if err := WriteKeyStore(Opts{Base: t.TempDir()}); err == nil {
		t.Fatal("expected error on missing key material")
	}
}
