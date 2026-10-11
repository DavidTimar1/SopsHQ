package place

import (
	"bytes"
	"os"
	"testing"
)

// TestReadCappedFileRejectsOversized proves the key-store read cap: a file larger than
// the cap is refused (not loaded whole), while a normal small file reads back intact.
// The scan/read paths (ReadPrivateKeys, the public-key scan) rely on this to skip a
// KeyBase pointed at a huge file rather than exhaust memory on every render.
func TestReadCappedFileRejectsOversized(t *testing.T) {
	base := t.TempDir()

	small := []byte("AGE-SECRET-KEY-1EXAMPLE\n")
	if err := os.WriteFile(KeyFile(base), small, 0o600); err != nil {
		t.Fatalf("write small: %v", err)
	}
	got, err := ReadCappedFile(KeyFile(base))
	if err != nil || !bytes.Equal(got, small) {
		t.Fatalf("small file should read intact: err=%v", err)
	}

	// A file just over the cap must be rejected.
	huge := bytes.Repeat([]byte("x"), maxKeystoreBytes+1)
	if err := os.WriteFile(KeyFile(base), huge, 0o600); err != nil {
		t.Fatalf("write huge: %v", err)
	}
	if _, err := ReadCappedFile(KeyFile(base)); err == nil {
		t.Fatal("expected an oversized file to be rejected")
	}
	// ReadPrivateKeys sits on the same reader, so it too refuses the oversized file
	// (the discovery loop tolerates this by skipping that user).
	if _, err := ReadPrivateKeys(base); err == nil {
		t.Fatal("ReadPrivateKeys should refuse an oversized key store")
	}
}
