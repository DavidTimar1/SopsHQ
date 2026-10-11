package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sopshq/internal/update"
)

func TestKeygenWritesSeedPrivatelyAndNeverPrintsIt(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed.hex")
	pubPath := filepath.Join(dir, "pub.hex")
	var out bytes.Buffer
	if err := run([]string{"keygen", "-seed-out", seedPath, "-pub-out", pubPath}, &out, os.Getenv); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	seed, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), strings.TrimSpace(string(seed))) {
		t.Fatal("keygen printed the private seed")
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(seedPath); fi.Mode().Perm() != 0o600 {
			t.Fatalf("seed file mode = %o, want 0600", fi.Mode().Perm())
		}
	}
	sk, err := update.PrivateKeyFromSeedHex(string(seed))
	if err != nil {
		t.Fatalf("the written seed does not load: %v", err)
	}
	pubText, _ := os.ReadFile(pubPath)
	pub, err := update.ParsePublicKey(string(pubText))
	if err != nil || !pub.Equal(sk.PublicKey()) {
		t.Fatalf("the written public key does not match the seed: %v", err)
	}
	// A second run must not clobber the seed or replace a key that is already set.
	if err := run([]string{"keygen", "-seed-out", seedPath, "-pub-out", pubPath}, &out, os.Getenv); err == nil {
		t.Fatal("keygen overwrote an existing key")
	}
	if again, _ := os.ReadFile(seedPath); !bytes.Equal(again, seed) {
		t.Fatal("the seed file changed on a refused second run")
	}
}

// pipeline runs sums then sign the way the release job does, with the embedded key
// replaced by pub.
func pipeline(t *testing.T, seed string, keys update.Keys) (dir string, err error) {
	t.Helper()
	old := embeddedKeys
	embeddedKeys = func() (update.Keys, error) { return keys, nil }
	t.Cleanup(func() { embeddedKeys = old })

	dir = t.TempDir()
	bin := filepath.Join(dir, "sopshq-linux-amd64")
	if err := os.WriteFile(bin, []byte("binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	sums, sig := filepath.Join(dir, "SHA256SUMS"), filepath.Join(dir, "SHA256SUMS.sig")
	var out bytes.Buffer
	if err := run([]string{"sums", "-version", "0.83.0", "-out", sums, bin}, &out, os.Getenv); err != nil {
		t.Fatalf("sums: %v", err)
	}
	env := func(k string) string {
		if k == seedEnv {
			return seed
		}
		return ""
	}
	return dir, run([]string{"sign", "-in", sums, "-out", sig}, &out, env)
}

func TestSignedOutputVerifiesAsTheUpdaterWouldSeeIt(t *testing.T) {
	sk, _ := update.GenerateKey()
	dir, err := pipeline(t, update.SeedHex(sk), update.Keys{Primary: sk.PublicKey()})
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	sums, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	sig, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS.sig"))
	s, err := update.VerifySums(update.Keys{Primary: sk.PublicKey()}, sums, sig)
	if err != nil || s.Version != "0.83.0" {
		t.Fatalf("the signed release does not verify: %+v err=%v", s, err)
	}
	if err := s.CheckAsset("sopshq-linux-amd64", bytes.NewReader([]byte("binary"))); err != nil {
		t.Fatalf("the binary does not match the written checksums: %v", err)
	}
}

func TestSignRefusesASeedThatDoesNotMatchTheEmbeddedKey(t *testing.T) {
	signer, _ := update.GenerateKey()
	other, _ := update.GenerateKey()
	dir, err := pipeline(t, update.SeedHex(signer), update.Keys{Primary: other.PublicKey(), Next: other.PublicKey()})
	if err == nil || !strings.Contains(err.Error(), "matches neither") {
		t.Fatalf("err = %v, want a refusal that the seed and embedded key differ", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "SHA256SUMS.sig")); statErr == nil {
		t.Fatal("a signature was written for a key no binary embeds")
	}
}

func TestSignRefusesAMissingOrBadSeedWithoutEchoingIt(t *testing.T) {
	if err := cmdSign(nil, &bytes.Buffer{}, func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), seedEnv) {
		t.Fatalf("err = %v, want the missing variable named", err)
	}
	bad := strings.Repeat("ab", 5)
	err := cmdSign(nil, &bytes.Buffer{}, func(string) string { return bad })
	if err == nil || strings.Contains(err.Error(), bad) {
		t.Fatalf("err = %v, want a refusal that does not echo the seed", err)
	}
}

func TestSignAcceptsASeedThatMatchesTheNextKey(t *testing.T) {
	primary, _ := update.GenerateKey()
	next, _ := update.GenerateKey()
	dir, err := pipeline(t, update.SeedHex(next), update.Keys{Primary: primary.PublicKey(), Next: next.PublicKey()})
	if err != nil {
		t.Fatalf("a seed matching the next key was refused: %v", err)
	}
	sums, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	sig, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS.sig"))
	if _, err := update.VerifySums(update.Keys{Primary: primary.PublicKey(), Next: next.PublicKey()}, sums, sig); err != nil {
		t.Fatalf("the next-key signature does not verify: %v", err)
	}
}

func TestKeygenRequiresASeedPathOutsideAnyGitWorkTree(t *testing.T) {
	var out bytes.Buffer
	pub := filepath.Join(t.TempDir(), "pub.hex")
	if err := run([]string{"keygen", "-pub-out", pub}, &out, os.Getenv); err == nil || !strings.Contains(err.Error(), "-seed-out is required") {
		t.Fatalf("err = %v, want -seed-out to be required", err)
	}
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	seed := filepath.Join(repo, "sub", "seed.hex")
	if err := run([]string{"keygen", "-seed-out", seed, "-pub-out", pub}, &out, os.Getenv); err == nil || !strings.Contains(err.Error(), "git work tree") {
		t.Fatalf("err = %v, want a refusal for a seed path inside a git work tree", err)
	}
	if _, err := os.Stat(pub); err == nil {
		t.Fatal("a public key was written although the seed path was refused")
	}
}

func TestKeygenNextSlotWritesTheNextFileHeader(t *testing.T) {
	dir := t.TempDir()
	pub := filepath.Join(dir, "next.hex")
	var out bytes.Buffer
	if err := run([]string{"keygen", "-slot", "next", "-seed-out", filepath.Join(dir, "seed.hex"), "-pub-out", pub}, &out, os.Getenv); err != nil {
		t.Fatal(err)
	}
	text, _ := os.ReadFile(pub)
	if !strings.Contains(string(text), "NEXT release signing") {
		t.Fatalf("the next-slot file has the wrong header:\n%s", text)
	}
	if err := run([]string{"keygen", "-slot", "other", "-seed-out", filepath.Join(dir, "s2.hex")}, &out, os.Getenv); err == nil {
		t.Fatal("an unknown slot was accepted")
	}
}
