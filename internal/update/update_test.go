package update

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// release builds a signed release the way the pipeline does: a SHA256SUMS naming the
// version and the binary's hash, signed by sk.
type release struct {
	binary []byte
	sums   []byte
	sig    []byte
}

func makeRelease(t *testing.T, sk *mldsa.PrivateKey, version string, binary []byte) release {
	t.Helper()
	sum := sha256.Sum256(binary)
	sums := FormatSums(version, map[string]string{AssetName("linux", "amd64"): hex.EncodeToString(sum[:])})
	sig, err := Sign(sk, sums)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return release{binary: binary, sums: sums, sig: sig}
}

func newKey(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return sk
}

// verify runs the two-step check the updater runs: signature of SHA256SUMS, then the
// asset's hash.
func verify(keys Keys, r release) (Sums, error) {
	s, err := VerifySums(keys, r.sums, r.sig)
	if err != nil {
		return Sums{}, err
	}
	return s, s.CheckAsset(AssetName("linux", "amd64"), bytes.NewReader(r.binary))
}

func TestGoodReleaseVerifies(t *testing.T) {
	sk := newKey(t)
	r := makeRelease(t, sk, "0.83.0", []byte("the new binary"))
	s, err := verify(Keys{Primary: sk.PublicKey()}, r)
	if err != nil {
		t.Fatalf("a good release was refused: %v", err)
	}
	if s.Version != "0.83.0" {
		t.Fatalf("signed version = %q, want 0.83.0", s.Version)
	}
}

func TestTamperedSignatureRefused(t *testing.T) {
	sk := newKey(t)
	r := makeRelease(t, sk, "0.83.0", []byte("bin"))
	r.sig[len(r.sig)/2] ^= 0xff
	if _, err := verify(Keys{Primary: sk.PublicKey()}, r); err == nil {
		t.Fatal("a release with a tampered signature was accepted")
	}
}

func TestTamperedSumsRefused(t *testing.T) {
	sk := newKey(t)
	r := makeRelease(t, sk, "0.83.0", []byte("bin"))
	// An attacker rewrites the signed version to look newer; the signature no longer
	// covers the bytes.
	r.sums = bytes.Replace(r.sums, []byte("0.83.0"), []byte("9.9.9"), 1)
	if _, err := verify(Keys{Primary: sk.PublicKey()}, r); err == nil {
		t.Fatal("a release whose signed text was edited was accepted")
	}
}

func TestTamperedBinaryRefused(t *testing.T) {
	sk := newKey(t)
	r := makeRelease(t, sk, "0.83.0", []byte("the real binary"))
	r.binary = []byte("a different binary")
	_, err := verify(Keys{Primary: sk.PublicKey()}, r)
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("a tampered binary gave err = %v, want a checksum refusal", err)
	}
}

func TestWrongKeyRefused(t *testing.T) {
	r := makeRelease(t, newKey(t), "0.83.0", []byte("bin"))
	if _, err := verify(Keys{Primary: newKey(t).PublicKey()}, r); err == nil {
		t.Fatal("a release signed by another key was accepted")
	}
}

func TestEmptyKeyRefusesEverything(t *testing.T) {
	r := makeRelease(t, newKey(t), "0.83.0", []byte("bin"))
	for name, text := range map[string]string{
		"nothing":       "",
		"only comments": "# a placeholder\n\n# nothing else\n",
	} {
		keys, err := ParseKeys(text, "")
		if !errors.Is(err, ErrNoKey) {
			t.Fatalf("%s: ParseKeys err = %v, want ErrNoKey", name, err)
		}
		if _, err := verify(keys, r); !errors.Is(err, ErrNoKey) {
			t.Fatalf("%s: verify err = %v, want ErrNoKey", name, err)
		}
	}
}

func TestDamagedKeyIsNotMistakenForUnset(t *testing.T) {
	for name, text := range map[string]string{
		"not hex":    "zz11",
		"wrong size": "00ff00ff",
	} {
		if _, err := ParsePublicKey(text); err == nil || errors.Is(err, ErrNoKey) {
			t.Fatalf("%s: err = %v, want a malformed-key error that is not ErrNoKey", name, err)
		}
	}
}

func TestPublicKeyRoundTrip(t *testing.T) {
	sk := newKey(t)
	pub, err := ParsePublicKey("# comment\n" + EncodePublicKey(sk.PublicKey()) + "\n")
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !pub.Equal(sk.PublicKey()) {
		t.Fatal("public key changed across encode and parse")
	}
}

func TestSeedRoundTripSignsForSamePublicKey(t *testing.T) {
	sk := newKey(t)
	again, err := PrivateKeyFromSeedHex(" " + SeedHex(sk) + "\n")
	if err != nil {
		t.Fatalf("PrivateKeyFromSeedHex: %v", err)
	}
	if !again.PublicKey().Equal(sk.PublicKey()) {
		t.Fatal("a seed rebuilt a different key")
	}
}

func TestSeedErrorsNeverContainTheSeed(t *testing.T) {
	bad := strings.Repeat("ab", 31) // 31 bytes: wrong length
	_, err := PrivateKeyFromSeedHex(bad)
	if err == nil || strings.Contains(err.Error(), bad) {
		t.Fatalf("err = %v, want a length error that does not echo the seed", err)
	}
}

// TestEmbeddedKeyIsUnsetOrValid is the shipped-file half: whichever the operator has
// done, the embedded file must be either a placeholder or a well-formed key.
func TestEmbeddedKeyIsUnsetOrValid(t *testing.T) {
	if _, err := EmbeddedKeys(); err != nil && !errors.Is(err, ErrNoKey) {
		t.Fatalf("the embedded key file is neither a placeholder nor a valid key: %v", err)
	}
}

func TestOlderAndEqualVersionsRefused(t *testing.T) {
	cases := []struct {
		installed, candidate string
		wantErr              error
	}{
		{"0.82.0", "0.83.0", nil},
		{"0.9.0", "0.10.0", nil},
		{"0.82.0", "0.82.1", nil},
		{"0.82.0", "0.82.0", ErrNotNewer},
		{"0.83.0", "0.82.0", ErrNotNewer},
		{"1.0.0", "0.99.9", ErrNotNewer},
		{"dev", "0.83.0", ErrDevBuild},
	}
	for _, c := range cases {
		err := CheckNewer(c.installed, c.candidate)
		if !errors.Is(err, c.wantErr) {
			t.Errorf("CheckNewer(%q,%q) = %v, want %v", c.installed, c.candidate, err, c.wantErr)
		}
	}
	for _, bad := range []string{"", "1.2", "1.2.3.4", "v1.2.3", "01.2.3", "1.2.3-rc1", "1.2.x"} {
		if CheckNewer("0.1.0", bad) == nil {
			t.Errorf("CheckNewer accepted malformed candidate %q", bad)
		}
		if CheckNewer(bad, "9.9.9") == nil {
			t.Errorf("CheckNewer accepted malformed installed version %q", bad)
		}
	}
}

func TestParseSumsIsStrict(t *testing.T) {
	h := strings.Repeat("a", 64)
	good := "# version: 0.83.0\n" + h + "  sopshq-linux-amd64\n"
	if _, err := ParseSums([]byte(good)); err != nil {
		t.Fatalf("good SHA256SUMS refused: %v", err)
	}
	for name, text := range map[string]string{
		"no version header": h + "  sopshq-linux-amd64\n",
		"bad version":       "# version: latest\n" + h + "  a\n",
		"no final newline":  strings.TrimSuffix(good, "\n"),
		"malformed line":    "# version: 0.83.0\nnot a checksum\n",
		"short hash":        "# version: 0.83.0\nabcd  a\n",
		"upper-case hash":   "# version: 0.83.0\n" + strings.ToUpper(h) + "  a\n",
		"path in the name":  "# version: 0.83.0\n" + h + "  ../a\n",
		"duplicate name":    "# version: 0.83.0\n" + h + "  a\n" + h + "  a\n",
		"carriage return":   "# version: 0.83.0\r\n" + h + "  a\n",
	} {
		if _, err := ParseSums([]byte(text)); err == nil {
			t.Errorf("%s: SHA256SUMS was accepted", name)
		}
	}
}

func TestAssetWithNoSumsLineRefused(t *testing.T) {
	s, err := ParseSums(FormatSums("0.83.0", map[string]string{"sopshq-linux-amd64": strings.Repeat("0", 64)}))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckAsset("sopshq-linux-arm64", strings.NewReader("x")); err == nil {
		t.Fatal("an asset with no line in SHA256SUMS was accepted")
	}
}

func TestResolveRepoOrder(t *testing.T) {
	prompted := 0
	saved := ""
	in := func(env, cfg string, withPrompt bool) SourceInputs {
		si := SourceInputs{
			Env:        env,
			ConfigHint: "/etc/x/config.jsonc",
			Config:     func() (string, error) { return cfg, nil },
			Save:       func(r string) error { saved = r; return nil },
		}
		if withPrompt {
			si.Prompt = func() (string, error) { prompted++; return "asked/repo", nil }
		}
		return si
	}

	src, err := ResolveRepo(in("env/repo", "cfg/repo", true))
	if err != nil || src.Repo != "env/repo" || src.Origin != "environment" {
		t.Fatalf("environment must win: %+v err=%v", src, err)
	}
	src, err = ResolveRepo(in("", "cfg/repo", true))
	if err != nil || src.Repo != "cfg/repo" || src.Origin != "config" {
		t.Fatalf("config must come second: %+v err=%v", src, err)
	}
	if prompted != 0 || saved != "" {
		t.Fatalf("prompted %d times and saved %q while a value was already set", prompted, saved)
	}
	src, err = ResolveRepo(in("", "", true))
	if err != nil || src.Repo != "asked/repo" || src.Origin != "prompt" || saved != "asked/repo" {
		t.Fatalf("prompt must come third and be saved: %+v err=%v saved=%q", src, err, saved)
	}
	_, err = ResolveRepo(in("", "", false))
	if err == nil || !strings.Contains(err.Error(), `"release_repo"`) ||
		!strings.Contains(err.Error(), EnvRepo) || !strings.Contains(err.Error(), "/etc/x/config.jsonc") {
		t.Fatalf("with no source and no terminal the refusal must name the exact setting; got %v", err)
	}
}

func TestResolveRepoRejectsMalformedValuesWithoutFallingThrough(t *testing.T) {
	for _, bad := range []string{"no-slash", "-flag/repo", "owner/-flag", "a/b/c", "host.com/a/b", "o wner/r", "a/b;rm"} {
		_, err := ResolveRepo(SourceInputs{Env: bad, Config: func() (string, error) { return "good/repo", nil }})
		if err == nil {
			t.Errorf("environment value %q was accepted", bad)
		}
		_, err = ResolveRepo(SourceInputs{Config: func() (string, error) { return bad, nil }})
		if err == nil {
			t.Errorf("config value %q was accepted", bad)
		}
	}
}

func TestResolveRepoReportsSaveFailureButKeepsTheAnswer(t *testing.T) {
	src, err := ResolveRepo(SourceInputs{
		Prompt: func() (string, error) { return "a/b", nil },
		Save:   func(string) error { return errors.New("read-only") },
	})
	if err != nil || src.Repo != "a/b" || src.SaveErr == nil {
		t.Fatalf("src=%+v err=%v, want the answer kept and SaveErr set", src, err)
	}
}

func TestBackupPruningKeepsNewestAndOnlyTouchesItsOwnNames(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour)
	for i, v := range []string{"0.80.0", "0.81.0", "0.82.0", "0.83.0", "0.84.0"} {
		name, err := BackupName(v)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v), 0o700); err != nil {
			t.Fatal(err)
		}
		at := base.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
	// Files the pruner did not name must survive, whatever they look like.
	keepers := []string{"notes.txt", "sopshq-latest", "sopshq-0.1.0.bak", "sopshq-1.2"}
	for _, n := range keepers {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sopshq-0.1.0"), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "sopshq-0.2.0")); err != nil {
		t.Fatal(err)
	}

	removed, err := PruneBackups(dir, KeepBackups)
	if err != nil {
		t.Fatalf("PruneBackups: %v", err)
	}
	if strings.Join(removed, ",") != "sopshq-0.81.0,sopshq-0.80.0" {
		t.Fatalf("removed %v, want the two oldest", removed)
	}
	left, err := ListBackups(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, b := range left {
		names = append(names, b.Version)
	}
	if strings.Join(names, ",") != "0.84.0,0.83.0,0.82.0" {
		t.Fatalf("kept %v, want the newest three, newest first", names)
	}
	for _, n := range append(keepers, "sopshq-0.1.0", "sopshq-0.2.0") {
		if _, err := os.Lstat(filepath.Join(dir, n)); err != nil {
			t.Errorf("the pruner touched %s: %v", n, err)
		}
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("the pruner reached through a symlink: %v", err)
	}
}

func TestListBackupsMissingFolderIsEmpty(t *testing.T) {
	got, err := ListBackups(filepath.Join(t.TempDir(), "absent"))
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v err=%v, want an empty list", got, err)
	}
}

func TestAssetName(t *testing.T) {
	if got := AssetName("linux", "amd64"); got != "sopshq-linux-amd64" {
		t.Fatalf("linux asset = %q", got)
	}
	if got := AssetName("windows", "amd64"); got != "sopshq-windows-amd64.exe" {
		t.Fatalf("windows asset = %q", got)
	}
}

func TestPruneSkipsProtectedNames(t *testing.T) {
	dir := t.TempDir()
	for _, v := range []string{"0.1.0", "0.2.0", "0.3.0", "0.4.0"} {
		os.WriteFile(filepath.Join(dir, "sopshq-"+v), []byte(v), 0o700)
	}
	removed, err := PruneBackups(dir, 2, "sopshq-0.1.0")
	if err != nil || strings.Join(removed, ",") != "sopshq-0.2.0" {
		t.Fatalf("removed %v err=%v, want only sopshq-0.2.0 (0.1.0 is protected)", removed, err)
	}
}

func TestRotationAcceptsEitherKey(t *testing.T) {
	oldKey, newK := newKey(t), newKey(t)
	keys := Keys{Primary: oldKey.PublicKey(), Next: newK.PublicKey()}
	for name, sk := range map[string]*mldsa.PrivateKey{"primary": oldKey, "next": newK} {
		if _, err := verify(keys, makeRelease(t, sk, "0.83.0", []byte("bin"))); err != nil {
			t.Errorf("a release signed by the %s key was refused: %v", name, err)
		}
		if !keys.Matches(sk) {
			t.Errorf("Matches did not recognise the %s key", name)
		}
	}
	stranger := newKey(t)
	if _, err := verify(keys, makeRelease(t, stranger, "0.83.0", []byte("bin"))); err == nil {
		t.Fatal("a release signed by neither key was accepted")
	}
	if keys.Matches(stranger) {
		t.Fatal("Matches recognised a key that is in neither slot")
	}
}

func TestEmptyPrimaryWithFilledNextStillRefuses(t *testing.T) {
	sk := newKey(t)
	next := EncodePublicKey(sk.PublicKey())
	keys, err := ParseKeys("# nothing\n", next)
	if !errors.Is(err, ErrNoKey) {
		t.Fatalf("ParseKeys err = %v, want ErrNoKey", err)
	}
	if _, err := verify(keys, makeRelease(t, sk, "0.83.0", []byte("bin"))); !errors.Is(err, ErrNoKey) {
		t.Fatalf("verify err = %v, want ErrNoKey (a next key alone must not be trusted)", err)
	}
}

func TestDamagedNextKeyIsAnError(t *testing.T) {
	primary := EncodePublicKey(newKey(t).PublicKey())
	if _, err := ParseKeys(primary, "zz"); err == nil {
		t.Fatal("a damaged next key was ignored")
	}
	k, err := ParseKeys(primary, "# empty\n")
	if err != nil || k.Next != nil {
		t.Fatalf("an empty next slot: %+v err=%v, want it accepted and unset", k, err)
	}
}

func TestSeedErrorNeverRevealsABadCharacter(t *testing.T) {
	seed := strings.Repeat("ab", 31) + "aq" // one bad character, 'q'
	_, err := PrivateKeyFromSeedHex(seed)
	if err == nil {
		t.Fatal("a malformed seed was accepted")
	}
	if strings.Contains(err.Error(), "q") || strings.Contains(err.Error(), "U+") || strings.Contains(err.Error(), seed) {
		t.Fatalf("the error reveals part of the seed: %q", err)
	}
}
