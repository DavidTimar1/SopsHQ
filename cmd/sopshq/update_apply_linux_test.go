//go:build linux

package main

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sopshq/internal/unlock"
	"sopshq/internal/update"
)

// fakeBinary is the content of a pretend sopshq binary: its first line is what
// `sopshq version` would print, so fakeVersion can read it back without running anything.
func fakeBinary(version string) []byte {
	return []byte("sopshq " + version + "\n" + strings.Repeat("payload ", 64) + version + "\n")
}

func fakeVersion(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(string(b), "\n")
	f := strings.Fields(line)
	if len(f) != 2 || f[0] != "sopshq" {
		return "", fmt.Errorf("%s does not look like a sopshq binary", path)
	}
	return f[1], nil
}

// fakeSystem stands in for systemd and the status socket. Which version "runs" is read
// from the installed binary file, so a swap is observable the way a real restart is.
type fakeSystem struct {
	bin            string
	active         bool
	started        bool
	calls          []string
	startFails     map[string]bool // installed version -> Start fails
	noVersionField map[string]bool // installed version -> status reply omits the version
	stopErr        error
}

func (f *fakeSystem) UnitActive() (bool, error) {
	f.calls = append(f.calls, "active?")
	return f.active, nil
}

func (f *fakeSystem) Stop() error {
	f.calls = append(f.calls, "stop")
	f.started = false
	return f.stopErr
}

func (f *fakeSystem) Start() error {
	f.calls = append(f.calls, "start")
	v, err := fakeVersion(f.bin)
	if err != nil {
		return err
	}
	if f.startFails[v] {
		return fmt.Errorf("unit failed to start (version %s)", v)
	}
	f.started = true
	return nil
}

func (f *fakeSystem) Status() (unlock.StatusReply, error) {
	if !f.started {
		return unlock.StatusReply{}, unlock.ErrNotRunning
	}
	v, _ := fakeVersion(f.bin)
	if f.noVersionField[v] {
		v = ""
	}
	return unlock.StatusReply{Locked: true, Version: v}, nil
}

func (f *fakeSystem) did(call string) int {
	n := 0
	for _, c := range f.calls {
		if c == call {
			n++
		}
	}
	return n
}

type fakeFetcher struct {
	tag string
	dir string
	err error
}

func (f fakeFetcher) LatestTag(string) (string, error) { return f.tag, f.err }
func (f fakeFetcher) Download(string, string, []string) (string, func(), error) {
	return f.dir, func() {}, f.err
}

// harness is one install on disk under a temp prefix plus the updater wired to fakes.
type harness struct {
	t      *testing.T
	prefix string
	sk     *mldsa.PrivateKey
	sys    *fakeSystem
	u      *updater
	out    *bytes.Buffer
}

func newHarness(t *testing.T, installed string) *harness {
	t.Helper()
	sk, err := update.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	prefix := t.TempDir()
	bin := filepath.Join(prefix, "sopshq")
	if err := os.WriteFile(bin, fakeBinary(installed), 0o755); err != nil {
		t.Fatal(err)
	}
	sys := &fakeSystem{bin: bin, active: true, started: true,
		startFails: map[string]bool{}, noVersionField: map[string]bool{}}
	out := &bytes.Buffer{}
	h := &harness{t: t, prefix: prefix, sk: sk, sys: sys, out: out}
	h.u = &updater{
		out: out, prefix: prefix, goos: "linux", goarch: "amd64", running: installed,
		pubkey:     func() (update.Keys, error) { return update.Keys{Primary: sk.PublicKey()}, nil },
		sys:        sys,
		runVersion: fakeVersion,
		rootOwned:  func(string) error { return nil },
		chownRoot:  func(string) error { return nil },
		wait:       200 * time.Millisecond, poll: 5 * time.Millisecond, keep: update.KeepBackups,
	}
	return h
}

// release writes a signed release for version into a fresh folder and returns it.
func (h *harness) release(version string, binary []byte) string {
	h.t.Helper()
	dir := h.t.TempDir()
	asset := update.AssetName("linux", "amd64")
	sum := sha256.Sum256(binary)
	sums := update.FormatSums(version, map[string]string{asset: hex.EncodeToString(sum[:])})
	sig, err := update.Sign(h.sk, sums)
	if err != nil {
		h.t.Fatal(err)
	}
	for name, b := range map[string][]byte{asset: binary, update.SumsFile: sums, update.SigFile: sig} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			h.t.Fatal(err)
		}
	}
	return dir
}

func (h *harness) installed() string {
	h.t.Helper()
	v, err := fakeVersion(filepath.Join(h.prefix, "sopshq"))
	if err != nil {
		h.t.Fatal(err)
	}
	return v
}

// assertUntouched fails unless nothing about the install changed: same version, nothing
// stopped, no backups, no staging leftovers.
func (h *harness) assertUntouched(wantVersion string) {
	h.t.Helper()
	if got := h.installed(); got != wantVersion {
		h.t.Fatalf("installed version = %s, want it untouched at %s", got, wantVersion)
	}
	if len(h.sys.calls) != 0 && h.sys.did("stop") != 0 {
		h.t.Fatalf("the service was stopped (%v) for an update that must be refused", h.sys.calls)
	}
	if b, _ := update.ListBackups(filepath.Join(h.prefix, backupDirName)); len(b) != 0 {
		h.t.Fatalf("backups were made: %v", b)
	}
	h.assertNoLeftovers()
}

func (h *harness) assertNoLeftovers() {
	h.t.Helper()
	entries, err := os.ReadDir(h.prefix)
	if err != nil {
		h.t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "sopshq" && e.Name() != backupDirName {
			h.t.Fatalf("leftover in the install prefix: %s", e.Name())
		}
	}
}

func TestUpdateInstallsAGoodRelease(t *testing.T) {
	h := newHarness(t, "0.82.0")
	dir := h.release("0.83.0", fakeBinary("0.83.0"))

	if err := h.u.installFrom(dir); err != nil {
		t.Fatalf("installFrom: %v", err)
	}
	if got := h.installed(); got != "0.83.0" {
		t.Fatalf("installed = %s, want 0.83.0", got)
	}
	fi, err := os.Stat(filepath.Join(h.prefix, "sopshq"))
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("binary mode = %v err=%v, want 0755", fi.Mode().Perm(), err)
	}
	backup := filepath.Join(h.prefix, backupDirName, "sopshq-0.82.0")
	if v, err := fakeVersion(backup); err != nil || v != "0.82.0" {
		t.Fatalf("backup = %q err=%v, want the old 0.82.0 binary", v, err)
	}
	if fi, _ := os.Stat(filepath.Join(h.prefix, backupDirName)); fi.Mode().Perm() != 0o700 {
		t.Fatalf("backups folder mode = %o, want 0700", fi.Mode().Perm())
	}
	if got := strings.Join(h.sys.calls, ","); got != "active?,stop,start" {
		t.Fatalf("service calls = %s, want active?,stop,start", got)
	}
	if !strings.Contains(h.out.String(), "sudo sopshq unlock") || !strings.Contains(h.out.String(), "LOCKED") {
		t.Fatalf("output must tell the operator the vault is locked and how to unlock it:\n%s", h.out)
	}
	h.assertNoLeftovers()
}

func TestUpdateRefusesBadReleasesAndChangesNothing(t *testing.T) {
	good := fakeBinary("0.83.0")
	cases := map[string]func(h *harness) string{
		"tampered signature": func(h *harness) string {
			dir := h.release("0.83.0", good)
			p := filepath.Join(dir, update.SigFile)
			b, _ := os.ReadFile(p)
			b[10] ^= 0xff
			os.WriteFile(p, b, 0o644)
			return dir
		},
		"tampered signed text": func(h *harness) string {
			dir := h.release("0.83.0", good)
			p := filepath.Join(dir, update.SumsFile)
			b, _ := os.ReadFile(p)
			os.WriteFile(p, bytes.Replace(b, []byte("0.83.0"), []byte("0.99.0"), 1), 0o644)
			return dir
		},
		"tampered binary": func(h *harness) string {
			dir := h.release("0.83.0", good)
			os.WriteFile(filepath.Join(dir, update.AssetName("linux", "amd64")), fakeBinary("0.83.0-evil"), 0o644)
			return dir
		},
		"signed by another key": func(h *harness) string {
			other := *h
			other.sk, _ = update.GenerateKey()
			return other.release("0.83.0", good)
		},
		"older version": func(h *harness) string { return h.release("0.81.0", fakeBinary("0.81.0")) },
		"same version":  func(h *harness) string { return h.release("0.82.0", fakeBinary("0.82.0")) },
		"binary reports a different version than the signed one": func(h *harness) string {
			return h.release("0.83.0", fakeBinary("0.84.0"))
		},
		"missing signature file": func(h *harness) string {
			dir := h.release("0.83.0", good)
			os.Remove(filepath.Join(dir, update.SigFile))
			return dir
		},
		"release file is a symlink": func(h *harness) string {
			dir := h.release("0.83.0", good)
			p := filepath.Join(dir, update.AssetName("linux", "amd64"))
			real := filepath.Join(t.TempDir(), "elsewhere")
			os.WriteFile(real, good, 0o644)
			os.Remove(p)
			os.Symlink(real, p)
			return dir
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "0.82.0")
			dir := build(h)
			if err := h.u.installFrom(dir); err == nil {
				t.Fatal("the update was accepted, want a refusal")
			}
			h.assertUntouched("0.82.0")
		})
	}
}

func TestUpdateWithNoEmbeddedKeyRefuses(t *testing.T) {
	h := newHarness(t, "0.82.0")
	dir := h.release("0.83.0", fakeBinary("0.83.0"))
	h.u.pubkey = update.EmbeddedKeys
	if _, err := update.EmbeddedKeys(); !errors.Is(err, update.ErrNoKey) {
		t.Skip("a real key is embedded in this tree; the placeholder case is covered in internal/update")
	}
	if err := h.u.installFrom(dir); !errors.Is(err, update.ErrNoKey) {
		t.Fatalf("err = %v, want ErrNoKey", err)
	}
	h.assertUntouched("0.82.0")
}

func TestDevBuildRefusesToUpdate(t *testing.T) {
	h := newHarness(t, "0.82.0")
	h.u.running = "dev"
	dir := h.release("0.83.0", fakeBinary("0.83.0"))
	if err := h.u.installFrom(dir); !errors.Is(err, update.ErrDevBuild) {
		t.Fatalf("installFrom err = %v, want ErrDevBuild", err)
	}
	if err := h.u.installLatest("o/r"); !errors.Is(err, update.ErrDevBuild) {
		t.Fatalf("installLatest err = %v, want ErrDevBuild", err)
	}
	if err := h.u.rollback(); !errors.Is(err, update.ErrDevBuild) {
		t.Fatalf("rollback err = %v, want ErrDevBuild", err)
	}
	h.assertUntouched("0.82.0")
}

func TestUpdateRefusesAnInstallOthersCouldRewrite(t *testing.T) {
	h := newHarness(t, "0.82.0")
	h.u.rootOwned = func(p string) error { return fmt.Errorf("%s is writable by others", p) }
	dir := h.release("0.83.0", fakeBinary("0.83.0"))
	if err := h.u.installFrom(dir); err == nil || !strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("err = %v, want the ownership refusal", err)
	}
	h.assertUntouched("0.82.0")
}

func TestFailedStartRestoresTheBackup(t *testing.T) {
	h := newHarness(t, "0.82.0")
	h.sys.startFails["0.83.0"] = true
	dir := h.release("0.83.0", fakeBinary("0.83.0"))

	err := h.u.installFrom(dir)
	if err == nil || !strings.Contains(err.Error(), "did not start") || !strings.Contains(err.Error(), "restored and is running") {
		t.Fatalf("err = %v, want both results reported", err)
	}
	if got := h.installed(); got != "0.82.0" {
		t.Fatalf("installed = %s, want the old 0.82.0 back", got)
	}
	if !h.sys.started {
		t.Fatal("the restored service is not running")
	}
	if !strings.Contains(h.out.String(), "sudo sopshq unlock") {
		t.Fatalf("a restore must still say the vault is locked:\n%s", h.out)
	}
}

func TestNewBuildThatReportsAnotherVersionIsRolledBack(t *testing.T) {
	h := newHarness(t, "0.82.0")
	h.sys.noVersionField["0.83.0"] = true // starts, but does not identify itself as 0.83.0
	dir := h.release("0.83.0", fakeBinary("0.83.0"))
	if err := h.u.installFrom(dir); err == nil {
		t.Fatal("an update whose service did not report the new version was accepted")
	}
	if got := h.installed(); got != "0.82.0" {
		t.Fatalf("installed = %s, want 0.82.0 restored", got)
	}
}

func TestRestoredOldBuildWithNoVersionFieldCounts(t *testing.T) {
	h := newHarness(t, "0.82.0")
	h.sys.noVersionField["0.82.0"] = true // the restored build has no status version field
	h.sys.startFails["0.83.0"] = true
	dir := h.release("0.83.0", fakeBinary("0.83.0"))
	err := h.u.installFrom(dir)
	if err == nil || !strings.Contains(err.Error(), "restored and is running") {
		t.Fatalf("err = %v, want the old build reported as restored and running", err)
	}
}

func TestOldBuildAlsoFailingStopsWithoutLooping(t *testing.T) {
	h := newHarness(t, "0.82.0")
	h.sys.startFails["0.83.0"] = true
	h.sys.startFails["0.82.0"] = true
	dir := h.release("0.83.0", fakeBinary("0.83.0"))
	err := h.u.installFrom(dir)
	if err == nil || !strings.Contains(err.Error(), "also failed") {
		t.Fatalf("err = %v, want both failures reported", err)
	}
	if n := h.sys.did("start"); n != 2 {
		t.Fatalf("start was tried %d times, want exactly 2 (new, then old) and no loop", n)
	}
	if !strings.Contains(h.out.String(), "sopshq-0.82.0") {
		t.Fatalf("output must name where the backup is:\n%s", h.out)
	}
}

func TestUpdateWhenServiceWasNotRunningDoesNotStartIt(t *testing.T) {
	h := newHarness(t, "0.82.0")
	h.sys.active, h.sys.started = false, false
	dir := h.release("0.83.0", fakeBinary("0.83.0"))
	if err := h.u.installFrom(dir); err != nil {
		t.Fatalf("installFrom: %v", err)
	}
	if h.installed() != "0.83.0" {
		t.Fatal("the binary was not replaced")
	}
	if h.sys.did("start") != 0 {
		t.Fatal("the service was started although it was not running before")
	}
}

func TestStopFailureAbortsAndRestartsTheOldService(t *testing.T) {
	h := newHarness(t, "0.82.0")
	h.sys.stopErr = errors.New("cannot stop")
	dir := h.release("0.83.0", fakeBinary("0.83.0"))
	if err := h.u.installFrom(dir); err == nil {
		t.Fatal("update continued after a failed stop")
	}
	if h.installed() != "0.82.0" {
		t.Fatal("the binary was replaced although the service could not be stopped")
	}
	if h.sys.did("start") != 1 {
		t.Fatalf("calls = %v, want the old service started again", h.sys.calls)
	}
	h.assertNoLeftovers()
}

func TestSuccessfulUpdatePrunesToTheNewestThree(t *testing.T) {
	h := newHarness(t, "0.82.0")
	bdir := filepath.Join(h.prefix, backupDirName)
	if err := os.MkdirAll(bdir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	for i, v := range []string{"0.78.0", "0.79.0", "0.80.0"} {
		p := filepath.Join(bdir, "sopshq-"+v)
		os.WriteFile(p, fakeBinary(v), 0o700)
		at := old.Add(time.Duration(i) * time.Hour)
		os.Chtimes(p, at, at)
	}
	if err := h.u.installFrom(h.release("0.83.0", fakeBinary("0.83.0"))); err != nil {
		t.Fatal(err)
	}
	got, _ := update.ListBackups(bdir)
	var names []string
	for _, b := range got {
		names = append(names, b.Version)
	}
	if strings.Join(names, ",") != "0.82.0,0.80.0,0.79.0" {
		t.Fatalf("backups after update = %v, want 0.82.0,0.80.0,0.79.0", names)
	}
}

func TestFailedUpdateDoesNotPrune(t *testing.T) {
	h := newHarness(t, "0.82.0")
	h.sys.startFails["0.83.0"] = true
	bdir := filepath.Join(h.prefix, backupDirName)
	os.MkdirAll(bdir, 0o700)
	old := time.Now().Add(-48 * time.Hour)
	for i, v := range []string{"0.77.0", "0.78.0", "0.79.0"} {
		p := filepath.Join(bdir, "sopshq-"+v)
		os.WriteFile(p, fakeBinary(v), 0o700)
		at := old.Add(time.Duration(i) * time.Hour)
		os.Chtimes(p, at, at)
	}
	_ = h.u.installFrom(h.release("0.83.0", fakeBinary("0.83.0")))
	if got, _ := update.ListBackups(bdir); len(got) != 4 {
		t.Fatalf("%d backups after a failed update, want 4 (nothing pruned)", len(got))
	}
}

func TestRollbackRestoresTheNewestBackup(t *testing.T) {
	h := newHarness(t, "0.82.0")
	if err := h.u.installFrom(h.release("0.83.0", fakeBinary("0.83.0"))); err != nil {
		t.Fatal(err)
	}
	h.sys.calls = nil
	if err := h.u.rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got := h.installed(); got != "0.82.0" {
		t.Fatalf("installed after rollback = %s, want 0.82.0", got)
	}
	if v, err := fakeVersion(filepath.Join(h.prefix, backupDirName, "sopshq-0.83.0")); err != nil || v != "0.83.0" {
		t.Fatalf("the replaced 0.83.0 binary was not kept as a backup: %q err=%v", v, err)
	}
	if got := strings.Join(h.sys.calls, ","); got != "active?,stop,start" {
		t.Fatalf("service calls = %s, want the same stop, swap, start sequence", got)
	}
}

func TestRollbackToABuildWithNoVersionFieldIsAccepted(t *testing.T) {
	h := newHarness(t, "0.82.0")
	h.sys.noVersionField["0.82.0"] = true
	if err := h.u.installFrom(h.release("0.83.0", fakeBinary("0.83.0"))); err != nil {
		t.Fatal(err)
	}
	if err := h.u.rollback(); err != nil {
		t.Fatalf("rollback to a build older than the version field: %v", err)
	}
}

func TestRollbackRefusals(t *testing.T) {
	t.Run("no backups", func(t *testing.T) {
		h := newHarness(t, "0.82.0")
		if err := h.u.rollback(); err == nil || !strings.Contains(err.Error(), "no backup") {
			t.Fatalf("err = %v, want no-backup refusal", err)
		}
		h.assertUntouched("0.82.0")
	})
	t.Run("backup is the installed version", func(t *testing.T) {
		h := newHarness(t, "0.82.0")
		bdir := filepath.Join(h.prefix, backupDirName)
		os.MkdirAll(bdir, 0o700)
		os.WriteFile(filepath.Join(bdir, "sopshq-0.82.0"), fakeBinary("0.82.0"), 0o700)
		if err := h.u.rollback(); err == nil {
			t.Fatal("rollback to the already-installed version was accepted")
		}
		if h.sys.did("stop") != 0 {
			t.Fatal("the service was stopped for a pointless rollback")
		}
	})
	t.Run("backup that is not what its name says", func(t *testing.T) {
		h := newHarness(t, "0.82.0")
		bdir := filepath.Join(h.prefix, backupDirName)
		os.MkdirAll(bdir, 0o700)
		os.WriteFile(filepath.Join(bdir, "sopshq-0.81.0"), fakeBinary("0.99.0"), 0o700)
		if err := h.u.rollback(); err == nil {
			t.Fatal("a backup reporting another version was accepted")
		}
		if h.installed() != "0.82.0" || h.sys.did("stop") != 0 {
			t.Fatalf("the install was touched (calls %v)", h.sys.calls)
		}
	})
}

func TestInstallLatestDownloadsThenVerifies(t *testing.T) {
	h := newHarness(t, "0.82.0")
	h.u.fetch = fakeFetcher{tag: "v0.83.0", dir: h.release("0.83.0", fakeBinary("0.83.0"))}
	if err := h.u.installLatest("o/r"); err != nil {
		t.Fatalf("installLatest: %v", err)
	}
	if h.installed() != "0.83.0" {
		t.Fatal("not installed")
	}
}

func TestInstallLatestSkipsDownloadWhenTagIsNotNewer(t *testing.T) {
	h := newHarness(t, "0.82.0")
	h.u.fetch = fakeFetcher{tag: "v0.82.0", err: nil, dir: "/nonexistent"}
	err := h.u.installLatest("o/r")
	if !errors.Is(err, update.ErrNotNewer) {
		t.Fatalf("err = %v, want ErrNotNewer", err)
	}
	h.assertUntouched("0.82.0")
}

func TestCheckReportsRunningAndNewest(t *testing.T) {
	h := newHarness(t, "0.82.0")
	h.u.fetch = fakeFetcher{tag: "v0.83.0"}
	if err := h.u.check("o/r"); err != nil {
		t.Fatal(err)
	}
	out := h.out.String()
	for _, want := range []string{"0.82.0", "0.83.0", "sudo sopshq update"} {
		if !strings.Contains(out, want) {
			t.Fatalf("check output missing %q:\n%s", want, out)
		}
	}
	h.assertUntouched("0.82.0")
	if len(h.sys.calls) != 0 {
		t.Fatalf("check touched the service: %v", h.sys.calls)
	}
}

func TestCopyRegularFileLimits(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	os.WriteFile(src, bytes.Repeat([]byte("x"), 100), 0o644)
	if err := copyRegularFile(src, filepath.Join(dir, "ok"), 100); err != nil {
		t.Fatalf("a file at the limit was refused: %v", err)
	}
	if err := copyRegularFile(src, filepath.Join(dir, "big"), 99); err == nil {
		t.Fatal("an oversized file was accepted")
	}
	if err := copyRegularFile(src, filepath.Join(dir, "ok"), 100); err == nil {
		t.Fatal("copy overwrote an existing staged file")
	}
	if err := copyRegularFile(dir, filepath.Join(dir, "d"), 100); err == nil {
		t.Fatal("a directory was accepted as a release file")
	}
}

func TestParseUpdateFlags(t *testing.T) {
	if o, err := parseUpdateFlags([]string{"--check"}); err != nil || !o.Check {
		t.Fatalf("--check: %+v err=%v", o, err)
	}
	if o, err := parseUpdateFlags([]string{"-FROM", "/tmp/rel"}); err != nil || o.From != "/tmp/rel" {
		t.Fatalf("-from (any case): %+v err=%v", o, err)
	}
	for _, bad := range [][]string{
		{"--check", "--rollback"}, {"--check", "--from", "/x"}, {"--rollback", "--from", "/x"}, {"extra"},
	} {
		if _, err := parseUpdateFlags(bad); err == nil {
			t.Errorf("flags %v were accepted", bad)
		}
	}
}

func TestManualStepsNameTheWindowsAsset(t *testing.T) {
	var b bytes.Buffer
	printManualUpdateSteps(&b)
	for _, want := range []string{"sopshq-windows-amd64.exe", "SHA256SUMS", "Stop SopsHQ"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("manual steps missing %q:\n%s", want, b.String())
		}
	}
}

// seedBackups writes backups with the given versions; mtimes run opposite to the listed
// order, so a passing test cannot be choosing by modification time.
func seedBackups(t *testing.T, h *harness, versions ...string) {
	t.Helper()
	bdir := filepath.Join(h.prefix, backupDirName)
	if err := os.MkdirAll(bdir, 0o700); err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-48 * time.Hour)
	for i, v := range versions {
		p := filepath.Join(bdir, "sopshq-"+v)
		if err := os.WriteFile(p, fakeBinary(v), 0o700); err != nil {
			t.Fatal(err)
		}
		at := base.Add(time.Duration(len(versions)-i) * time.Hour)
		os.Chtimes(p, at, at)
	}
}

func TestRollbackStepsDownThroughVersions(t *testing.T) {
	h := newHarness(t, "0.84.0")
	seedBackups(t, h, "0.81.0", "0.83.0", "0.82.0")
	for _, want := range []string{"0.83.0", "0.82.0", "0.81.0"} {
		if err := h.u.rollback(); err != nil {
			t.Fatalf("rollback to %s: %v", want, err)
		}
		if got := h.installed(); got != want {
			t.Fatalf("installed = %s, want %s (stepping down)", got, want)
		}
	}
	for _, kept := range []string{"0.84.0", "0.83.0", "0.82.0"} {
		if _, err := os.Stat(filepath.Join(h.prefix, backupDirName, "sopshq-"+kept)); err != nil {
			t.Errorf("the replaced binary %s was not kept as a backup: %v", kept, err)
		}
	}
	if err := h.u.rollback(); err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("rollback below the oldest backup: err = %v, want a refusal that none is older", err)
	}
}

func TestRollbackRefusesWhenNoBackupIsOlder(t *testing.T) {
	h := newHarness(t, "0.82.0")
	seedBackups(t, h, "0.82.0", "0.83.0", "0.90.0")
	if err := h.u.rollback(); err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("err = %v, want a refusal that no backup is older", err)
	}
	if h.installed() != "0.82.0" || h.sys.did("stop") != 0 {
		t.Fatalf("the install was touched (calls %v)", h.sys.calls)
	}
}

func TestRollbackIgnoresDecoyNames(t *testing.T) {
	h := newHarness(t, "0.84.0")
	seedBackups(t, h, "0.82.0")
	bdir := filepath.Join(h.prefix, backupDirName)
	for _, n := range []string{"sopshq-0.83", "sopshq-latest", "sopshq-0.83.0.bak", "sopshq-9.9.9-evil"} {
		os.WriteFile(filepath.Join(bdir, n), fakeBinary("0.83.0"), 0o700)
	}
	if err := h.u.rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got := h.installed(); got != "0.82.0" {
		t.Fatalf("installed = %s, want 0.82.0 (decoys must not be chosen)", got)
	}
}

func TestInstallLatestRefusesAnUnsafeInstallBeforeRunningAnything(t *testing.T) {
	h := newHarness(t, "0.82.0")
	ran := 0
	h.u.runVersion = func(string) (string, error) { ran++; return "0.82.0", nil }
	h.u.rootOwned = func(p string) error { return fmt.Errorf("%s is writable by others", p) }
	h.u.fetch = &countingFetcher{tag: "v0.83.0", dir: h.release("0.83.0", fakeBinary("0.83.0"))}
	err := h.u.installLatest("o/r")
	if err == nil || !strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("err = %v, want the ownership refusal", err)
	}
	if ran != 0 {
		t.Fatalf("the installed binary was run %d times before the ownership check", ran)
	}
	if f := h.u.fetch.(*countingFetcher); f.calls != 0 {
		t.Fatalf("the release source was contacted %d times", f.calls)
	}
}

type countingFetcher struct {
	tag, dir string
	calls    int
}

func (f *countingFetcher) LatestTag(string) (string, error) { f.calls++; return f.tag, nil }
func (f *countingFetcher) Download(string, string, []string) (string, func(), error) {
	f.calls++
	return f.dir, func() {}, nil
}

func TestRollbackChecksTheBackupFolderAndFileBeforeRunningThem(t *testing.T) {
	h := newHarness(t, "0.84.0")
	seedBackups(t, h, "0.82.0")
	backup := filepath.Join(h.prefix, backupDirName, "sopshq-0.82.0")
	for _, bad := range []string{filepath.Join(h.prefix, backupDirName), backup} {
		ran := map[string]int{}
		h.u.runVersion = func(p string) (string, error) { ran[p]++; return fakeVersion(p) }
		h.u.rootOwned = func(p string) error {
			if p == bad {
				return fmt.Errorf("%s is writable by others", p)
			}
			return nil
		}
		if err := h.u.rollback(); err == nil || !strings.Contains(err.Error(), bad) {
			t.Fatalf("bad %s: err = %v, want a refusal naming it", bad, err)
		}
		if ran[backup] != 0 {
			t.Fatalf("bad %s: the backup was run before the check", bad)
		}
	}
}

func TestUpdateNeverPrunesTheBackupItJustWrote(t *testing.T) {
	// The installed version is the LOWEST in the folder, so a plain prune of the
	// three highest would remove the backup this run just made.
	h := newHarness(t, "0.50.0")
	seedBackups(t, h, "0.82.0", "0.81.0", "0.80.0")
	if err := h.u.installFrom(h.release("0.83.0", fakeBinary("0.83.0"))); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.prefix, backupDirName, "sopshq-0.50.0")); err != nil {
		t.Fatalf("the backup written in this run was pruned: %v", err)
	}
}
