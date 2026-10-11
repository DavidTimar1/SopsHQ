//go:build linux

package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"sopshq/internal/config"
	"sopshq/internal/update"
)

// writeScript writes an executable shell script and skips the test where the temp
// folder does not allow running files.
func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunBinaryVersion(t *testing.T) {
	dir := t.TempDir()
	good := writeScript(t, dir, "good", "echo sopshq 1.2.3")
	v, err := runBinaryVersion(good)
	if err != nil {
		t.Skipf("cannot run scripts from the temp folder: %v", err)
	}
	if v != "1.2.3" {
		t.Fatalf("version = %q, want 1.2.3", v)
	}
	for name, body := range map[string]string{
		"wrong-program": "echo other 1.2.3",
		"no-version":    "echo sopshq",
		"extra-words":   "echo sopshq 1.2.3 extra",
		"fails":         "exit 3",
	} {
		if _, err := runBinaryVersion(writeScript(t, dir, name, body)); err == nil {
			t.Errorf("%s: output was accepted as a version", name)
		}
	}
}

func TestRunBinaryVersionDoesNotPassTheEnvironment(t *testing.T) {
	t.Setenv("SOPSHQ_VAULT_KEY", "must-not-leak")
	dir := t.TempDir()
	p := writeScript(t, dir, "env", `echo "sopshq 1.0.0"; [ -z "$SOPSHQ_VAULT_KEY" ] || echo leaked >&2; [ -z "$SOPSHQ_VAULT_KEY" ] || exit 9`)
	if _, err := runBinaryVersion(p); err != nil {
		t.Fatalf("the binary saw the caller's environment (or could not run): %v", err)
	}
}

func TestRequireRootOwnedRefusesWhatOthersCouldRewrite(t *testing.T) {
	dir := t.TempDir()
	if os.Geteuid() == 0 {
		t.Skip("running as root: files created here are root-owned")
	}
	err := requireRootOwned(dir)
	if err == nil || !strings.Contains(err.Error(), "owned by root") {
		t.Fatalf("a folder owned by a normal user was accepted: %v", err)
	}
	if err := requireRootOwned(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing path was accepted")
	}
}

func TestGHCommandDropsPrivilegesAndEnvironment(t *testing.T) {
	t.Setenv("GH_TOKEN", "must-not-be-forwarded")
	t.Setenv("SOPSHQ_VAULT_KEY", "must-not-be-forwarded")
	f := &ghFetcher{gh: "/usr/bin/gh", drop: &user.User{Uid: "1234", Gid: "5678", Username: "operator", HomeDir: "/home/operator"}}
	cmd, err := f.command("/work", "release", "view")
	if err != nil {
		t.Fatal(err)
	}
	cred := cmd.SysProcAttr.Credential
	if cred == nil || cred.Uid != 1234 || cred.Gid != 5678 || len(cred.Groups) != 0 || cred.NoSetGroups {
		t.Fatalf("credential = %+v, want uid 1234 gid 5678 with supplementary groups cleared", cred)
	}
	env := strings.Join(cmd.Env, "\n")
	if !strings.Contains(env, "HOME=/home/operator") {
		t.Fatalf("env lacks the operator's HOME:\n%s", env)
	}
	if strings.Contains(env, "must-not-be-forwarded") || strings.Contains(env, "GH_TOKEN") || strings.Contains(env, "SOPSHQ_VAULT_KEY") {
		t.Fatalf("root's environment reached the dropped child:\n%s", env)
	}
	if cmd.Dir != "/work" {
		t.Fatalf("dir = %q", cmd.Dir)
	}
}

func TestGHCommandWithoutDropRunsAsTheCurrentUser(t *testing.T) {
	f := &ghFetcher{gh: "/usr/bin/gh"}
	cmd, err := f.command("")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.Credential != nil {
		t.Fatal("a credential switch was set although no user was given")
	}
}

// fakeGH is a gh stand-in that records its arguments and prints a canned release
// description (the shape of `gh release view --json tagName,isDraft`).
func fakeGH(t *testing.T, tag string) (f *ghFetcher, argsFile string) {
	t.Helper()
	return fakeGHRelease(t, tag, false)
}

func fakeGHRelease(t *testing.T, tag string, draft bool) (f *ghFetcher, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	t.Setenv("FAKE_GH_ARGS", argsFile)
	script := writeScript(t, dir, "gh", `printf '%s\n' "$@" > "$FAKE_GH_ARGS"; echo '{"tagName":"`+tag+`","isDraft":`+fmt.Sprint(draft)+`}'`)
	return &ghFetcher{gh: script}, argsFile
}

func TestLatestTagAcceptsOnlyAPlainVersionTag(t *testing.T) {
	f, argsFile := fakeGH(t, "v0.83.0")
	tag, err := f.LatestTag("owner/repo")
	if err != nil {
		t.Skipf("cannot run scripts from the temp folder: %v", err)
	}
	if tag != "v0.83.0" {
		t.Fatalf("tag = %q", tag)
	}
	args, _ := os.ReadFile(argsFile)
	if !strings.Contains(string(args), "--repo\nowner/repo\n") {
		t.Fatalf("gh was not told which repository:\n%s", args)
	}
	for _, evil := range []string{"--help", "v1.2", "latest", "v1.2.3-rc1", "../x"} {
		f, _ := fakeGH(t, evil)
		if _, err := f.LatestTag("owner/repo"); err == nil {
			t.Errorf("tag %q was accepted", evil)
		}
	}
	if _, err := f.LatestTag("-bad/repo"); err == nil {
		t.Error("a repository that starts with a dash was accepted")
	}
}

func TestDownloadRefusesUnexpectedTagAndPassesExactPatterns(t *testing.T) {
	f, argsFile := fakeGH(t, "v0.83.0")
	if _, _, err := f.Download("owner/repo", "--clobber", []string{"a"}); err == nil {
		t.Fatal("a flag-shaped tag was accepted")
	}
	dir, cleanup, err := f.Download("owner/repo", "v0.83.0", []string{"sopshq-linux-amd64", "SHA256SUMS", "SHA256SUMS.sig"})
	if err != nil {
		t.Skipf("cannot run scripts from the temp folder: %v", err)
	}
	args, _ := os.ReadFile(argsFile)
	for _, want := range []string{"release\ndownload\nv0.83.0\n", "--repo\nowner/repo\n", "--dir\n" + dir + "\n",
		"--pattern\nsopshq-linux-amd64\n", "--pattern\nSHA256SUMS\n", "--pattern\nSHA256SUMS.sig\n"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("gh arguments missing %q:\n%s", want, args)
		}
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("cleanup left the download folder behind: %v", err)
	}
}

func newConfigFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.jsonc")
	if err := config.Default(path, dir, "node").Save(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReleaseRepoConfigReadAndSave(t *testing.T) {
	path := newConfigFile(t)
	if got, err := readReleaseRepo(path); err != nil || got != "" {
		t.Fatalf("unset release_repo = %q err=%v, want empty", got, err)
	}
	if err := saveReleaseRepo(path, "owner/repo"); err != nil {
		t.Fatalf("saveReleaseRepo: %v", err)
	}
	if got, err := readReleaseRepo(path); err != nil || got != "owner/repo" {
		t.Fatalf("release_repo = %q err=%v, want owner/repo", got, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %o after save, want 0600", fi.Mode().Perm())
	}
	if _, err := config.Load(path); err != nil {
		t.Fatalf("the saved config no longer loads: %v", err)
	}
}

func TestReleaseRepoMissingConfigIsUnset(t *testing.T) {
	got, err := readReleaseRepo(filepath.Join(t.TempDir(), "absent.jsonc"))
	if err != nil || got != "" {
		t.Fatalf("got %q err=%v, want unset and no error", got, err)
	}
	if err := saveReleaseRepo(filepath.Join(t.TempDir(), "absent.jsonc"), "o/r"); err == nil {
		t.Fatal("saving to a config that does not exist succeeded")
	}
}

func TestReleaseRepoUnreadableConfigNamesTheWayOut(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read any file")
	}
	path := newConfigFile(t)
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	_, err := readReleaseRepo(path)
	if err == nil || !strings.Contains(err.Error(), "sudo") || !strings.Contains(err.Error(), update.EnvRepo) {
		t.Fatalf("err = %v, want advice to use sudo or the environment variable", err)
	}
}

type statInfo struct {
	mode os.FileMode
	uid  uint32
}

func (s statInfo) Name() string       { return "x" }
func (s statInfo) Size() int64        { return 0 }
func (s statInfo) Mode() os.FileMode  { return s.mode }
func (s statInfo) ModTime() time.Time { return time.Time{} }
func (s statInfo) IsDir() bool        { return s.mode.IsDir() }
func (s statInfo) Sys() any           { return &syscall.Stat_t{Uid: s.uid} }

func TestRootOwnedChainCoversEveryParent(t *testing.T) {
	good := map[string]statInfo{
		"/":                  {mode: os.ModeDir | 0o755},
		"/opt":               {mode: os.ModeDir | 0o755},
		"/opt/sopshq":        {mode: os.ModeDir | 0o755},
		"/opt/sopshq/sopshq": {mode: 0o755},
	}
	statFrom := func(m map[string]statInfo) func(string) (os.FileInfo, error) {
		return func(p string) (os.FileInfo, error) {
			fi, ok := m[p]
			if !ok {
				return nil, os.ErrNotExist
			}
			return fi, nil
		}
	}
	if err := requireRootOwnedChain("/opt/sopshq/sopshq", statFrom(good)); err != nil {
		t.Fatalf("a root-owned chain was refused: %v", err)
	}
	for _, c := range []struct {
		path string
		bad  statInfo
	}{
		{"/", statInfo{mode: os.ModeDir | 0o777}},
		{"/opt", statInfo{mode: os.ModeDir | 0o775}},
		{"/opt", statInfo{mode: os.ModeDir | 0o755, uid: 1000}},
		{"/opt/sopshq", statInfo{mode: os.ModeDir | 0o757}},
		{"/opt/sopshq/sopshq", statInfo{mode: 0o775}},
	} {
		m := map[string]statInfo{}
		for k, v := range good {
			m[k] = v
		}
		m[c.path] = c.bad
		err := requireRootOwnedChain("/opt/sopshq/sopshq", statFrom(m))
		if err == nil || !strings.Contains(err.Error(), "refusing to update: "+c.path+" ") {
			t.Errorf("bad %s (%+v): err = %v, want a refusal naming that path", c.path, c.bad, err)
		}
	}
	if err := requireRootOwnedChain("/opt/sopshq/sopshq", statFrom(map[string]statInfo{})); err == nil {
		t.Fatal("a path that cannot be stat'ed was accepted")
	}
}

func TestDraftReleasesAreIgnored(t *testing.T) {
	f, _ := fakeGHRelease(t, "v0.83.0", true)
	_, err := f.LatestTag("owner/repo")
	if err == nil || !strings.Contains(err.Error(), "draft") {
		if err != nil && strings.Contains(err.Error(), "run") {
			t.Skipf("cannot run scripts from the temp folder: %v", err)
		}
		t.Fatalf("a draft was accepted as the latest release: %v", err)
	}
	if dir, cleanup, err := f.Download("owner/repo", "v0.83.0", []string{"SHA256SUMS"}); err == nil {
		cleanup()
		t.Fatalf("a draft release was downloaded into %s", dir)
	}
}
