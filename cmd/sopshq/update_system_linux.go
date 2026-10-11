//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sopshq/internal/config"
	"sopshq/internal/unlock"
	"sopshq/internal/update"
)

// versionRunTimeout bounds `<binary> version`, which only prints a string.
const versionRunTimeout = 10 * time.Second

// readyWait is how long an update waits for the restarted service to answer on its
// status socket. The unit is Type=notify, so `systemctl start` already returns once
// the socket is listening; this only covers the gap to the first answer.
const readyWait = 30 * time.Second

// tagRe is the only shape of release tag the downloader accepts, so a tag from the
// remote can never reach a command line as anything but a plain version tag.
var tagRe = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// runUpdate runs `sopshq update` against this machine.
func runUpdate(opts updateOptions) error {
	u := &updater{
		out:        os.Stdout,
		prefix:     opts.Prefix,
		goos:       "linux",
		goarch:     runtime.GOARCH,
		running:    strings.TrimSpace(version),
		pubkey:     update.EmbeddedKeys,
		runVersion: runBinaryVersion,
		rootOwned:  requireRootOwned,
		chownRoot:  func(path string) error { return os.Chown(path, 0, 0) },
		wait:       readyWait,
		poll:       500 * time.Millisecond,
		keep:       update.KeepBackups,
	}
	u.sys = &systemdSystem{sock: filepath.Join(opts.RuntimeDir, unlockSocketName), unattended: opts.Yes}

	root := os.Geteuid() == 0
	if !opts.Check && !root {
		return errors.New("sopshq update must be run as root. Re-run with: sudo sopshq update " +
			"(to only look, no root needed: sopshq update --check)")
	}
	switch {
	case opts.Rollback:
		return u.rollback()
	case opts.From != "":
		return u.installFrom(opts.From)
	}

	repo, err := resolveReleaseRepo(opts.Config, root && !opts.Check)
	if err != nil {
		return err
	}
	fetcher, err := newGHFetcher()
	if err != nil {
		return err
	}
	u.fetch = fetcher
	if opts.Check {
		return u.check(repo)
	}
	return u.installLatest(repo)
}

// resolveReleaseRepo finds the release repository: SOPSHQ_RELEASE_REPO, then the config
// file's release_repo, then (on a terminal) a prompt whose answer is saved to the
// config. save is false for a read-only check, which prints a note instead of writing.
func resolveReleaseRepo(explicitConfig string, save bool) (string, error) {
	cfgPath, _ := resolveConfigPath(explicitConfig, machinePointerBase(), userPointerBase(), defaultDir())
	in := update.SourceInputs{
		Env:        os.Getenv(update.EnvRepo),
		ConfigHint: cfgPath,
		Config:     func() (string, error) { return readReleaseRepo(cfgPath) },
	}
	if stdinIsTTY() {
		in.Prompt = func() (string, error) {
			return promptLine("GitHub repository that publishes SopsHQ releases (OWNER/REPO): ")
		}
		if save {
			in.Save = func(repo string) error { return saveReleaseRepo(cfgPath, repo) }
		}
	}
	src, err := update.ResolveRepo(in)
	if err != nil {
		return "", err
	}
	switch {
	case src.Origin != "prompt":
	case src.SaveErr != nil:
		fmt.Fprintf(os.Stderr, "warning: could not save the release source: %v\n"+
			"         add %q: %q to %s to keep it\n", src.SaveErr, update.ConfigKey, src.Repo, cfgPath)
	case !save:
		fmt.Fprintf(os.Stderr, "note: the release source was not saved (a read-only check). "+
			"Add %q: %q to %s, or run: sudo sopshq update\n", update.ConfigKey, src.Repo, cfgPath)
	default:
		fmt.Printf("-> saved the release source to %s\n", cfgPath)
	}
	return src.Repo, nil
}

func machinePointerBase() string { b, _ := readMachinePointer(); return b }
func userPointerBase() string    { b, _ := readPointer(); return b }

// readReleaseRepo returns release_repo from the config at path ("" when unset). A config
// this user cannot read is an error that names the way out, since the config belongs to
// the service account.
func readReleaseRepo(path string) (string, error) {
	cfg, err := config.Load(path)
	switch {
	case errors.Is(err, config.ErrNotFound):
		return "", nil
	case errors.Is(err, fs.ErrPermission):
		return "", fmt.Errorf("cannot read %s as this user (it belongs to the service account): "+
			"run with sudo, or set %s=OWNER/REPO: %w", path, update.EnvRepo, err)
	case err != nil:
		return "", err
	}
	return cfg.ReleaseRepo, nil
}

// saveReleaseRepo writes release_repo into the config through the config package's own
// atomic write. The config's owner and mode are kept by config.Save.
func saveReleaseRepo(path, repo string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("cannot save to %s: %w", path, err)
	}
	cfg.ReleaseRepo = repo
	return cfg.Save()
}

// runBinaryVersion runs `<binary> version` with an empty environment and returns the
// version it prints ("sopshq 0.83.0" -> "0.83.0"). Callers only run binaries they have
// already verified or that sit in a root-owned location.
func runBinaryVersion(binary string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), versionRunTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "version")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("run %s version: %w", binary, err)
	}
	fields := strings.Fields(out.String())
	if len(fields) != 2 || fields[0] != "sopshq" {
		return "", fmt.Errorf("%s version printed %q, expected \"sopshq <version>\"", binary, strings.TrimSpace(out.String()))
	}
	return fields[1], nil
}

// requireRootOwned refuses a path that is not owned by root or that group or others can
// write, and does the same for every folder above it up to "/", because root is about to
// execute or replace it and anyone who can rewrite a parent can swap what root runs.
// Symlinks in the parent path are resolved first so the folders checked are the real ones.
func requireRootOwned(path string) error {
	resolved, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return err
	}
	return requireRootOwnedChain(filepath.Join(resolved, filepath.Base(path)), os.Lstat)
}

// requireRootOwnedChain checks path and each parent up to "/" with stat, and names the
// first path that fails. stat is a parameter so a test can supply owners and modes.
func requireRootOwnedChain(path string, stat func(string) (os.FileInfo, error)) error {
	for p := path; ; p = filepath.Dir(p) {
		fi, err := stat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot read the owner of %s", p)
		}
		if st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("refusing to update: %s must be owned by root and writable by no one else "+
				"(it is owned by uid %d, mode %o); repair it with: sudo sopshq install", p, st.Uid, fi.Mode().Perm())
		}
		if p == "/" || filepath.Dir(p) == p {
			return nil
		}
	}
}

// systemdSystem is the real updateSystem: systemctl, the stray-serve reconcile that
// setup uses, and the unlock status socket.
type systemdSystem struct {
	sock       string
	unattended bool // skip the confirmation before stopping a stray serve
}

func (s *systemdSystem) UnitActive() (bool, error) {
	systemctl := systemctlBin()
	if systemctl == "" {
		return false, nil
	}
	err := exec.Command(systemctl, "is-active", "--quiet", "sopshq").Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &exitErr):
		return false, nil // inactive, failed or not loaded
	default:
		return false, err
	}
}

func (s *systemdSystem) Stop() error { return reconcileExistingServe(s.unattended) }

func (s *systemdSystem) Start() error {
	systemctl := systemctlBin()
	if systemctl == "" {
		return errors.New("systemctl not found; start SopsHQ by hand")
	}
	cmd := exec.Command(systemctl, "start", "sopshq")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl start sopshq: %w (see: journalctl -u sopshq)", err)
	}
	return nil
}

func (s *systemdSystem) Status() (unlock.StatusReply, error) { return unlock.Status(s.sock) }

// ghFetcher reads and downloads releases with the GitHub CLI, as the operator who
// invoked sudo and with that operator's own gh login. No token is read, passed, stored
// or printed by this program.
type ghFetcher struct {
	gh   string
	drop *user.User // run gh as this user; nil runs it as the current user
}

// newGHFetcher finds gh and decides whose login it runs under: under sudo, the
// invoking user's, with root's privileges dropped for the child.
func newGHFetcher() (*ghFetcher, error) {
	gh := firstExecutable(ghPaths)
	if gh == "" {
		return nil, fmt.Errorf("the GitHub CLI (gh) was not found at %s; install it there, then run \"gh auth login\" as your own user",
			strings.Join(ghPaths, ", "))
	}
	f := &ghFetcher{gh: gh}
	if sudoUser := os.Getenv("SUDO_USER"); os.Geteuid() == 0 && sudoUser != "" && sudoUser != "root" {
		u, err := user.Lookup(sudoUser)
		if err != nil {
			return nil, fmt.Errorf("look up the invoking user %q: %w", sudoUser, err)
		}
		f.drop = u
	}
	return f, nil
}

// command builds a gh command. When dropping, it runs with the invoking user's uid and
// gid, no supplementary groups, their HOME (where gh keeps its login) and a minimal
// environment, so nothing of root's reaches it.
func (f *ghFetcher) command(dir string, args ...string) (*exec.Cmd, error) {
	cmd := exec.Command(f.gh, args...)
	cmd.Dir = "/"
	if dir != "" {
		cmd.Dir = dir
	}
	extra := []string{"GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1", "NO_COLOR=1"}
	if f.drop == nil {
		cmd.Env = append(os.Environ(), extra...)
		return cmd, nil
	}
	uid, err := strconv.ParseUint(f.drop.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("bad uid %q for %s: %w", f.drop.Uid, f.drop.Username, err)
	}
	gid, err := strconv.ParseUint(f.drop.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("bad gid %q for %s: %w", f.drop.Gid, f.drop.Username, err)
	}
	cmd.Env = append([]string{
		"HOME=" + f.drop.HomeDir,
		"USER=" + f.drop.Username,
		"LOGNAME=" + f.drop.Username,
		"PATH=/usr/local/bin:/usr/bin:/bin",
	}, extra...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
	}
	return cmd, nil
}

// releaseView is the part of `gh release view --json` the updater reads.
type releaseView struct {
	TagName string `json:"tagName"`
	IsDraft bool   `json:"isDraft"`
}

// view reads one release: the latest published one when tag is empty (drafts are never
// "latest"), or the named one. A draft is refused either way: a draft is a release the
// operator has not signed and published yet.
func (f *ghFetcher) view(repo, tag string) (releaseView, error) {
	args := []string{"release", "view"}
	if tag != "" {
		args = append(args, tag)
	}
	args = append(args, "--repo", repo, "--json", "tagName,isDraft")
	cmd, err := f.command("", args...)
	if err != nil {
		return releaseView{}, err
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, os.Stderr
	if err := cmd.Run(); err != nil {
		return releaseView{}, fmt.Errorf("gh could not read the release of %s (is gh logged in as your user, with access to it?): %w", repo, err)
	}
	var rv releaseView
	if err := json.Unmarshal(out.Bytes(), &rv); err != nil {
		return releaseView{}, fmt.Errorf("gh printed an unreadable release description: %w", err)
	}
	if rv.IsDraft {
		return releaseView{}, fmt.Errorf("release %s of %s is a draft (not signed and published yet); ignoring it", rv.TagName, repo)
	}
	if !tagRe.MatchString(rv.TagName) {
		return releaseView{}, fmt.Errorf("the release of %s has an unexpected tag %q", repo, rv.TagName)
	}
	return rv, nil
}

func (f *ghFetcher) LatestTag(repo string) (string, error) {
	if err := update.ValidateRepo(repo); err != nil {
		return "", err
	}
	rv, err := f.view(repo, "")
	if err != nil {
		return "", err
	}
	return rv.TagName, nil
}

func (f *ghFetcher) Download(repo, tag string, names []string) (string, func(), error) {
	if err := update.ValidateRepo(repo); err != nil {
		return "", nil, err
	}
	if !tagRe.MatchString(tag) {
		return "", nil, fmt.Errorf("refusing to download unexpected tag %q", tag)
	}
	if _, err := f.view(repo, tag); err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp("", "sopshq-update-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	if f.drop != nil {
		uid, _ := strconv.Atoi(f.drop.Uid)
		gid, _ := strconv.Atoi(f.drop.Gid)
		if err := os.Chown(dir, uid, gid); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("hand the download folder to %s: %w", f.drop.Username, err)
		}
	}
	args := []string{"release", "download", tag, "--repo", repo, "--dir", dir}
	for _, n := range names {
		args = append(args, "--pattern", n)
	}
	cmd, err := f.command(dir, args...)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("gh could not download release %s of %s: %w", tag, repo, err)
	}
	return dir, cleanup, nil
}
