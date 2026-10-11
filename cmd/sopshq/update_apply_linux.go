//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"sopshq/internal/unlock"
	"sopshq/internal/update"
)

// Size caps for the files copied out of the (operator-owned) download folder into the
// root-owned staging folder, so a hostile folder cannot fill the disk.
const (
	maxReleaseBinary = 256 << 20
	maxReleaseSums   = 64 << 10
	maxReleaseSig    = 16 << 10
)

// backupDirName is the folder under the install prefix that holds the old binaries.
const backupDirName = "backups"

// updateSystem is everything `sopshq update` asks of the running machine's service
// manager and status socket. The real one is in update_system_linux.go; tests supply a
// fake, so the update sequence is exercised without root or systemd.
type updateSystem interface {
	// UnitActive reports whether the sopshq systemd unit is running now.
	UnitActive() (bool, error)
	// Stop brings the machine to a known-stopped state: the unit and any stray serve.
	Stop() error
	// Start starts the unit and returns once systemd reports it up.
	Start() error
	// Status asks the service's unlock socket for its state.
	Status() (unlock.StatusReply, error)
}

// releaseFetcher reads release metadata from, and downloads release files out of, the
// release source with the invoking operator's own login.
type releaseFetcher interface {
	// LatestTag returns the tag name of the newest published release.
	LatestTag(repo string) (string, error)
	// Download fetches the named assets of the release at tag into a new folder it
	// owns, returning that folder and a cleanup that removes it.
	Download(repo, tag string, names []string) (dir string, cleanup func(), err error)
}

// updater carries one `sopshq update` run: where the install is, how to reach the
// machine, and the injectable seams the tests replace.
type updater struct {
	out    io.Writer
	prefix string // install prefix; the binary is <prefix>/sopshq
	goos   string
	goarch string
	// running is the version of the binary executing this command; "dev" refuses.
	running string

	pubkey     func() (update.Keys, error)
	fetch      releaseFetcher
	sys        updateSystem
	runVersion func(binary string) (string, error) // runs `<binary> version`
	rootOwned  func(path string) error             // refuses a path another user could rewrite
	chownRoot  func(path string) error             // makes a file root:root

	wait time.Duration // how long to wait for the service's status socket after a start
	poll time.Duration
	keep int
}

func (u *updater) say(format string, args ...any) { fmt.Fprintf(u.out, format+"\n", args...) }

func (u *updater) binPath() string   { return filepath.Join(u.prefix, "sopshq") }
func (u *updater) backupDir() string { return filepath.Join(u.prefix, backupDirName) }
func (u *updater) assetName() string { return update.AssetName(u.goos, u.goarch) }
func (u *updater) assets() []string {
	return []string{u.assetName(), update.SumsFile, update.SigFile}
}

// tagVersion is the version a release tag names ("v0.83.0" -> "0.83.0"). A tag is
// unverified; only the signed version in SHA256SUMS decides what is installed.
func tagVersion(tag string) string { return strings.TrimPrefix(tag, "v") }

// check prints the running version and the newest published one. It changes nothing.
func (u *updater) check(repo string) error {
	tag, err := u.fetch.LatestTag(repo)
	if err != nil {
		return err
	}
	newest := tagVersion(tag)
	u.say("running version : %s", u.running)
	u.say("newest published: %s (release %s of %s; the update itself verifies the signature)", newest, tag, repo)
	switch err := update.CheckNewer(u.running, newest); {
	case err == nil:
		u.say("An update is available. Run: sudo sopshq update")
	case errors.Is(err, update.ErrDevBuild):
		u.say("This is a dev build; it cannot be updated.")
	case errors.Is(err, update.ErrNotNewer):
		u.say("Already up to date.")
	default:
		return err
	}
	return nil
}

// installLatest downloads the newest release and installs it.
func (u *updater) installLatest(repo string) error {
	if err := u.refuseDev(); err != nil {
		return err
	}
	// Before anything runs the installed binary: it must be root-owned all the way up.
	if err := u.preflight(); err != nil {
		return err
	}
	if _, err := u.pubkey(); err != nil {
		return err
	}
	tag, err := u.fetch.LatestTag(repo)
	if err != nil {
		return err
	}
	u.say("newest release: %s", tag)
	if installed, verr := u.runVersion(u.binPath()); verr == nil {
		// The tag is unverified, so this only saves a download; the signed version is
		// checked again after verification.
		if cerr := update.CheckNewer(installed, tagVersion(tag)); errors.Is(cerr, update.ErrNotNewer) {
			return fmt.Errorf("nothing to do: %w", cerr)
		}
	}
	dir, cleanup, err := u.fetch.Download(repo, tag, u.assets())
	if err != nil {
		return err
	}
	defer cleanup()
	return u.installFrom(dir)
}

// refuseDev refuses to update from a binary with no release version.
func (u *updater) refuseDev() error {
	if strings.TrimSpace(u.running) == "dev" {
		return update.ErrDevBuild
	}
	return nil
}

// installFrom installs the release held in dir (the three release files for this
// platform): stage and verify in a root-owned folder, then swap.
func (u *updater) installFrom(dir string) error {
	if err := u.refuseDev(); err != nil {
		return err
	}
	keys, err := u.pubkey()
	if err != nil {
		return err
	}
	if err := u.preflight(); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(u.prefix, ".update-")
	if err != nil {
		return fmt.Errorf("create staging folder in %s: %w", u.prefix, err)
	}
	defer os.RemoveAll(staging)

	// Copy first, verify the copies: the download folder belongs to the operator, so
	// nothing in it is trusted until it sits in a folder only root can write to.
	for name, limit := range map[string]int64{
		u.assetName(): maxReleaseBinary, update.SumsFile: maxReleaseSums, update.SigFile: maxReleaseSig,
	} {
		if err := copyRegularFile(filepath.Join(dir, name), filepath.Join(staging, name), limit); err != nil {
			return err
		}
	}
	sums, err := os.ReadFile(filepath.Join(staging, update.SumsFile))
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(filepath.Join(staging, update.SigFile))
	if err != nil {
		return err
	}
	verified, err := update.VerifySums(keys, sums, sig)
	if err != nil {
		return err
	}
	stagedBin := filepath.Join(staging, u.assetName())
	f, err := os.Open(stagedBin)
	if err != nil {
		return err
	}
	err = verified.CheckAsset(u.assetName(), f)
	f.Close()
	if err != nil {
		return err
	}
	u.say("-> signature and checksum verified: release %s", verified.Version)

	installed, err := u.runVersion(u.binPath())
	if err != nil {
		return fmt.Errorf("cannot read the installed version (repair it with: sudo sopshq install): %w", err)
	}
	if err := update.CheckNewer(installed, verified.Version); err != nil {
		return err
	}
	if err := os.Chmod(stagedBin, 0o755); err != nil {
		return err
	}
	got, err := u.runVersion(stagedBin)
	if err != nil {
		return fmt.Errorf("the staged binary does not run: %w", err)
	}
	if got != verified.Version {
		return fmt.Errorf("the staged binary reports version %q but the signed release is %s; refusing", got, verified.Version)
	}
	return u.swap(stagedBin, verified.Version, true)
}

// rollback restores the newest backup through the same swap sequence.
func (u *updater) rollback() error {
	if err := u.refuseDev(); err != nil {
		return err
	}
	if err := u.preflight(); err != nil {
		return err
	}
	installed, err := u.runVersion(u.binPath())
	if err != nil {
		return fmt.Errorf("cannot read the installed version, so the backup to step down to cannot be chosen "+
			"(repair it with: sudo sopshq install): %w", err)
	}
	have, err := update.ParseVersion(installed)
	if err != nil {
		return fmt.Errorf("installed version: %w", err)
	}
	backups, err := update.ListBackups(u.backupDir())
	if err != nil {
		return err
	}
	// The target is the backup with the highest version LOWER than the installed one,
	// by the version in its file name, so repeated rollbacks step down and never bounce.
	var target *update.Backup
	var targetVer update.Version
	for i := range backups {
		v, perr := update.ParseVersion(backups[i].Version)
		if perr != nil || v.Compare(have) >= 0 {
			continue
		}
		if target == nil || v.Compare(targetVer) > 0 {
			target, targetVer = &backups[i], v
		}
	}
	if target == nil {
		return fmt.Errorf("no backup in %s is older than the installed version %s", u.backupDir(), installed)
	}
	path := filepath.Join(u.backupDir(), target.Name)
	// Root runs the backup next, so the folder and the file must be root-only first.
	for _, p := range []string{u.backupDir(), path} {
		if err := u.rootOwned(p); err != nil {
			return err
		}
	}
	got, err := u.runVersion(path)
	if err != nil {
		return fmt.Errorf("the backup %s does not run: %w", path, err)
	}
	if got != target.Version {
		return fmt.Errorf("the backup %s reports version %q, not %s; refusing", path, got, target.Version)
	}
	u.say("-> restoring backup %s", target.Name)
	return u.swap(path, target.Version, false)
}

// preflight refuses to run when the install is not in a state it can safely change: the
// prefix and the binary must exist, be regular, and be unwritable by anyone but root,
// because root is about to execute that binary and replace it.
func (u *updater) preflight() error {
	for _, p := range []string{u.prefix, u.binPath()} {
		if err := u.rootOwned(p); err != nil {
			return err
		}
	}
	fi, err := os.Lstat(u.binPath())
	if err != nil {
		return fmt.Errorf("no installed binary at %s (install first with: sudo sopshq install): %w", u.binPath(), err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file; refusing to replace it", u.binPath())
	}
	return nil
}

// ensureBackupDir creates the backups folder (root-owned, 0700) and refuses a symlink
// or non-folder standing in its place.
func (u *updater) ensureBackupDir() error {
	dir := u.backupDir()
	if fi, err := os.Lstat(dir); err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("%s exists and is not a folder", dir)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	return u.chownRoot(dir)
}

// swap replaces the installed binary with src (version want): pre-flight, stop, back up
// the old binary, atomic swap, then start it again if the service was running and check
// that the new build came up. On a failed check it restores the backup. A forward update
// (forward true) requires the service to report exactly the new version; a rollback
// target may predate the version field in the status reply, so it also accepts none.
func (u *updater) swap(src, want string, forward bool) error {
	bin := u.binPath()
	oldVer, oldErr := u.runVersion(bin)
	if err := u.ensureBackupDir(); err != nil {
		return err
	}
	// Pre-flight: put the new binary beside the old one before stopping anything, so a
	// full disk or a permission problem is found while the service is still up.
	newPath, err := u.stageBeside(src)
	if err != nil {
		return err
	}
	defer os.Remove(newPath) // gone after a successful rename; clears a failed attempt

	wasRunning, err := u.sys.UnitActive()
	if err != nil {
		return fmt.Errorf("check whether the service is running: %w", err)
	}
	// From the stop until the restart or restore finishes, a stray Ctrl-C or a closed
	// terminal must not leave the service stopped or the binary half swapped.
	defer holdSignals()()
	u.say("-> stopping SopsHQ")
	if err := u.sys.Stop(); err != nil {
		return u.abort(wasRunning, fmt.Errorf("stop: %w", err))
	}

	backup := ""
	if oldErr == nil {
		name, err := update.BackupName(oldVer)
		if err != nil {
			return u.abort(wasRunning, err)
		}
		backup = filepath.Join(u.backupDir(), name)
		u.say("-> backing up %s to %s", oldVer, backup)
		if err := copyFile(bin, backup, 0o700); err != nil {
			return u.abort(wasRunning, err)
		}
		if err := u.chownRoot(backup); err != nil {
			return u.abort(wasRunning, err)
		}
	} else {
		u.say("warning: the installed binary does not report a version (%v); it is not backed up", oldErr)
	}

	u.say("-> replacing %s with version %s", bin, want)
	if err := os.Rename(newPath, bin); err != nil {
		return u.abort(wasRunning, fmt.Errorf("swap in the new binary: %w", err))
	}

	if !wasRunning {
		u.say("The sopshq service was not running, so it was not started. The binary is now version %s.", want)
		u.say("Start it with: sudo systemctl start sopshq   then: sudo sopshq unlock")
		return nil
	}

	u.say("-> starting SopsHQ")
	checkErr := u.sys.Start()
	if checkErr == nil {
		checkErr = u.waitReady(want, forward)
	}
	if checkErr != nil {
		return u.restore(backup, oldVer, fmt.Errorf("the new version did not start: %w", checkErr))
	}
	u.say("[ok] SopsHQ %s is running.", want)

	// A rollback keeps every backup: the older ones are the next steps down.
	if forward {
		u.pruneBackups(filepath.Base(backup))
	}
	u.say("")
	u.say("The vault is LOCKED after every update. Unlock it with: sudo sopshq unlock")
	return nil
}

// holdSignals ignores SIGHUP, SIGINT and SIGTERM and returns the function that restores
// the default handling.
func holdSignals() func() {
	sigs := []os.Signal{syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM}
	signal.Ignore(sigs...)
	return func() { signal.Reset(sigs...) }
}

// pruneBackups keeps the highest versions in the backups folder, never the backup named
// protect (the one written in this run), and says what it removed.
func (u *updater) pruneBackups(protect string) {
	removed, err := update.PruneBackups(u.backupDir(), u.keep, protect)
	if err != nil {
		u.say("warning: could not prune old backups: %v", err)
	} else if len(removed) > 0 {
		u.say("-> pruned old backups: %s", strings.Join(removed, ", "))
	}
}

// abort ends an update that failed before the binary was replaced: nothing changed, and
// the service is started again if the update had stopped it.
func (u *updater) abort(wasRunning bool, cause error) error {
	if !wasRunning {
		return cause
	}
	u.say("-> the update failed before changing anything; starting the service again")
	if err := u.sys.Start(); err != nil {
		return fmt.Errorf("%w; and starting the service again failed: %v", cause, err)
	}
	return cause
}

// restore puts the backup back after a failed start, starts it, and reports both
// results. If the old binary also fails it stops there and says so, without looping.
func (u *updater) restore(backup, oldVer string, cause error) error {
	u.say("!! %v", cause)
	if backup == "" {
		return fmt.Errorf("%w; there is no backup to restore (the old binary reported no version). "+
			"Check: journalctl -u sopshq", cause)
	}
	u.say("-> restoring the previous version %s from %s", oldVer, backup)
	_ = u.sys.Stop() // the failed new build may still be up; best effort
	if err := copyFile(backup, u.binPath(), 0o755); err != nil {
		return fmt.Errorf("%w; and the previous version could not be restored: %v", cause, err)
	}
	if err := u.chownRoot(u.binPath()); err != nil {
		return fmt.Errorf("%w; and the previous version could not be restored: %v", cause, err)
	}
	if err := u.sys.Start(); err != nil {
		return u.bothFailed(cause, backup, err)
	}
	if err := u.waitReady(oldVer, false); err != nil {
		return u.bothFailed(cause, backup, err)
	}
	u.say("[ok] The previous version %s is running again.", oldVer)
	u.say("The vault is LOCKED. Unlock it with: sudo sopshq unlock")
	return fmt.Errorf("%w; the previous version %s was restored and is running", cause, oldVer)
}

// bothFailed is the end of the line: the new build failed and so did the restored old
// one. It makes no further attempt.
func (u *updater) bothFailed(cause error, backup string, second error) error {
	u.say("!! The previous version also failed to start: %v", second)
	u.say("   Nothing more will be tried automatically. The backup is at %s.", backup)
	u.say("   Look at: journalctl -u sopshq")
	return fmt.Errorf("%w; and the restored previous version also failed: %v", cause, second)
}

// stageBeside copies src into a temp file in the install prefix (same filesystem as the
// binary, so the later rename is atomic), root:root 0755, and returns its path.
func (u *updater) stageBeside(src string) (string, error) {
	tmp, err := os.CreateTemp(u.prefix, ".sopshq-new-")
	if err != nil {
		return "", fmt.Errorf("stage the new binary in %s: %w", u.prefix, err)
	}
	name := tmp.Name()
	in, err := os.Open(src)
	if err == nil {
		_, err = io.Copy(tmp, in)
		in.Close()
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(name, 0o755)
	}
	if err == nil {
		err = u.chownRoot(name)
	}
	if err != nil {
		os.Remove(name)
		return "", fmt.Errorf("stage the new binary: %w", err)
	}
	return name, nil
}

// waitReady waits, for a bounded time, for the service to answer on its status socket
// and report version want. A socket that answers with another version fails at once; a
// socket that is not there yet is polled. With strict false an answer with no version
// (a build older than the field) also counts.
func (u *updater) waitReady(want string, strict bool) error {
	deadline := time.Now().Add(u.wait)
	for {
		st, err := u.sys.Status()
		if err == nil {
			if st.Version == want || (!strict && st.Version == "") {
				return nil
			}
			got := st.Version
			if got == "" {
				got = "unknown"
			}
			return fmt.Errorf("the service answered but reports version %s, not %s", got, want)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the service did not answer on its status socket within %s: %w", u.wait, err)
		}
		time.Sleep(u.poll)
	}
}

// copyRegularFile copies src to dst (created exclusively, 0600) reading at most limit
// bytes. src must be a regular file, not a symlink, and must still be the same file
// after it is opened, so a swap during the copy is caught.
func copyRegularFile(src, dst string, limit int64) error {
	before, err := os.Lstat(src)
	if err != nil {
		return fmt.Errorf("release file: %w", err)
	}
	if !before.Mode().IsRegular() {
		return fmt.Errorf("release file %s is not a regular file", src)
	}
	// O_NOFOLLOW refuses a link swapped in after the Lstat; O_NONBLOCK keeps a FIFO from
	// hanging the open.
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("release file: %w", err)
	}
	defer in.Close()
	opened, err := in.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return fmt.Errorf("release file %s changed while it was being opened", src)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("stage %s: %w", dst, err)
	}
	n, err := io.Copy(out, io.LimitReader(in, limit+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("stage %s: %w", dst, err)
	}
	if n > limit {
		return fmt.Errorf("release file %s is larger than the %d byte limit", src, limit)
	}
	return nil
}
