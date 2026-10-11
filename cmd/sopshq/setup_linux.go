//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// executeSetup performs every idempotent system change the resolved plan describes -
// create the service account, create/own/permission the directories, ensure the acl
// package, install the running binary, link it onto PATH, write and reload the systemd
// unit - then hands
// off to the binary for the interactive first run as the service account, wires the
// keybase root into the config, and prints how to start and stop SopsHQ. It runs as
// root (cmdSetup enforces that before calling here).
func executeSetup(plan setupPlan, unit string) error {
	uid, gid, err := ensureServiceUser(plan.User)
	if err != nil {
		return err
	}
	if err := ensureDirs(plan, uid, gid); err != nil {
		return err
	}
	if err := ensureACL(); err != nil {
		return err
	}
	// Path-permission review: walk every path component down to the data dir and keybase root and make sure
	// the service account can traverse each one, offering the operator a remedy at every
	// blocking junction. Run after the dirs exist and acl tooling is present, but before
	// the handoff init (which writes to the data dir AS the service account).
	if err := reviewPathAccess(plan, uid, gid); err != nil {
		return err
	}
	if err := installBinary(plan.BinDest); err != nil {
		return err
	}
	if err := ensurePathSymlink(plan.BinDest); err != nil {
		return err
	}
	if err := installUnit(plan, unit); err != nil {
		return err
	}
	if err := handoffInit(plan, uid, gid); err != nil {
		return err
	}
	if err := writeMachinePointer(plan.Data); err != nil {
		return err
	}
	if err := wireKeybaseRoot(plan); err != nil {
		return err
	}
	printFootprint(os.Stdout, plan)
	printSetupDone(os.Stdout, plan)
	return nil
}

// ensureServiceUser creates the dedicated, unprivileged system account if it is
// missing (nologin, no home) and returns its uid and gid. Re-running is a no-op.
func ensureServiceUser(name string) (uid, gid int, err error) {
	fmt.Printf("-> service account: %s\n", name)
	if u, lookupErr := user.Lookup(name); lookupErr == nil {
		fmt.Println("   already exists")
		return atoiIDs(u)
	}
	shell := firstExisting("/usr/sbin/nologin", "/sbin/nologin", "/bin/false")
	cmd := exec.Command("useradd", "--system", "--no-create-home", "--shell", shell, name)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if runErr := cmd.Run(); runErr != nil {
		return 0, 0, fmt.Errorf("create service account %q: %w", name, runErr)
	}
	fmt.Println("   created")
	u, lookupErr := user.Lookup(name)
	if lookupErr != nil {
		return 0, 0, fmt.Errorf("service account %q not found after useradd: %w", name, lookupErr)
	}
	return atoiIDs(u)
}

// atoiIDs parses the numeric uid and gid from a user record.
func atoiIDs(u *user.User) (uid, gid int, err error) {
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("bad uid %q for %q: %w", u.Uid, u.Username, err)
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("bad gid %q for %q: %w", u.Gid, u.Username, err)
	}
	return uid, gid, nil
}

// firstExisting returns the first path that exists (used to pick this distro's nologin
// shell), falling back to the last candidate when none is found.
func firstExisting(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return paths[len(paths)-1]
}

// ensureDirs creates and permissions every managed directory: the install prefix
// (root:root 0755), the data base and its data subdir (service account, 0700), and the
// keybase root (service account, 0711). It is idempotent.
func ensureDirs(plan setupPlan, uid, gid int) error {
	fmt.Println("-> directories")
	if err := makeDir(plan.Prefix, 0o755, 0, 0); err != nil {
		return err
	}
	if err := makeDir(plan.Data, 0o700, uid, gid); err != nil {
		return err
	}
	if err := makeDir(plan.DataSubdir, 0o700, uid, gid); err != nil {
		return err
	}
	if plan.Keybase != "" {
		if err := makeDir(plan.Keybase, 0o711, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

// makeDir creates path (and parents), then sets its mode and owner exactly, so a
// pre-existing directory converges to the intended perms and ownership.
func makeDir(path string, mode os.FileMode, uid, gid int) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}

// ensureACL makes sure setfacl is available (SopsHQ grants each user read on their own
// key with POSIX ACLs). If it is missing it installs the acl package via the detected
// package manager, then re-checks. It errors clearly if it still cannot be found.
func ensureACL() error {
	fmt.Println("-> acl package (setfacl/getfacl)")
	if _, err := exec.LookPath("setfacl"); err == nil {
		fmt.Println("   already present")
		return nil
	}
	pm, ok := detectPackageManager(func(cmd string) bool {
		_, err := exec.LookPath(cmd)
		return err == nil
	})
	if !ok {
		return errors.New("setfacl is missing and no known package manager was found; install the 'acl' package by hand, then re-run")
	}
	fmt.Printf("   installing via %s ...\n", pm.Name)
	cmd := exec.Command(pm.Install[0], pm.Install[1:]...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("install acl via %s: %w", pm.Name, err)
	}
	if _, err := exec.LookPath("setfacl"); err != nil {
		return errors.New("acl install ran but setfacl is still missing; install the 'acl' package by hand")
	}
	return nil
}

// binaryInPlace reports whether the running binary (srcInfo) already IS the install
// target (destInfo), so the copy can be skipped and only ownership/mode re-asserted.
// destInfo is nil when the destination does not exist. It uses os.SameFile, which
// compares the underlying file identity (device + inode on Unix), so it is robust to
// symlinks and to relative-vs-absolute path spellings. It is pure and unit-tested; the
// chown/chmod side effects it gates stay in the privileged installBinary path.
func binaryInPlace(srcInfo, destInfo os.FileInfo) bool {
	if srcInfo == nil || destInfo == nil {
		return false
	}
	return os.SameFile(srcInfo, destInfo)
}

// installBinary makes the RUNNING binary the one installed at dest (root:root 0755), so
// the installed binary is exactly the one the operator invoked. When the source already
// IS the destination (an operator who dropped the binary at dest and ran it from there),
// it skips the copy and only re-asserts ownership and mode; otherwise it copies the
// binary in place atomically (temp file + rename). It runs as root and is idempotent.
func installBinary(dest string) error {
	fmt.Printf("-> binary -> %s\n", dest)
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate running binary: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(self); rerr == nil {
		self = resolved
	}
	srcInfo, err := os.Stat(self)
	if err != nil {
		return fmt.Errorf("stat running binary %s: %w", self, err)
	}
	destInfo, statErr := os.Stat(dest) // destInfo is nil when dest is absent
	if statErr != nil && !os.IsNotExist(statErr) {
		return fmt.Errorf("stat %s: %w", dest, statErr)
	}
	if binaryInPlace(srcInfo, destInfo) {
		fmt.Printf("   binary already at %s; leaving it in place\n", dest)
		if err := os.Chmod(dest, 0o755); err != nil {
			return fmt.Errorf("chmod %s: %w", dest, err)
		}
		return os.Chown(dest, 0, 0)
	}
	if err := copyFile(self, dest, 0o755); err != nil {
		return err
	}
	return os.Chown(dest, 0, 0)
}

// copyFile writes src's contents to dst atomically (temp file in the destination
// directory + rename) with the given mode.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".sopshq-*")
	if err != nil {
		return fmt.Errorf("temp file in %s: %w", filepath.Dir(dst), err)
	}
	tmpName := tmp.Name()
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("copy to %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("install %s: %w", dst, err)
	}
	return nil
}

// pathLinkAction is the decision ensurePathSymlink acts on for the /usr/local/bin/sopshq
// PATH symlink, given the current state of that path.
type pathLinkAction int

const (
	pathLinkCreate  pathLinkAction = iota // nothing exists at the link path: create the symlink
	pathLinkLeave                         // already a symlink to the installed binary: nothing to do
	pathLinkRepoint                       // a symlink pointing elsewhere: repoint it to the installed binary
	pathLinkRefuse                        // a non-symlink file is in the way: do not clobber it
)

// pathSymlinkDecision decides what to do about the /usr/local/bin/sopshq PATH symlink so
// the `sopshq` command resolves on PATH. It is given whether a file already exists at the
// link path, whether that file is a symlink, its current link target (when it is a
// symlink), and the wanted target (the installed binary). It is pure so it is unit-tested;
// the symlink syscalls it gates run in ensurePathSymlink under root.
func pathSymlinkDecision(exists, isSymlink bool, currentTarget, wantTarget string) pathLinkAction {
	switch {
	case !exists:
		return pathLinkCreate
	case !isSymlink:
		return pathLinkRefuse
	case currentTarget == wantTarget:
		return pathLinkLeave
	default:
		return pathLinkRepoint
	}
}

// ensurePathSymlink makes `sopshq` resolve on PATH by pointing /usr/local/bin/sopshq at
// the installed binary (that directory is on sudo's secure_path, so `sudo sopshq unlock`
// works). It ensures /usr/local/bin exists, then acts on pathSymlinkDecision: it leaves a
// symlink already pointing at the binary, repoints one that points elsewhere, and refuses
// to clobber a non-symlink file in the way (printing a clear, non-fatal warning so setup
// still finishes). It runs as root and is idempotent.
func ensurePathSymlink(binDest string) error {
	fmt.Printf("-> PATH symlink -> %s -> %s\n", pathSymlink, binDest)
	if err := os.MkdirAll(pathSymlinkDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", pathSymlinkDir, err)
	}
	info, statErr := os.Lstat(pathSymlink)
	if statErr != nil && !os.IsNotExist(statErr) {
		return fmt.Errorf("stat %s: %w", pathSymlink, statErr)
	}
	exists := statErr == nil
	var isSymlink bool
	var currentTarget string
	if exists && info.Mode()&os.ModeSymlink != 0 {
		isSymlink = true
		target, readErr := os.Readlink(pathSymlink)
		if readErr != nil {
			return fmt.Errorf("read symlink %s: %w", pathSymlink, readErr)
		}
		currentTarget = target
	}
	switch pathSymlinkDecision(exists, isSymlink, currentTarget, binDest) {
	case pathLinkLeave:
		fmt.Printf("   already points at %s; leaving it\n", binDest)
		return nil
	case pathLinkRefuse:
		fmt.Fprintf(os.Stderr, "warn: %s already exists and is NOT a symlink; leaving it untouched. "+
			"Add %s to PATH, or remove that file, so \"sopshq\" resolves on PATH.\n", pathSymlink, filepath.Dir(binDest))
		return nil
	case pathLinkRepoint:
		if err := os.Remove(pathSymlink); err != nil {
			return fmt.Errorf("remove stale symlink %s: %w", pathSymlink, err)
		}
		if err := os.Symlink(binDest, pathSymlink); err != nil {
			return fmt.Errorf("create symlink %s: %w", pathSymlink, err)
		}
		fmt.Printf("   repointed to %s\n", binDest)
		return nil
	default: // pathLinkCreate
		if err := os.Symlink(binDest, pathSymlink); err != nil {
			return fmt.Errorf("create symlink %s: %w", pathSymlink, err)
		}
		fmt.Println("   created")
		return nil
	}
}

// installUnit renders nothing (the unit is already rendered) - it writes the unit to
// its destination (root:root 0644) and reloads systemd. When systemctl is not present
// it prints a note and skips the unit, so SopsHQ still installs on a non-systemd host.
func installUnit(plan setupPlan, unit string) error {
	systemctl := systemctlBin()
	if systemctl == "" {
		fmt.Println("-> systemd unit: (systemctl not found - skipped; start SopsHQ by hand as the service account)")
		return nil
	}
	fmt.Printf("-> systemd unit -> %s\n", plan.UnitDest)
	if err := os.WriteFile(plan.UnitDest, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", plan.UnitDest, err)
	}
	if err := os.Chown(plan.UnitDest, 0, 0); err != nil {
		return fmt.Errorf("chown %s: %w", plan.UnitDest, err)
	}
	cmd := exec.Command(systemctl, "daemon-reload")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	fmt.Println("   installed (NOT enabled at boot)")
	return nil
}

// handoffInit runs `init` as the service account on this terminal, so the operator sets
// the vault key interactively and the config + location pointer land in the managed
// tree. Privileges are dropped for the child via a Unix Credential (the setup process
// is root); HOME and -dir point at the data base so the homeless account writes there.
func handoffInit(plan setupPlan, uid, gid int) error {
	fmt.Println()
	fmt.Println("==============================================================================")
	fmt.Printf(" First-run setup (interactive) - runs as %s\n", plan.User)
	fmt.Println("==============================================================================")
	fmt.Println("You will now choose the VAULT KEY. It is typed (not echoed), held only in")
	fmt.Println("memory, and required every time SopsHQ starts. Use the SAME vault key on every")
	fmt.Println("machine in your cluster.")
	fmt.Println()
	cmd := buildInitHandoff(plan, uid, gid)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("first-run init as %s: %w", plan.User, err)
	}
	return nil
}

// buildInitHandoff constructs the privilege-dropped command that runs `init` as the
// service account: the installed binary with `-dir <data>`, HOME set in a de-duplicated
// environment (glibc getenv reads the FIRST match, so a stale HOME must be removed, not
// shadowed), and a Unix Credential carrying the service account's uid and gid. It sets
// no stdio (the caller wires the terminal), so it is a pure builder that a test can
// inspect.
func buildInitHandoff(plan setupPlan, uid, gid int) *exec.Cmd {
	cmd := exec.Command(plan.BinDest, "init", "-dir", plan.Data)
	base := os.Environ()
	env := make([]string, 0, len(base)+1)
	for _, e := range base {
		if strings.HasPrefix(e, "HOME=") {
			continue
		}
		env = append(env, e)
	}
	env = append(env, "HOME="+plan.Data)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
	}
	return cmd
}

// writeMachinePointer records the data base at the fixed, machine-wide, world-readable
// location pointer (machinePointerFile, /etc/sopshq/location) so ANY user - including
// root running the bare `sopshq` dashboard - can locate this system install, no matter
// which user's config dir the per-user pointer landed in. The data base path is not a
// secret (the systemd unit already exposes it via `systemctl cat`), so the file is 0644
// in a 0755 dir. It overwrites on reinstall (idempotent) and re-asserts the perms.
func writeMachinePointer(dataBase string) error {
	dir := filepath.Dir(machinePointerFile)
	fmt.Printf("-> machine pointer -> %s\n", machinePointerFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	if err := os.WriteFile(machinePointerFile, []byte(dataBase+"\n"), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", machinePointerFile, err)
	}
	if err := os.Chmod(machinePointerFile, 0o644); err != nil {
		return fmt.Errorf("chmod %s: %w", machinePointerFile, err)
	}
	return nil
}

// wireKeybaseRoot fills the keybase root into the freshly-written config idempotently:
// it sets an empty value only, leaves a matching value, and flags (without changing) a
// different existing value. Skipped when no keybase root was chosen or no config exists.
func wireKeybaseRoot(plan setupPlan) error {
	if plan.Keybase == "" {
		return nil
	}
	body, err := os.ReadFile(plan.Config)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // init did not write a config (interrupted); nothing to wire
		}
		return fmt.Errorf("read %s: %w", plan.Config, err)
	}
	out, changed, conflict := setKeybaseRootInConfig(string(body), plan.Keybase)
	switch {
	case conflict:
		fmt.Fprintf(os.Stderr, "warn: keybase_root in %s is already set to a different value; leaving it. Edit it by hand if needed.\n", plan.Config)
		return nil
	case !changed:
		return nil
	}
	// Overwrite in place so the file keeps its owner (the service account) and 0600 mode.
	if err := os.WriteFile(plan.Config, []byte(out), 0o600); err != nil {
		return fmt.Errorf("update %s: %w", plan.Config, err)
	}
	fmt.Printf("-> set keybase_root = %s in %s\n", plan.Keybase, plan.Config)
	return nil
}

// printSetupDone prints how to start and stop SopsHQ after a successful setup.
func printSetupDone(w io.Writer, plan setupPlan) {
	fmt.Fprint(w, `
==============================================================================
 Done. How to start and stop SopsHQ
==============================================================================
`)
	if systemctlBin() != "" {
		fmt.Fprint(w, `  Start  : sudo systemctl start sopshq     (starts LOCKED, then waits)
  Unlock : sudo sopshq unlock                (type the vault key; brings the panel up)
  Status : sudo sopshq status                (locked/unlocked + the panel URL)
           systemctl status sopshq
  Logs   : journalctl -u sopshq -f
  Stop   : sudo systemctl stop sopshq

  Because the service has no terminal to type the vault key on, it starts LOCKED and
  serves nothing until you run "sudo sopshq unlock". After a reboot you start it and
  unlock it again the same way - it never auto-unlocks its vault.
`)
	} else {
		fmt.Fprintf(w, `  No systemd detected. Start it by hand as the service account:
    sudo runuser -u %s -- env HOME=%s %s serve -config %s
  With a terminal it prompts for the vault key (no echo). Without one it starts LOCKED;
  unlock it with "sudo sopshq unlock". For an unattended start, set SOPSHQ_VAULT_KEY in that
  command's environment instead.
`, plan.User, plan.Data, plan.BinDest, plan.Config)
	}
	fmt.Fprint(w, `
  Dashboard: run "sudo sopshq" (no arguments) any time to see the state, every path
  this machine uses, and the exact command for each action. Run it as root: root reads
  both the machine pointer (/etc/sopshq/location) and the sopshq-only unlock socket.

  Reach the panel over an SSH tunnel or Tailscale (it serves plain HTTP on loopback
  or the tailnet only - never a public interface). The transfer key that authenticates
  machine-to-machine sync is set later in the panel.

  Full guide: docs/deployment.md
`)
}
