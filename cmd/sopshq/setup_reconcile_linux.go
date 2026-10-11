//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sopshq/internal/config"
)

// staleServe describes a `sopshq serve` process found still running before setup writes
// anything. It is what setup SHOWS the operator so the decision to stop it is informed,
// never a blind kill.
type staleServe struct {
	pid        int
	cmdline    string // the full command line, space-joined, for display
	configPath string // the -config value it was started with (may be empty)
	dataDir    string // the data directory that config resolves to (or a note if unreadable)
}

// reconcileExistingServe brings the machine to a known-stopped state before setup writes
// any file. It stops the systemd unit, then finds every stale `sopshq serve` still
// running, shows each one (data path, pid, command line), asks the operator to confirm
// (unless unattended), stops them, and verifies none remain. It never kills by guessed
// name or pid: every process it stops was positively identified as a sopshq serve by
// resolving its executable and reading its arguments.
func reconcileExistingServe(unattended bool) error {
	stopSystemdUnit()

	self, err := os.Executable()
	if err != nil {
		self = ""
	}
	stale, err := detectStaleServes(self)
	if err != nil {
		return fmt.Errorf("scan for a running SopsHQ: %w", err)
	}
	if len(stale) == 0 {
		fmt.Println("-> no stale SopsHQ serve is running")
		return nil
	}

	fmt.Println()
	fmt.Println("A SopsHQ serve is still running. It must be stopped before the install is rewritten,")
	fmt.Println("otherwise the old process would keep serving the previous data path (and a later")
	fmt.Println("unlock could hand the vault key to it):")
	fmt.Println()
	for _, s := range stale {
		fmt.Printf("  pid %d\n", s.pid)
		fmt.Printf("    data path : %s\n", s.dataDir)
		fmt.Printf("    command   : %s\n", s.cmdline)
	}
	fmt.Println()

	if !unattended {
		ans, err := promptLine("Stop the running SopsHQ serve process(es) now? [y/N]: ")
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(ans)) {
		case "y", "yes":
		default:
			return errors.New("aborted: a SopsHQ serve is still running. Stop it and re-run setup")
		}
	}

	for _, s := range stale {
		fmt.Printf("-> stopping pid %d ...\n", s.pid)
		if err := terminateProcess(s.pid); err != nil {
			// Already gone between detection and now is fine.
			if !processAlive(s.pid) {
				continue
			}
			return fmt.Errorf("signal pid %d: %w", s.pid, err)
		}
		if !waitForExit(s.pid, 10*time.Second) {
			fmt.Printf("   pid %d did not exit within 10s; forcing it.\n", s.pid)
			if err := forceKillProcess(s.pid); err != nil && processAlive(s.pid) {
				return fmt.Errorf("force-kill pid %d: %w", s.pid, err)
			}
			waitForExit(s.pid, 2*time.Second)
		}
	}

	remaining, err := detectStaleServes(self)
	if err != nil {
		return fmt.Errorf("re-scan for a running SopsHQ: %w", err)
	}
	if len(remaining) > 0 {
		var pids []string
		for _, s := range remaining {
			pids = append(pids, strconv.Itoa(s.pid))
		}
		return fmt.Errorf("a SopsHQ serve is still running after the stop attempt (pid %s); "+
			"stop it by hand and re-run setup", strings.Join(pids, ", "))
	}
	fmt.Println("   stopped; none remain")
	return nil
}

// stopSystemdUnit stops the sopshq systemd unit if systemctl is present. A unit that is
// not loaded or already stopped is not an error - the goal is only that it is not running
// when setup rewrites it. It never enables or starts anything.
func stopSystemdUnit() {
	systemctl := systemctlBin()
	if systemctl == "" {
		return
	}
	fmt.Println("-> stopping the sopshq systemd unit (if running)")
	cmd := exec.Command(systemctl, "stop", "sopshq")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	_ = cmd.Run() // a missing/stopped unit is fine
}

// detectStaleServes scans /proc for every running `sopshq serve` process (other than
// this one), resolving each candidate's executable so only real sopshq binaries match,
// then reading its arguments to confirm the serve subcommand and recover its data path.
// self is this process's executable path, excluded from the results.
func detectStaleServes(self string) ([]staleServe, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	me := os.Getpid()
	var out []staleServe
	for _, e := range entries {
		pid, perr := strconv.Atoi(e.Name())
		if perr != nil || pid == me {
			continue
		}
		if !procIsSopshq(pid, self) {
			continue
		}
		argv, rerr := procArgv(pid)
		if rerr != nil || len(argv) == 0 {
			continue
		}
		configPath, isServe := staleServeMatch(argv)
		if !isServe {
			continue
		}
		out = append(out, staleServe{
			pid:        pid,
			cmdline:    strings.Join(argv, " "),
			configPath: configPath,
			dataDir:    staleDataDir(configPath),
		})
	}
	return out, nil
}

// procIsSopshq reports whether the process pid runs a sopshq binary: its resolved
// executable is either exactly this setup binary (self) or a file named "sopshq". The
// exe link is resolved with EvalSymlinks so a symlinked or reinstalled binary still
// matches. A pid that vanished or whose exe cannot be read is not a match.
func procIsSopshq(pid int, self string) bool {
	exe, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return false
	}
	// A deleted-and-replaced binary shows as "<path> (deleted)"; trim that marker.
	exe = strings.TrimSuffix(exe, " (deleted)")
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	if self != "" && exe == self {
		return true
	}
	return filepath.Base(exe) == "sopshq"
}

// procArgv reads a process's argument vector from /proc/<pid>/cmdline, which is a
// NUL-separated, NUL-terminated list. It decodes the bytes as UTF-8 (arguments are
// arbitrary data, not necessarily ASCII) and drops the trailing empty field.
func procArgv(pid int) ([]string, error) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return nil, err
	}
	parts := strings.Split(string(raw), "\x00")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

// staleDataDir resolves the data directory a stale serve is bound to from its -config
// path, for display. When the config is missing or unreadable it returns a short note
// instead of a path, so the operator still sees which config was in play.
func staleDataDir(configPath string) string {
	if configPath == "" {
		return "(unknown - started without -config)"
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Sprintf("(config %s unreadable: %v)", configPath, err)
	}
	return cfg.DataDir
}
