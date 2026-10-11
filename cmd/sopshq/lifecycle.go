package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"sopshq/internal/config"
)

// Background-run runtime files. Both live under the data dir (the running process owns
// it, so it can always write them) and are listed on the bare-run dashboard.
const (
	pidFileName = "sopshq.pid"
	logFileName = "serve.log"
)

// cmdStart launches `serve` as a detached background process owned by the current
// user, records its pid, and routes its output to a log file. The child gets no
// terminal, so `serve` starts LOCKED and waits for `sopshq unlock` (the vault never
// auto-unlocks). It refuses to start a second instance while one is already running,
// clearing a stale pid file left by a dead process first.
func cmdStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path (default: auto-discovered)")
	if err := fs.Parse(normalizeFlagArgs(args)); err != nil {
		return err
	}
	applyTrailingQuoteFix("config", cfgPath)
	path := *cfgPath
	if path == "" {
		path = discoverConfigPath()
	}
	cfg, err := config.Load(path)
	if errors.Is(err, config.ErrNotFound) {
		return fmt.Errorf("no config at %s (install first: `sudo sopshq setup` on Linux, or `sopshq init`)", path)
	} else if err != nil {
		return err
	}
	// The detached child runs `serve`, which enforces this same guard; check it here
	// too so a wrong invocation (as root, or from a data dir this user does not own)
	// fails loudly in the foreground rather than only in the log.
	if err := checkServeGuard(cfg.DataDir); err != nil {
		return err
	}

	pidPath := filepath.Join(cfg.DataDir, pidFileName)
	if pid, running := pidFileRunning(pidPath, processAlive); running {
		return fmt.Errorf("SopsHQ is already running (pid %d); stop it first with `sopshq stop`", pid)
	}

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir %s: %w", cfg.DataDir, err)
	}
	logPath := filepath.Join(cfg.DataDir, logFileName)
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", logPath, err)
	}
	defer logf.Close()

	bin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate this binary: %w", err)
	}
	cmd := exec.Command(bin, "serve", "-config", path)
	cmd.Stdin = nil // no terminal -> serve starts LOCKED and waits for `sopshq unlock`
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = detachSysProcAttr()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start serve: %w", err)
	}
	pid := cmd.Process.Pid
	// Detach: release the child so it outlives this command; we never wait on it.
	_ = cmd.Process.Release()
	if err := writePIDFile(pidPath, pid); err != nil {
		return fmt.Errorf("write pid file %s: %w", pidPath, err)
	}

	fmt.Printf("SopsHQ started in the background (pid %d).\n", pid)
	fmt.Printf("  log: %s\n", logPath)
	fmt.Printf("  pid: %s\n", pidPath)
	fmt.Println("It starts LOCKED (the vault is not unlocked yet). Unlock it with:")
	if runtime.GOOS == "linux" {
		fmt.Println("  sudo sopshq unlock")
	} else {
		fmt.Println("  sopshq unlock")
	}
	return nil
}

// cmdStop stops the background SopsHQ recorded in the pid file: it asks the process to
// exit gracefully, waits, force-kills if it overstays, then removes the pid file. A
// missing pid file (nothing running) or a stale one (the pid is dead) is handled
// cleanly, never as an error.
func cmdStop(args []string) error {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path (default: auto-discovered)")
	if err := fs.Parse(normalizeFlagArgs(args)); err != nil {
		return err
	}
	applyTrailingQuoteFix("config", cfgPath)
	path := *cfgPath
	if path == "" {
		path = discoverConfigPath()
	}
	cfg, err := config.Load(path)
	if errors.Is(err, config.ErrNotFound) {
		return fmt.Errorf("no config at %s; nothing to stop", path)
	} else if err != nil {
		return err
	}

	pidPath := filepath.Join(cfg.DataDir, pidFileName)
	pid, running := pidFileRunning(pidPath, processAlive)
	switch {
	case pid == 0:
		fmt.Printf("SopsHQ does not appear to be running (no pid file at %s).\n", pidPath)
		return nil
	case !running:
		fmt.Printf("SopsHQ is not running (stale pid %d); clearing the pid file.\n", pid)
		_ = os.Remove(pidPath)
		return nil
	}

	fmt.Printf("Stopping SopsHQ (pid %d)...\n", pid)
	if err := terminateProcess(pid); err != nil {
		return fmt.Errorf("signal pid %d: %w", pid, err)
	}
	if !waitForExit(pid, 10*time.Second) {
		fmt.Printf("pid %d did not exit within 10s; forcing it.\n", pid)
		if err := forceKillProcess(pid); err != nil {
			return fmt.Errorf("force-kill pid %d: %w", pid, err)
		}
		waitForExit(pid, 2*time.Second)
	}
	_ = os.Remove(pidPath)
	fmt.Printf("Stopped (pid %d).\n", pid)
	return nil
}

// waitForExit polls until the process is gone or the timeout elapses, returning true
// once it has exited. The poll is cheap (a signal-0 / handle probe) and bounded.
func waitForExit(pid int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return !processAlive(pid)
}

// pidFileRunning reads the pid file at path and reports the recorded pid and whether a
// live process currently owns it. A missing, empty, or corrupt pid file reads as pid 0
// / not running, so the caller treats it as absent or stale. alive is injected (the
// platform liveness probe in production) so the staleness decision is unit-testable
// without a real process.
func pidFileRunning(path string, alive func(int) bool) (pid int, running bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	p, ok := parsePID(string(b))
	if !ok {
		return 0, false
	}
	return p, alive(p)
}

// parsePID reads a pid from pid-file contents. ok is false for empty, non-numeric, or
// non-positive content, so a corrupt pid file reads as "no pid".
func parsePID(s string) (pid int, ok bool) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p <= 0 {
		return 0, false
	}
	return p, true
}

// writePIDFile records pid at path (0600). The file is owned by the running process
// (the service account), which is the only account that can write the data dir.
func writePIDFile(path string, pid int) error {
	return os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0o600)
}
