package main

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"sopshq/internal/config"
	"sopshq/internal/unlock"
)

// unlockSocketName is the socket file the locked service listens on, inside the
// runtime directory.
const unlockSocketName = "unlock.sock"

// cmdUnlock delivers the vault key to a running-but-locked SopsHQ. It checks the
// service is running (and not already unlocked), prompts for the vault key without
// echo, sends it over the private unlock socket, and reports the outcome. A wrong key
// leaves the service locked so it can be retried. Typically run as `sudo sopshq unlock`
// (root reaches the socket through the service account's 0700 runtime directory). The
// key is never logged.
func cmdUnlock(args []string) error {
	fs := flag.NewFlagSet("unlock", flag.ContinueOnError)
	runtimeDir := fs.String("runtime-dir", defaultRuntimeDir(), "directory holding the unlock socket")
	cfgPath := fs.String("config", "", "config file path (default: auto-discovered) - used to guard against a stale process")
	if err := fs.Parse(normalizeFlagArgs(args)); err != nil {
		return err
	}
	applyTrailingQuoteFix("runtime-dir", runtimeDir)
	applyTrailingQuoteFix("config", cfgPath)
	sock := filepath.Join(*runtimeDir, unlockSocketName)

	// Check the service first, so a not-running or already-unlocked state is reported
	// before prompting for the key.
	st, err := unlock.Status(sock)
	if errors.Is(err, unlock.ErrNotRunning) {
		return notRunningError(sock)
	}
	if err != nil {
		return err
	}
	// Refuse to hand the vault key to a STALE process: if the running serve reports a
	// data path different from the one the current install resolves to, it is an old
	// process left over from a re-setup. Delivering the key to it would unlock the wrong
	// (often broken) instance. Compare before prompting; skip the guard only when the
	// current config cannot be resolved (nothing to compare against).
	if want, ok := expectedUnlockDataDir(*cfgPath); ok {
		if err := unlockPathMismatch(st.DataDir, want); err != nil {
			return err
		}
	}
	if !st.Locked {
		fmt.Println("SopsHQ is already unlocked.")
		if st.URL != "" {
			fmt.Printf("Panel: %s\n", st.URL)
		}
		return nil
	}

	key, err := promptSecret("Vault key: ")
	if err != nil {
		return err
	}
	rep, err := unlock.Unlock(sock, key)
	if errors.Is(err, unlock.ErrNotRunning) {
		return notRunningError(sock)
	}
	if err != nil {
		return err
	}
	if !rep.OK {
		return fmt.Errorf("unlock failed: %s (the service is still locked; try again)", rep.Error)
	}
	fmt.Println("Vault unlocked. SopsHQ is starting the panel.")
	if url := waitForPanelURL(sock, 3*time.Second); url != "" {
		fmt.Printf("Panel: %s\n", url)
	}
	return nil
}

// cmdStatus reports whether the locked-start service is running, and if so whether its
// vault is locked or unlocked, plus the panel URL. A missing socket means "not running"
// and is printed, not treated as an error.
func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	runtimeDir := fs.String("runtime-dir", defaultRuntimeDir(), "directory holding the unlock socket")
	if err := fs.Parse(normalizeFlagArgs(args)); err != nil {
		return err
	}
	applyTrailingQuoteFix("runtime-dir", runtimeDir)
	sock := filepath.Join(*runtimeDir, unlockSocketName)

	st, err := unlock.Status(sock)
	if errors.Is(err, unlock.ErrNotRunning) {
		fmt.Printf("SopsHQ is not running (no unlock socket at %s).\n", sock)
		fmt.Println("Start it with: sudo systemctl start sopshq")
		return nil
	}
	if err != nil {
		return err
	}
	if st.Locked {
		fmt.Println("SopsHQ is running but LOCKED (vault not unlocked).")
		fmt.Println("Unlock it with: sudo sopshq unlock")
		return nil
	}
	fmt.Println("SopsHQ is running and UNLOCKED.")
	if st.URL != "" {
		fmt.Printf("Panel: %s\n", st.URL)
	}
	return nil
}

// unlockPathMismatch refuses to deliver the vault key when the running serve's data
// directory (running) differs from the one the current install resolves to (expected).
// A mismatch means `unlock` would be talking to a STALE process left over from an
// earlier install on a different path - exactly the failure this guard exists to stop.
// An empty running value (the server did not report a data dir) skips the check, since
// there is nothing to compare. It is pure so the refusal wording is unit-tested.
func unlockPathMismatch(running, expected string) error {
	if running == "" || expected == "" {
		return nil
	}
	if filepath.Clean(running) == filepath.Clean(expected) {
		return nil
	}
	return fmt.Errorf("refusing to unlock: the running SopsHQ serves data from %s, but this "+
		"install expects %s. That running process is stale (left over from an earlier setup). "+
		"Stop it first (systemctl stop sopshq, or sopshq stop), then start and unlock again",
		running, expected)
}

// expectedUnlockDataDir resolves the data directory the CURRENT install uses, for the
// stale-process guard. cfgPath is an explicit -config (empty means auto-discover). It
// returns ok=false when no config can be loaded, so unlock proceeds without the guard
// rather than blocking on a missing config.
func expectedUnlockDataDir(cfgPath string) (dataDir string, ok bool) {
	path := cfgPath
	if path == "" {
		path = discoverConfigPath()
	}
	cfg, err := config.Load(path)
	if err != nil {
		return "", false
	}
	return cfg.DataDir, true
}

// notRunningError is the shared, clear message when no service is listening on the
// unlock socket.
func notRunningError(sock string) error {
	return fmt.Errorf("SopsHQ is not running (no unlock socket at %s); start it with: sudo systemctl start sopshq", sock)
}

// waitForPanelURL briefly polls the socket for the panel URL, which the service sets a
// moment after unlock (once its listener address is resolved). It returns the URL, or
// empty if it is not published within the deadline.
func waitForPanelURL(sock string, within time.Duration) string {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if st, err := unlock.Status(sock); err == nil && st.URL != "" {
			return st.URL
		}
		time.Sleep(100 * time.Millisecond)
	}
	return ""
}
