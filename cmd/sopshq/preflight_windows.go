//go:build windows

package main

import (
	"fmt"
	"os"
	"os/user"

	"sopshq/internal/config"
)

// runPreflight verifies, BEFORE the vault key is acquired, that serve can actually write
// everywhere it needs to on Windows: the data directory, the (usually identical) vault
// directory, the keybase root when one is configured, and the unlock-socket runtime
// directory. It returns the first failure as a clear, path-naming error - "directory
// does not exist" or "not writable" - so a missing folder or a permission gap stops
// serve before it touches the vault key, rather than crashing obscurely after unlock.
// Windows has no /mnt-style mount hint and no POSIX owner/ACL model, so this is a plain
// exists-and-writable probe with no mount reasoning.
func runPreflight(cfg *config.Config) error {
	account := preflightAccountName()
	dirs := []requiredDir{{"data", cfg.DataDir}}
	if cfg.VaultDir != "" && cfg.VaultDir != cfg.DataDir {
		dirs = append(dirs, requiredDir{"vault", cfg.VaultDir})
	}
	if cfg.KeybaseRoot != "" {
		dirs = append(dirs, requiredDir{"keybase root", cfg.KeybaseRoot})
	}
	for _, d := range dirs {
		exists, writable := probeDir(d.path)
		if err := classifyDirProbe(d.label, d.path, account, exists, writable, ""); err != nil {
			return err
		}
	}
	if err := probeRuntimeDir(defaultRuntimeDir()); err != nil {
		return err
	}
	return nil
}

// probeRuntimeDir verifies the unlock-socket runtime directory (defaultRuntimeDir) can
// be created and written to. Unlike the data/vault/keybase directories - which the
// operator creates ahead of time via `init` - the runtime directory is created lazily by
// serve itself the first time it locks (see lockedServe's os.MkdirAll), so a preflight
// that only checked EXISTENCE would misreport a normal first run as a failure. It creates
// the directory (idempotent - a no-op if it already exists) and only then probes
// writability, so a genuine permission problem is caught before the vault key is touched
// instead of surfacing later as a confusing unlock-socket bind failure.
func probeRuntimeDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("runtime directory could not be created: %s: %w", path, err)
	}
	if _, writable := probeDir(path); !writable {
		return fmt.Errorf("runtime directory is not writable: %s", path)
	}
	return nil
}

// preflightAccountName returns this process's Windows account name for preflight
// messages, or a neutral label when it cannot be resolved.
func preflightAccountName() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "this account"
}
