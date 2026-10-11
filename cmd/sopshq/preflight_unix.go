//go:build unix

package main

import (
	"bufio"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"sopshq/internal/config"
)

// runPreflight verifies, BEFORE the vault key is acquired, that serve can actually write
// everywhere it needs to: the data directory, the (usually identical) vault directory,
// and the keybase root when one is configured. It returns the first failure as a clear,
// path-naming error - "directory does not exist" or "not writable" rather than the
// misleading read-only-filesystem message the systemd sandbox would otherwise produce -
// so a broken mount or a permission gap stops serve before it touches the key.
func runPreflight(cfg *config.Config) error {
	account := preflightAccountName()
	mounts := readMountpoints()
	isMounted := func(dir string) bool { return mounts[dir] }

	dirs := []requiredDir{{"data", cfg.DataDir}}
	if cfg.VaultDir != "" && cfg.VaultDir != cfg.DataDir {
		dirs = append(dirs, requiredDir{"vault", cfg.VaultDir})
	}
	if cfg.KeybaseRoot != "" {
		dirs = append(dirs, requiredDir{"keybase root", cfg.KeybaseRoot})
	}
	for _, d := range dirs {
		exists, writable := probeDir(d.path)
		hint := ""
		if !exists {
			hint = unmountedMountHint(d.path, isMounted)
		}
		if err := classifyDirProbe(d.label, d.path, account, exists, writable, hint); err != nil {
			return err
		}
	}
	return nil
}

// preflightAccountName returns this process's account name for preflight messages, or
// its numeric uid when the name cannot be resolved.
func preflightAccountName() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return strconv.Itoa(os.Getuid())
}

// readMountpoints returns the set of directories that are currently mount points, read
// from /proc/self/mounts. An unreadable mounts file yields an empty set (the mount hint
// then simply stays silent). The second whitespace field is the mount point; mount
// points with spaces are encoded as \040, which is decoded here.
func readMountpoints() map[string]bool {
	out := map[string]bool{}
	f, err := os.Open("/proc/self/mounts")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		out[decodeMountField(fields[1])] = true
	}
	return out
}

// decodeMountField decodes the octal escapes (\040 space, \011 tab, \012 newline, \134
// backslash) that /proc/self/mounts uses in path fields, so a mount point path matches
// filepath.Clean output.
func decodeMountField(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseInt(s[i+1:i+4], 8, 16); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return filepath.Clean(b.String())
}
