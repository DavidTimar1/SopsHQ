package main

import (
	"os"
	"os/exec"
	"strings"
)

// sopshqOnPath reports whether typing `sopshq` in a fresh shell would run the given
// binary: it resolves `sopshq` through PATH and compares the result to bin by file
// identity (following symlinks), so both the Windows PATH-entry case and the Linux
// /usr/local/bin-symlink case count as "already reachable".
func sopshqOnPath(bin string) bool {
	found, err := exec.LookPath("sopshq")
	if err != nil {
		return false
	}
	fi1, err := os.Stat(found)
	if err != nil {
		return false
	}
	fi2, err := os.Stat(bin)
	if err != nil {
		return false
	}
	return os.SameFile(fi1, fi2)
}

// parseRegQueryPath extracts the user PATH value and its registry type from
// `reg query HKCU\Environment /v Path` output. The value line looks like
// "    Path    REG_EXPAND_SZ    C:\a;C:\b" - the value is everything after the
// type token, so paths containing spaces survive. ok is false when no Path value
// is present (a fresh profile has none).
func parseRegQueryPath(out string) (value, regType string, ok bool) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "Path") && strings.HasPrefix(fields[1], "REG_") {
			regType = fields[1]
			idx := strings.Index(line, regType) + len(regType)
			return strings.TrimSpace(line[idx:]), regType, true
		}
	}
	return "", "", false
}

// mergeUserPath returns cur with dir appended as a new ";"-separated entry, and
// reports whether anything changed: when dir is already listed (compared
// case-insensitively, ignoring a trailing separator) cur comes back unchanged.
func mergeUserPath(cur, dir string) (string, bool) {
	norm := func(p string) string {
		return strings.ToLower(strings.TrimRight(strings.TrimSpace(p), `\/`))
	}
	for _, entry := range strings.Split(cur, ";") {
		if norm(entry) != "" && norm(entry) == norm(dir) {
			return cur, false
		}
	}
	if strings.TrimSpace(cur) == "" {
		return dir, true
	}
	return strings.TrimRight(cur, ";") + ";" + dir, true
}
