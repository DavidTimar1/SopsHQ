//go:build windows

package access

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// readTokens are icacls permission tokens that imply read access.
var readTokens = map[string]bool{
	"f": true, "m": true, "rx": true, "r": true, "rd": true, "rea": true,
	"gr": true, "ga": true,
}

// CanReadDir (Windows) reads the directory's DACL with the built-in `icacls` tool
// and looks for a read grant to the user or a broad group they belong to. Windows
// effective access (deny-ACE ordering, inheritance, nested groups) is not fully
// evaluated, so a "no match" is reported as not-evaluated rather than a hard deny.
func CanReadDir(username, dir string) Result {
	if _, err := os.Stat(dir); err != nil {
		return Result{OK: true, Evaluated: false,
			Reason: fmt.Sprintf("%s does not exist yet (will be created)", dir)}
	}
	out, err := exec.Command("icacls", dir).CombinedOutput()
	if err != nil {
		return Result{OK: true, Evaluated: false,
			Reason: "could not read the ACL via icacls (best-effort skipped)"}
	}

	// Principals that would grant this user read: the user (with and without any
	// DOMAIN\ prefix) plus the broad groups most setups rely on.
	cands := []string{strings.ToLower(username)}
	if i := strings.LastIndex(username, `\`); i >= 0 {
		cands = append(cands, strings.ToLower(username[i+1:]))
	}
	cands = append(cands, "everyone", "authenticated users", "users")

	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.ToLower(strings.TrimSpace(raw))
		for _, c := range cands {
			marker := c + ":("
			idx := strings.Index(line, marker)
			if idx < 0 {
				continue
			}
			if grantsRead(line[idx+len(marker):]) {
				return Result{OK: true, Evaluated: true,
					Reason: fmt.Sprintf("icacls shows read access for %q on %s", c, dir)}
			}
		}
	}
	return Result{OK: true, Evaluated: false,
		Reason: fmt.Sprintf("icacls shows no obvious read grant for %q on %s (Windows effective access is best-effort; check deny rules/inheritance manually)", username, dir)}
}

// grantsRead reports whether the icacls permission portion (everything after a
// "principal:(") contains a read-implying token. Inheritance flags (OI/CI/IO) and
// non-read rights are ignored.
func grantsRead(perms string) bool {
	repl := strings.NewReplacer("(", " ", ")", " ", ",", " ")
	for _, tok := range strings.Fields(repl.Replace(perms)) {
		if readTokens[tok] {
			return true
		}
	}
	return false
}
