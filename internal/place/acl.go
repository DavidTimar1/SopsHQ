package place

// This file holds the OS-INDEPENDENT core of the shared-keybase-root POSIX ACL
// step: which ACL entries a root-derived key store needs, how to build the setfacl
// argv for each (a plain string slice - never a shell command line), how to parse
// getfacl output to verify them, and the exact sudo remediation printed when the
// step cannot be completed. The actual exec of setfacl/getfacl and the root
// ownership check live in acl_linux.go (real) and acl_windows.go (unsupported).
//
// Splitting DECISION from EFFECT lets the argv building and the getfacl parsing be
// unit-tested on any OS with plain strings - no real setfacl, getfacl, or ACL-
// capable filesystem is ever touched by a test of these pure helpers.

import "strings"

// aclEntry is one POSIX ACL grant SopsHQ places for the target OS user so that user
// - and only that user - can read their own key under a shared keybase root.
type aclEntry struct {
	// path is the file or directory the entry applies to.
	path string
	// def marks a DEFAULT ACL entry (setfacl -d): it is inherited by files created
	// later in a directory, so SOPS's temp-file+rename keeps the user's grant.
	def bool
	// perms is the rwx triplet in ASCII ("r--", "r-x", "--x"). A '-' means "not this
	// bit"; verification checks only the bits that are set.
	perms string
}

// GlobalSetACLOpts describes the on-disk global-set dirs a root-derived recipient
// needs read access to. A shared (global) secret set lives at
// SetDir = "<base>/global/<set>", inside GlobalDir = "<base>/global". Both dirs are
// created 0700 and owned by the SopsHQ account, so - exactly like the key store - the
// recipient needs an explicit POSIX ACL to traverse in and read their own copy.
// Files are the already-written secret files inside SetDir (secrets.yaml, .sops.yaml)
// that also need a read grant; a file created later is covered by the SetDir default.
type GlobalSetACLOpts struct {
	// Username is the recipient OS account. ValidUsername-validated by the caller.
	Username string
	// GlobalDir is "<base>/global". ValidKeystorePath-validated by the caller.
	GlobalDir string
	// SetDir is "<base>/global/<set>". ValidKeystorePath-validated by the caller.
	SetDir string
	// Files are existing secret files inside SetDir to grant read on (may be empty).
	Files []string
}

// globalSetACLEntries returns the ACL grants a root-derived recipient needs to reach
// and read ONLY their own copy of a shared secret set:
//
//   - "r-x" on "<base>/global": traverse in + read.
//   - "r-x" on "<base>/global/<set>": traverse in + read.
//   - a DEFAULT "r--" on both dirs, so a file created later (SOPS temp+rename of
//     secrets.yaml/.sops.yaml) inherits the read grant without a re-grant.
//   - "r--" on each already-written secret file.
//
// It mirrors keystoreACLEntries: the recipient can read their copy, but the files stay
// owned by the SopsHQ account and no cross-account write is ever needed.
func globalSetACLEntries(o GlobalSetACLOpts) []aclEntry {
	entries := []aclEntry{
		{path: o.GlobalDir, def: false, perms: "r-x"},
		{path: o.GlobalDir, def: true, perms: "r--"},
		{path: o.SetDir, def: false, perms: "r-x"},
		{path: o.SetDir, def: true, perms: "r--"},
	}
	for _, f := range o.Files {
		entries = append(entries, aclEntry{path: f, def: false, perms: "r--"})
	}
	return entries
}

// keystoreACLEntries returns the ACL grants a root-derived key store needs so the
// target user can reach and read ONLY their own key:
//
//   - "--x" on the shared root: traverse INTO their own subfolder without being able
//     to list or read siblings (mutual privacy between users).
//   - "r-x" on their subfolder: enter and list it.
//   - "r--" on keys.txt: read their own private key.
//   - a DEFAULT "r--" on their subfolder: a file created there later (SOPS temp+rename)
//     is readable by the user without a re-grant.
//
// root is the shared keybase root, base is "<root>/<username>", keyFile is the key
// file inside base. All three are already ValidKeystorePath-validated by the caller.
func keystoreACLEntries(root, base, keyFile string) []aclEntry {
	return []aclEntry{
		{path: root, def: false, perms: "--x"},
		{path: base, def: false, perms: "r-x"},
		{path: keyFile, def: false, perms: "r--"},
		{path: base, def: true, perms: "r--"},
	}
}

// setfaclArgv builds the exact argv for setfacl to place one entry for username. It
// is a plain slice run WITHOUT a shell, so the username and path are passed as single
// arguments and can never be re-parsed as shell syntax. The username is
// ValidUsername-validated and the path ValidKeystorePath-validated by the caller.
func setfaclArgv(username string, e aclEntry) []string {
	argv := []string{"setfacl"}
	if e.def {
		argv = append(argv, "-d")
	}
	argv = append(argv, "-m", "u:"+username+":"+e.perms, e.path)
	return argv
}

// getfaclArgv builds the argv to read a path's ACL for verification. "-c" omits the
// comment header so the parser sees only entry lines; "-E" is not used (portability).
func getfaclArgv(path string) []string {
	return []string{"getfacl", "-c", path}
}

// parsedACL is one named-user ACL entry read back from getfacl.
type parsedACL struct {
	def   bool   // a "default:" entry
	perms string // the rwx triplet as printed (e.g. "r-x")
}

// parseGetfacl extracts the named-user entries for username from getfacl output. It
// reads both access entries ("user:alice:r-x") and default entries
// ("default:user:alice:r--"), ignoring the owning-user entry ("user::rw-", which has
// an empty name) and every other line. It is defensive: unknown or malformed lines
// are skipped, and the input is treated as UTF-8 text (getfacl may print non-ASCII in
// a comment, which -c already strips). It never errors - a caller that finds no
// matching entry treats the grant as absent and fails loud.
func parseGetfacl(out []byte, username string) []parsedACL {
	var res []parsedACL
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		def := false
		if rest, ok := strings.CutPrefix(line, "default:"); ok {
			def = true
			line = rest
		}
		name, ok := strings.CutPrefix(line, "user:")
		if !ok {
			continue // not a named-user entry (group/mask/other/owner-user)
		}
		// name is now "<username>:<perms>[#effective:...]"; the owner-user entry is
		// "user::<perms>" -> name begins with ":" (empty username) and is skipped.
		i := strings.IndexByte(name, ':')
		if i <= 0 {
			continue
		}
		if name[:i] != username {
			continue
		}
		perms := name[i+1:]
		if j := strings.IndexByte(perms, '#'); j >= 0 { // drop "#effective:" suffix
			perms = strings.TrimSpace(perms[:j])
		}
		perms = strings.TrimSpace(perms)
		if len(perms) < 3 {
			continue
		}
		res = append(res, parsedACL{def: def, perms: perms[:3]})
	}
	return res
}

// permsInclude reports whether have grants every bit set in want. Each is an rwx
// triplet; a '-' in want means "do not care". So permsInclude("r-x", "r--") is true
// (r is present) and permsInclude("--x", "r--") is false (r is missing).
func permsInclude(have, want string) bool {
	if len(have) < 3 || len(want) < 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		if want[i] != '-' && have[i] != want[i] {
			return false
		}
	}
	return true
}

// aclSatisfied reports whether the entries read back from getfacl for a path grant
// the target user at least the bits the intended entry wants, matching on whether it
// is a default entry. It is the verification predicate: a grant that setfacl claimed
// to place but getfacl does not confirm is treated as NOT satisfied (fail loud).
func aclSatisfied(parsed []parsedACL, want aclEntry) bool {
	for _, p := range parsed {
		if p.def == want.def && permsInclude(p.perms, want.perms) {
			return true
		}
	}
	return false
}

// aclRemediation returns the exact sudo commands an operator can run to place the ACL
// entries by hand when SopsHQ cannot (setfacl missing, no ACL support, or EPERM).
// Each path is single-quoted so a path with spaces pastes correctly; the values are
// already validated to carry no shell metacharacter, so the quoting is belt-and-suspenders.
func aclRemediation(username string, entries []aclEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		flag := ""
		if e.def {
			flag = "-d "
		}
		out = append(out, "sudo setfacl "+flag+"-m u:"+username+":"+e.perms+" "+shellQuote(e.path))
	}
	return out
}

// sharedRootSudo returns the one-time commands to create and hand a shared keybase
// root to the SopsHQ service account. SopsHQ never runs these; it prints them when the
// root is missing or not owned by its account.
func sharedRootSudo(root, sopshqUser string) []string {
	return []string{
		"sudo mkdir -p " + shellQuote(root),
		"sudo chown " + sopshqUser + " " + shellQuote(root),
		// 0711: each enrolled user can TRAVERSE the root to reach their own subfolder
		// (the per-user "--x" ACL is belt-and-suspenders), but "other" cannot LIST it, so
		// no local user can enumerate the usernames of everyone with a key store here.
		"sudo chmod 0711 " + shellQuote(root),
	}
}

// shellQuote single-quotes s for a POSIX shell, escaping an embedded single quote the
// standard way, so a printed remediation command is safe to copy into a root shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
