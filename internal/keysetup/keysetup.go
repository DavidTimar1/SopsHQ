// Package keysetup computes how an operating-system account's keystore should be
// prepared for the OS-users flow - and, crucially, never performs a privileged
// action itself.
//
// SopsHQ runs UNPRIVILEGED. It can do only what its own account can do: create and
// own its own keystore folder, and read account facts. Anything that needs root
// (create an account, give it a home, make or own a folder in another account's
// space, symlink into another account's home) is returned here as the exact `sudo`
// commands for the operator to run first - "Mode A", print-commands only. Once the
// operator has run them, SopsHQ proceeds. It NEVER runs these commands.
//
// Account facts (does the account exist? what is its /etc/passwd home?) are read
// with getent on Linux (unprivileged). On platforms without getent (Windows) the
// lookup reports "unsupported" and the caller treats the keystore as a plain folder
// path secured by an ACL.
//
// All strings this package emits are ASCII (they may be printed to a cp1252 console).
package keysetup

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// usernameRe constrains an OS account name to a safe set: a POSIX/service account
// name that starts with a letter, digit, or underscore, continues with letters,
// digits, underscore, dot, or dash, and may end with a single "$" (Windows machine
// accounts). It CANNOT contain whitespace, control characters, any shell
// metacharacter, or a leading dash - so a value that reaches a printed sudo command
// can never carry a command substitution or an option-injection payload.
var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]*\$?$`)

// pathForbidden lists characters a keystore path may never contain. Backslash,
// colon, and space are deliberately allowed so Windows paths (Z:\keys\sops) and
// ordinary folder names keep working; the printed commands single-quote every path
// as defense-in-depth. Control characters and a leading dash are rejected separately.
// `%` and `^` are included because the same value can reach cmd.exe (Windows junction
// creation via mklink), where `^` is the escape character and `%VAR%` triggers
// variable expansion; neither appears in a legitimate keystore path.
const pathForbidden = ";|&$`()<>\"'*?!{}[]%^\n\r"

// ValidUsername reports whether name is a safe OS account name (see usernameRe),
// capped at 32 characters. It gates any value later shown in a Mode-A sudo command.
func ValidUsername(name string) bool {
	if name == "" || len(name) > 32 {
		return false
	}
	return usernameRe.MatchString(name)
}

// ValidKeystorePath reports whether p is safe to store and to interpolate into a
// printed command: no control characters, no shell metacharacter from pathForbidden,
// and no leading dash (which quoting does NOT neutralize - it would be read as an
// option). An empty path is allowed (it means "use the default" / prompt).
func ValidKeystorePath(p string) bool {
	if p == "" {
		return true
	}
	if strings.HasPrefix(p, "-") {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
		if strings.ContainsRune(pathForbidden, r) {
			return false
		}
	}
	return true
}

// shq single-quotes s for a POSIX shell, escaping an embedded single quote the
// standard way (close the quote, add an escaped quote, reopen), so a value
// interpolated into a printed command cannot break out of the quoting.
// Defense-in-depth on top of the boundary validators above.
func shq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// DefaultKeyBase is the keystore folder shown as the form default: the standard sops
// location under the account's home. It resolves only for an account that HAS a home;
// a homeless service account needs an explicit, account-owned path instead.
const DefaultKeyBase = "~/.config/sops/age"

// KeysFile is the private-key filename inside a keystore folder.
const KeysFile = "keys.txt"

// Account is what SopsHQ learned about an OS account from the local system.
type Account struct {
	Username  string // the account name that was looked up
	Supported bool   // the platform can look accounts up (Linux via getent)
	Exists    bool   // the account is present in the account database
	Home      string // the /etc/passwd home field (may be "/nonexistent" or empty)
	HasHome   bool   // Home names a real, existing directory
}

// ParsePasswdHome returns the home-directory field for username from `getent passwd`
// output. Each line is colon-separated: name:passwd:uid:gid:gecos:home:shell. ok is
// false when no line names username or the matching line is malformed. Pure and
// cross-platform, so it is unit-tested on any OS with sample input (never the real
// system).
func ParsePasswdHome(getentOut, username string) (home string, ok bool) {
	for _, line := range strings.Split(getentOut, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		if fields[0] != username {
			continue
		}
		return fields[5], true
	}
	return "", false
}

// DefaultFor returns the standard sops keystore folder under a resolved home
// directory (<home>/.config/sops/age). Used to fill the default for an account that
// has a home.
func DefaultFor(home string) string {
	return filepath.Join(home, ".config", "sops", "age")
}

// ExpandHome replaces a leading "~" in path with the account's home directory. It is
// used to turn the displayed default "~/.config/sops/age" into a real per-account
// path. With an empty home it returns path unchanged (the caller then treats a still
// "~"-prefixed value as unresolved).
func ExpandHome(path, home string) string {
	path = strings.TrimSpace(path)
	if home == "" || path == "" {
		return path
	}
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		return filepath.Join(home, path[2:])
	}
	return path
}

// SymlinkDecision decides whether SopsHQ can create the keystore symlink itself, or
// must print the `sudo ln -s` for the operator. It creates a symlink at linkPath
// (the location sops looks by default) pointing at realFile (the actual keys.txt,
// e.g. on a secure drive). create is true only when SopsHQ's own account can write
// the link's parent directory (canCreate); otherwise command is the exact sudo line
// to print.
func SymlinkDecision(realFile, linkPath string, canCreate bool) (create bool, command string) {
	if canCreate {
		return true, ""
	}
	return false, fmt.Sprintf("sudo ln -s %s %s", shq(realFile), shq(linkPath))
}

// Input is the pure, testable core: given an account and the chosen keystore, it
// produces the ordered Mode-A commands.
type Input struct {
	Username        string
	KeyBase         string  // the keystore folder (already defaulted/expanded)
	Account         Account // account facts (from getent)
	KeyBaseWritable bool    // SopsHQ's own account can create/own KeyBase (i.e. its own account)
}

// keysPath is <keybase>/keys.txt using forward slashes: the printed commands are
// Linux shell commands, so they must not pick up a Windows separator from the host
// SopsHQ happens to run on.
func keysPath(keyBase string) string {
	return strings.TrimRight(keyBase, `/\`) + "/" + KeysFile
}

// homeDir is the conventional /home/<user> path used in the printed useradd/usermod
// commands.
func homeDir(username string) string { return "/home/" + username }

// mkdirOwnCmd is the command to create the keystore folder and hand it to the account
// (owner-only). Used whenever the keystore lives in a space SopsHQ cannot write.
func (in Input) mkdirOwnCmd() string {
	kb := shq(in.KeyBase)
	u := shq(in.Username)
	return fmt.Sprintf("sudo mkdir -p %s && sudo chown %s:%s %s && sudo chmod 700 %s",
		kb, u, u, kb, kb)
}

// Commands returns the ordered Mode-A sudo commands the operator must run before
// SopsHQ can finish preparing this account's keystore, or nil when SopsHQ can do
// everything itself (its own account, with a keystore it can write). The commands are
// guidance only; SopsHQ never runs them.
func (in Input) Commands() []string {
	if !in.Account.Supported || strings.TrimSpace(in.KeyBase) == "" {
		return nil
	}
	var cmds []string
	if !in.Account.Exists {
		// A brand-new account needs creating, with a home so the default keystore
		// works. Its keystore is not in SopsHQ's own space, so it also needs making.
		cmds = append(cmds, fmt.Sprintf("sudo useradd -m -d %s %s", shq(homeDir(in.Username)), shq(in.Username)))
	}
	// When the keystore is not SopsHQ's own account's space, only root can create it
	// and hand it to the account.
	if !in.KeyBaseWritable {
		cmds = append(cmds, in.mkdirOwnCmd())
	}
	return cmds
}

// Plan is the rendered setup guidance for one local OS account: its live status, any
// Mode-A commands to run first, an optional secure-drive symlink command, and
// plain-language notes. It performs nothing; the caller (the OS-users page) renders
// it so the operator can act.
type Plan struct {
	Supported  bool     // Linux with getent (false on Windows: account facts unavailable)
	Exists     bool     // the account exists on this machine
	HasHome    bool     // the account has a usable home directory
	Home       string   // the account's home (from getent), for display
	KeyBase    string   // the keystore folder SopsHQ will use for this account
	Commands   []string // Mode-A sudo commands to run first (may be empty)
	SymlinkCmd string   // sudo ln -s to run when SopsHQ cannot create the default-location symlink (may be empty)
	Notes      []string // plain-language guidance (may be empty)
}

// NeedsOperator reports that the operator has something to run or read before the
// keystore is ready (used to decide whether to surface the guidance block).
func (p Plan) NeedsOperator() bool {
	return len(p.Commands) > 0 || p.SymlinkCmd != "" || len(p.Notes) > 0
}

// Compute builds the setup guidance for one OS account on THIS machine. own is true
// when SopsHQ runs as this same account, so it can create and own the keystore (and
// the default-location symlink) itself without any sudo. It performs the getent
// lookup via LookupAccount and never touches disk beyond that read.
func Compute(username, keyBase string, own bool) Plan {
	a := LookupAccount(username)
	p := Plan{Supported: a.Supported, Exists: a.Exists, HasHome: a.HasHome, Home: a.Home, KeyBase: keyBase}
	if !a.Supported {
		p.Notes = append(p.Notes,
			"Account checks are Linux-only; on this machine SopsHQ treats the keystore as a plain folder path. Make sure "+keyBase+" is owned by and readable only by "+username+".")
		return p
	}
	if strings.TrimSpace(keyBase) == "" {
		p.Notes = append(p.Notes,
			"This account needs an explicit, account-owned keystore folder (for example /etc/"+username+"/keys). Set one above.")
		return p
	}
	in := Input{Username: username, KeyBase: keyBase, Account: a, KeyBaseWritable: own}
	p.Commands = in.Commands()

	// sops with no SOPS_AGE_KEY_FILE reads <home>/.config/sops/age/keys.txt. When the
	// keystore is elsewhere (for example a secure drive) and the account has a home,
	// that default path should be a symlink to the real keys.txt. SopsHQ creates the
	// link itself for its own account; for another account's home only root can, so it
	// prints the command.
	if a.HasHome {
		defaultLink := keysPath(DefaultFor(a.Home))
		realFile := keysPath(keyBase)
		if defaultLink != realFile {
			if create, cmd := SymlinkDecision(realFile, defaultLink, own); !create {
				p.SymlinkCmd = cmd
			}
		}
	} else {
		p.Notes = append(p.Notes,
			"This account has no home, so the "+DefaultKeyBase+" default does not apply. Point its program at the keystore with SOPS_AGE_KEY_FILE="+keysPath(keyBase)+".")
	}
	return p
}
