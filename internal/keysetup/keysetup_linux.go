//go:build linux

package keysetup

import (
	"os"
	"os/exec"
)

// LookupAccount reads account facts from the local system with getent (unprivileged).
// getent consults the same account databases as login does (files, LDAP, ...), so it
// sees service/daemon accounts a plain /etc/passwd read might miss. It NEVER changes
// anything and needs no privilege.
//
// A non-zero getent exit (code 2) means "not found"; SopsHQ reports the account as
// not existing. Output is decoded as UTF-8 (the gecos field can hold non-ASCII); only
// the home field is used.
func LookupAccount(username string) Account {
	a := Account{Username: username, Supported: true}
	out, err := exec.Command("getent", "passwd", username).Output()
	if err != nil {
		return a // not found (or getent unavailable): Exists stays false
	}
	home, ok := ParsePasswdHome(string(out), username)
	if !ok {
		return a
	}
	a.Exists = true
	a.Home = home
	if home != "" {
		if fi, statErr := os.Stat(home); statErr == nil && fi.IsDir() {
			a.HasHome = true
		}
	}
	return a
}
