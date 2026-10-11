//go:build !linux

package keysetup

// LookupAccount reports that account facts cannot be read on this platform (no
// getent - for example Windows). The caller then treats the keystore as a plain
// folder path secured by an ACL and does not print Linux account commands.
func LookupAccount(username string) Account {
	return Account{Username: username, Supported: false}
}
