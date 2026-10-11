//go:build !unix

package main

// dirOwnerUID has no Unix file-owner concept on this platform (for example Windows),
// so it reports the owner as unknown and the serve guard skips the ownership check.
func dirOwnerUID(path string) (uid int, ok bool) {
	return 0, false
}
