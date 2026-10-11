//go:build windows

package access

import "testing"

// TestGrantsRead checks the icacls permission-token reader (read-implying rights
// vs write/deny/inheritance-only).
func TestGrantsRead(t *testing.T) {
	read := []string{"rx)", "f)", "m)", "oi)(ci)(rx)", "r,rea)", "gr)", "ga)", "rd)"}
	notRead := []string{"w)", "d)", "oi)(ci)", "wd)", "", "ad)"}
	for _, s := range read {
		if !grantsRead(s) {
			t.Errorf("grantsRead(%q) = false, want true", s)
		}
	}
	for _, s := range notRead {
		if grantsRead(s) {
			t.Errorf("grantsRead(%q) = true, want false", s)
		}
	}
}
