//go:build windows

package main

import (
	"fmt"
	"os/exec"
)

// addUserPath appends dir to the CURRENT USER's persistent PATH (HKCU\Environment),
// preserving the existing value and its registry type. It edits only the user-scope
// value - never the machine PATH - and never rewrites the merged %PATH% (the setx
// pattern), which is what truncates long PATHs. The change applies to terminals
// opened after the write; already-open shells keep their old environment.
func addUserPath(dir string) error {
	cur, regType, ok := "", "REG_EXPAND_SZ", false
	if out, err := exec.Command("reg", "query", `HKCU\Environment`, "/v", "Path").Output(); err == nil {
		cur, regType, ok = parseRegQueryPath(string(out))
		if !ok {
			regType = "REG_EXPAND_SZ"
		}
	}
	merged, changed := mergeUserPath(cur, dir)
	if !changed {
		return nil
	}
	out, err := exec.Command("reg", "add", `HKCU\Environment`, "/v", "Path", "/t", regType, "/d", merged, "/f").CombinedOutput()
	if err != nil {
		return fmt.Errorf("write user PATH: %v: %s", err, out)
	}
	return nil
}
