//go:build windows

package place

import (
	"fmt"
	"os"
)

// The keybase root works on Windows as a plain, ACL-free keys root: each OS user's
// store lives at "<root>\<username>\keys.txt", exactly the Linux layout, but nothing
// grants or verifies per-user read access - a Windows SopsHQ machine runs as one
// account, which owns the whole subtree through ordinary NTFS inheritance. The
// POSIX-ACL steps below are therefore no-ops rather than refusals.

// checkSharedRoot verifies the keys root exists and is a directory, WITHOUT creating
// or modifying it. Ownership and ACLs are not checked on Windows.
func checkSharedRoot(root string) error {
	fi, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("place: keys root %s does not exist - create the folder first: %w", root, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("place: keys root %s is not a directory", root)
	}
	return nil
}

// applyKeystoreACL is a no-op on Windows: there is no per-user ACL step to apply on a
// single-account machine.
func applyKeystoreACL(o Opts) error { return nil }

// verifyKeystoreACL verifies only what Windows guarantees: the root is present. The
// per-user read-grant checks are Linux (POSIX ACL) semantics.
func verifyKeystoreACL(o Opts) error { return checkSharedRoot(o.KeybaseRoot) }

// ApplyGlobalSetACL is a no-op on Windows: the recipient account already reads the
// shared-set files through ordinary ownership, with no traverse grants to add.
func ApplyGlobalSetACL(o GlobalSetACLOpts) error { return nil }
