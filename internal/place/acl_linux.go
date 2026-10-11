//go:build linux

package place

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

// checkSharedRoot verifies the shared keybase root exists and is owned by the SopsHQ
// service account (the process user), WITHOUT creating or modifying it. SopsHQ never
// creates the root itself: it lives on an encrypted volume the operator prepares once.
// When the root is missing or owned by another account, it returns a loud error that
// carries the exact one-time sudo commands to create and hand it over.
func checkSharedRoot(root string) error {
	fi, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("place: shared keybase root %q is not present. Create it once as root:\n%s",
			root, strings.Join(sharedRootSudo(root, currentUsername()), "\n"))
	}
	if !fi.IsDir() {
		return fmt.Errorf("place: shared keybase root %q is not a directory", root)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("place: cannot read ownership of shared keybase root %q", root)
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("place: shared keybase root %q is not owned by this account (%s). Hand it over as root:\n%s",
			root, currentUsername(), strings.Join(sharedRootSudo(root, currentUsername()), "\n"))
	}
	return nil
}

// applyKeystoreACL grants the target OS user read access to their own key under the
// shared keybase root via POSIX ACLs, then VERIFIES the grants with getfacl. Every
// failure path is loud: a missing setfacl/getfacl, an EPERM, a filesystem without ACL
// support, or a grant that verification cannot confirm all return an error that names
// the exact remediation commands, so the caller never treats an ungranted key store as
// managed.
func applyKeystoreACL(o Opts) error {
	return applyACLEntries(o.Username, keystoreACLEntries(o.KeybaseRoot, o.Base, KeyFile(o.Base)))
}

// verifyKeystoreACL reads back the ACLs with getfacl and confirms every intended grant
// is present. It is the check half of the verification/drift step and is also reused by
// the drift scan: a root-derived key store whose ACLs do not verify is reported rather
// than trusted. A missing or unconfirmable grant returns a loud, remediation-bearing
// error.
func verifyKeystoreACL(o Opts) error {
	return verifyACLEntries(o.Username, keystoreACLEntries(o.KeybaseRoot, o.Base, KeyFile(o.Base)))
}

// ApplyGlobalSetACL grants a root-derived recipient traverse+read on the shared-set
// dirs ("<base>/global" and "<base>/global/<set>") plus read on the already-written
// secret files, then VERIFIES with getfacl. Without it the recipient - whose only grant
// on the subtree is the base subfolder's default read - cannot traverse into "global/"
// and "sops -d" on their own copy is denied. It fails loud on the same paths as
// applyKeystoreACL (tools missing, no ACL support, EPERM, or an unverifiable grant).
func ApplyGlobalSetACL(o GlobalSetACLOpts) error {
	return applyACLEntries(o.Username, globalSetACLEntries(o))
}

// applyACLEntries places each ACL entry for username with setfacl (fixed argv, no
// shell), then verifies the result. It is the shared exec core for every root-derived
// ACL grant. Any failure returns an error carrying the exact setfacl/sudo remediation.
func applyACLEntries(username string, entries []aclEntry) error {
	if username == "" {
		return fmt.Errorf("place: shared keybase root ACL placement requires a target username")
	}
	if _, err := exec.LookPath("setfacl"); err != nil {
		return aclToolMissing("setfacl", username, entries)
	}
	if _, err := exec.LookPath("getfacl"); err != nil {
		return aclToolMissing("getfacl", username, entries)
	}
	for _, e := range entries {
		argv := setfaclArgv(username, e)
		if out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("place: could not set the ACL on %q (%v: %s). "+
				"The filesystem may not support ACLs, or this account lacks permission. Run:\n%s",
				e.path, err, strings.TrimSpace(string(out)), strings.Join(aclRemediation(username, entries), "\n"))
		}
	}
	return verifyACLEntries(username, entries)
}

// verifyACLEntries reads back the ACLs with getfacl and confirms every intended grant is
// present for username. A missing or unconfirmable grant returns a loud,
// remediation-bearing error rather than trusting an unverified grant.
func verifyACLEntries(username string, entries []aclEntry) error {
	// getfacl is read once per distinct path.
	byPath := map[string][]parsedACL{}
	for _, e := range entries {
		if _, done := byPath[e.path]; done {
			continue
		}
		argv := getfaclArgv(e.path)
		out, err := exec.Command(argv[0], argv[1:]...).Output()
		if err != nil {
			return fmt.Errorf("place: could not read the ACL of %q to verify it (%v). Run:\n%s",
				e.path, err, strings.Join(aclRemediation(username, entries), "\n"))
		}
		byPath[e.path] = parseGetfacl(out, username)
	}
	for _, e := range entries {
		if !aclSatisfied(byPath[e.path], e) {
			return fmt.Errorf("place: the ACL grant for %q on %q could not be verified; it is NOT managed. Run:\n%s",
				username, e.path, strings.Join(aclRemediation(username, entries), "\n"))
		}
	}
	return nil
}

// aclToolMissing builds the loud error returned when setfacl or getfacl is absent.
func aclToolMissing(tool, username string, entries []aclEntry) error {
	return fmt.Errorf("place: %s is not installed, so the shared keybase root ACLs cannot be applied. "+
		"Install acl (e.g. apt-get install acl) and re-apply, or grant access by hand:\n%s",
		tool, strings.Join(aclRemediation(username, entries), "\n"))
}

// currentUsername returns the process account name for the printed remediation, or its
// numeric uid when the name cannot be resolved.
func currentUsername() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return strconv.Itoa(os.Geteuid())
}
