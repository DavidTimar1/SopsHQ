//go:build linux

package place

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// aclSupported reports whether setfacl/getfacl exist and the given directory's
// filesystem accepts an ACL. Integration tests skip when it returns false, so a CI
// runner on a filesystem mounted without ACL support (or without the acl package) does
// not fail the suite.
func aclSupported(t *testing.T, dir, username string) bool {
	t.Helper()
	if _, err := exec.LookPath("setfacl"); err != nil {
		return false
	}
	if _, err := exec.LookPath("getfacl"); err != nil {
		return false
	}
	probe := filepath.Join(dir, "probe")
	if err := os.WriteFile(probe, []byte("x"), 0o600); err != nil {
		return false
	}
	defer os.Remove(probe)
	if out, err := exec.Command("setfacl", "-m", "u:"+username+":r", probe).CombinedOutput(); err != nil {
		t.Logf("ACL not supported here: %v: %s", err, strings.TrimSpace(string(out)))
		return false
	}
	return true
}

// TestApplyKeystoreACLGrantsSelf places a key into a shared-root key store for the
// CURRENT user (a real account setfacl accepts) and verifies place.Place both applies
// and confirms the ACL grants. It skips when the filesystem has no ACL support.
func TestApplyKeystoreACLGrantsSelf(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skipf("cannot resolve current user: %v", err)
	}
	root := t.TempDir() // owned by the test account -> checkSharedRoot passes
	if !aclSupported(t, root, cur.Username) {
		t.Skip("filesystem has no POSIX ACL support (or acl tools missing)")
	}
	base := filepath.Join(root, cur.Username)
	o := Opts{
		Base:        base,
		Recipient:   "age1examplerecipientexampleexampleexampleexampleexampleex",
		Private:     "AGE-SECRET-KEY-1EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE",
		Username:    cur.Username,
		KeybaseRoot: root,
	}
	if err := Place(o); err != nil {
		t.Fatalf("Place with shared root should succeed and verify ACLs: %v", err)
	}

	// The key file exists and getfacl confirms the read grant for the user.
	out, err := exec.Command("getfacl", "-c", KeyFile(base)).Output()
	if err != nil {
		t.Fatalf("getfacl keys.txt: %v", err)
	}
	parsed := parseGetfacl(out, cur.Username)
	if !aclSatisfied(parsed, aclEntry{def: false, perms: "r--"}) {
		t.Fatalf("keys.txt should grant %s read; getfacl:\n%s", cur.Username, out)
	}

	// Mutual privacy: a DIFFERENT (sibling) user has no ACL entry on the root or the
	// subfolder, and "other" has no filesystem bits, so no local account but the owner
	// can traverse or read another's store. (We cannot create a second real account in a
	// unit test, so we assert the ABSENCE of any sibling grant rather than a live denial.)
	const sibling = "sopshq-sibling-none"
	for _, p := range []string{root, base} {
		g, err := exec.Command("getfacl", "-c", p).Output()
		if err != nil {
			t.Fatalf("getfacl %q: %v", p, err)
		}
		if got := parseGetfacl(g, sibling); len(got) != 0 {
			t.Fatalf("no sibling grant expected on %q; got %+v", p, got)
		}
	}
	if fi, err := os.Stat(base); err != nil {
		t.Fatalf("stat base: %v", err)
	} else if fi.Mode().Perm()&0o007 != 0 {
		t.Fatalf("subfolder must give 'other' no bits; mode %v", fi.Mode().Perm())
	}

	// A temp+rename inside the store (how SOPS rewrites secrets.yaml) inherits the
	// default ACL, so the user keeps read on the newly named file with no re-grant.
	tmp := filepath.Join(base, "rewrite.tmp")
	if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	final := filepath.Join(base, "rewrite.yaml")
	if err := os.Rename(tmp, final); err != nil {
		t.Fatalf("rename temp: %v", err)
	}
	fg, err := exec.Command("getfacl", "-c", final).Output()
	if err != nil {
		t.Fatalf("getfacl renamed file: %v", err)
	}
	if !aclSatisfied(parseGetfacl(fg, cur.Username), aclEntry{def: false, perms: "r--"}) {
		t.Fatalf("temp+rename should inherit the default read grant; getfacl:\n%s", fg)
	}

	// The owner can traverse+read their own global-set subdir and read the copy in it.
	globalDir := filepath.Join(base, "global")
	setDir := filepath.Join(globalDir, "ci")
	if err := os.MkdirAll(setDir, 0o700); err != nil {
		t.Fatalf("mkdir global set dir: %v", err)
	}
	secret := filepath.Join(setDir, "secrets.yaml")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatalf("write set secret: %v", err)
	}
	if err := ApplyGlobalSetACL(GlobalSetACLOpts{
		Username: cur.Username, GlobalDir: globalDir, SetDir: setDir, Files: []string{secret},
	}); err != nil {
		t.Fatalf("ApplyGlobalSetACL should grant and verify: %v", err)
	}
	sg, err := exec.Command("getfacl", "-c", setDir).Output()
	if err != nil {
		t.Fatalf("getfacl set dir: %v", err)
	}
	if !aclSatisfied(parseGetfacl(sg, cur.Username), aclEntry{def: false, perms: "r-x"}) {
		t.Fatalf("set dir should grant %s traverse+read; getfacl:\n%s", cur.Username, sg)
	}
	xg, err := exec.Command("getfacl", "-c", secret).Output()
	if err != nil {
		t.Fatalf("getfacl set secret: %v", err)
	}
	if !aclSatisfied(parseGetfacl(xg, cur.Username), aclEntry{def: false, perms: "r--"}) {
		t.Fatalf("set secret should grant %s read; getfacl:\n%s", cur.Username, xg)
	}
}

// TestCheckSharedRootMissing checks placement into a shared root refuses loudly (with
// the sudo remediation) when the root does not exist, and never creates it.
func TestCheckSharedRootMissing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "does-not-exist")
	err := checkSharedRoot(root)
	if err == nil {
		t.Fatal("checkSharedRoot should fail for a missing root")
	}
	if !strings.Contains(err.Error(), "sudo mkdir") {
		t.Fatalf("error should carry the sudo remediation; got %v", err)
	}
	if _, serr := os.Stat(root); !os.IsNotExist(serr) {
		t.Fatal("checkSharedRoot must not create the root")
	}
}
