package place

import (
	"reflect"
	"strings"
	"testing"
)

// TestKeystoreACLEntries checks the intended ACL entries for a root-derived key store:
// traverse-only on the root, enter+list on the user's subfolder, read on keys.txt, and
// a default read grant on the subfolder so temp+rename inherits it.
func TestKeystoreACLEntries(t *testing.T) {
	root := "/srv/sopshq-keys"
	base := "/srv/sopshq-keys/dev"
	keyFile := "/srv/sopshq-keys/dev/keys.txt"
	got := keystoreACLEntries(root, base, keyFile)
	want := []aclEntry{
		{path: root, def: false, perms: "--x"},
		{path: base, def: false, perms: "r-x"},
		{path: keyFile, def: false, perms: "r--"},
		{path: base, def: true, perms: "r--"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("entries mismatch\n got %+v\nwant %+v", got, want)
	}
}

// TestGlobalSetACLEntries checks the ACL entries a root-derived recipient needs to read
// their own copy of a shared secret set: traverse+read on the "global" dir and the set
// dir, a default read on each so temp+rename inherits it, and read on each existing
// secret file.
func TestGlobalSetACLEntries(t *testing.T) {
	globalDir := "/srv/sopshq-keys/dev/global"
	setDir := "/srv/sopshq-keys/dev/global/ci"
	got := globalSetACLEntries(GlobalSetACLOpts{
		Username:  "dev",
		GlobalDir: globalDir,
		SetDir:    setDir,
		Files:     []string{setDir + "/secrets.yaml", setDir + "/.sops.yaml"},
	})
	want := []aclEntry{
		{path: globalDir, def: false, perms: "r-x"},
		{path: globalDir, def: true, perms: "r--"},
		{path: setDir, def: false, perms: "r-x"},
		{path: setDir, def: true, perms: "r--"},
		{path: setDir + "/secrets.yaml", def: false, perms: "r--"},
		{path: setDir + "/.sops.yaml", def: false, perms: "r--"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("global-set entries mismatch\n got %+v\nwant %+v", got, want)
	}

	// With no files yet (first ensureSetDirs, before secrets.yaml exists) only the two
	// dirs are granted; the default entries cover a file created later.
	bare := globalSetACLEntries(GlobalSetACLOpts{Username: "dev", GlobalDir: globalDir, SetDir: setDir})
	if len(bare) != 4 {
		t.Fatalf("expected 4 dir entries with no files; got %d (%+v)", len(bare), bare)
	}
}

// TestSetfaclArgv checks the argv is a plain slice (no shell), with the "-d" flag only
// for a default entry and the user/perms/path each passed as their own argument so they
// can never be re-parsed as shell syntax.
func TestSetfaclArgv(t *testing.T) {
	access := setfaclArgv("dev", aclEntry{path: "/srv/sopshq-keys/dev/keys.txt", perms: "r--"})
	wantAccess := []string{"setfacl", "-m", "u:dev:r--", "/srv/sopshq-keys/dev/keys.txt"}
	if !reflect.DeepEqual(access, wantAccess) {
		t.Fatalf("access argv\n got %v\nwant %v", access, wantAccess)
	}
	def := setfaclArgv("dev", aclEntry{path: "/srv/sopshq-keys/dev", def: true, perms: "r--"})
	wantDef := []string{"setfacl", "-d", "-m", "u:dev:r--", "/srv/sopshq-keys/dev"}
	if !reflect.DeepEqual(def, wantDef) {
		t.Fatalf("default argv\n got %v\nwant %v", def, wantDef)
	}
	// A path with a space stays a SINGLE argument (no splitting), so no shell is needed.
	sp := setfaclArgv("dev", aclEntry{path: "/mnt/my keys/dev", perms: "r-x"})
	if len(sp) != 4 || sp[3] != "/mnt/my keys/dev" {
		t.Fatalf("a spaced path must remain one argument; got %v", sp)
	}
}

// TestParseGetfacl checks the parser reads named-user access AND default entries, skips
// the owner-user entry (empty name), tolerates an "#effective" suffix, and ignores
// comment lines (including non-ASCII) and unrelated entries. An unknown user yields no
// entries (so verification fails loud rather than assuming a grant).
func TestParseGetfacl(t *testing.T) {
	out := "# file: dev\n" +
		"# a UTF-8 comment: caf\u00e9 na\u00efve\n" + // non-ASCII bytes must not break parsing
		"user::rw-\n" +
		"user:dev:rwx\t\t#effective:r-x\n" +
		"group::---\n" +
		"mask::r-x\n" +
		"other::---\n" +
		"default:user::rwx\n" +
		"default:user:dev:r--\n" +
		"garbage line that is not an entry\n" +
		"default:group::---\n"

	got := parseGetfacl([]byte(out), "dev")
	want := []parsedACL{{def: false, perms: "rwx"}, {def: true, perms: "r--"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseGetfacl\n got %+v\nwant %+v", got, want)
	}

	// An unknown user resolves to nothing at all.
	if entries := parseGetfacl([]byte(out), "mallory"); len(entries) != 0 {
		t.Fatalf("unknown user should yield no entries; got %+v", entries)
	}
}

// TestPermsIncludeAndSatisfied checks the permission-bit predicate and the verification
// predicate that maps parsed entries back to an intended entry.
func TestPermsIncludeAndSatisfied(t *testing.T) {
	if !permsInclude("r-x", "r--") {
		t.Fatal("r-x should include r--")
	}
	if permsInclude("--x", "r--") {
		t.Fatal("--x must NOT include r-- (r is missing)")
	}
	if permsInclude("rw", "r--") {
		t.Fatal("a too-short perms string must not satisfy")
	}

	parsed := []parsedACL{{def: false, perms: "r-x"}, {def: true, perms: "r--"}}
	if !aclSatisfied(parsed, aclEntry{def: false, perms: "r--"}) {
		t.Fatal("access r-- should be satisfied by r-x")
	}
	if !aclSatisfied(parsed, aclEntry{def: true, perms: "r--"}) {
		t.Fatal("default r-- should be satisfied")
	}
	// A default grant does not satisfy an ACCESS requirement of the same bits.
	if aclSatisfied([]parsedACL{{def: true, perms: "r--"}}, aclEntry{def: false, perms: "r--"}) {
		t.Fatal("a default entry must not satisfy an access requirement")
	}
	// No matching entry -> not satisfied (fail loud).
	if aclSatisfied(nil, aclEntry{def: false, perms: "r--"}) {
		t.Fatal("no entries must not satisfy any requirement")
	}
}

// TestAclRemediation checks the printed sudo commands single-quote the path and carry
// the "-d" flag for a default entry, so an operator can copy them verbatim.
func TestAclRemediation(t *testing.T) {
	entries := keystoreACLEntries("/srv/sopshq-keys", "/srv/sopshq-keys/dev", "/srv/sopshq-keys/dev/keys.txt")
	cmds := aclRemediation("dev", entries)
	if len(cmds) != len(entries) {
		t.Fatalf("expected one command per entry; got %d", len(cmds))
	}
	if !strings.HasPrefix(cmds[0], "sudo setfacl -m u:dev:--x '/srv/sopshq-keys'") {
		t.Fatalf("root traverse command wrong: %q", cmds[0])
	}
	if !strings.HasPrefix(cmds[3], "sudo setfacl -d -m u:dev:r-- '/srv/sopshq-keys/dev'") {
		t.Fatalf("default command wrong: %q", cmds[3])
	}
}

// TestSharedRootSudo checks the one-time root-provisioning commands.
func TestSharedRootSudo(t *testing.T) {
	cmds := sharedRootSudo("/srv/sopshq-keys", "sopshq")
	want := []string{
		"sudo mkdir -p '/srv/sopshq-keys'",
		"sudo chown sopshq '/srv/sopshq-keys'",
		"sudo chmod 0711 '/srv/sopshq-keys'",
	}
	if !reflect.DeepEqual(cmds, want) {
		t.Fatalf("sharedRootSudo\n got %v\nwant %v", cmds, want)
	}
}
