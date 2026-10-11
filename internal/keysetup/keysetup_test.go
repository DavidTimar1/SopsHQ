package keysetup

import (
	"path/filepath"
	"strings"
	"testing"
)

// sampleGetent is representative `getent passwd` output. It is fed to the parser
// directly - the tests NEVER call getent or touch the real account database.
const sampleGetent = "root:x:0:0:root:/root:/bin/bash\n" +
	"alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash\n" +
	"mailsvc:x:997:997:Mailsvc Mail Server:/nonexistent:/usr/sbin/nologin\n"

func TestParsePasswdHome(t *testing.T) {
	cases := []struct {
		name     string
		user     string
		wantHome string
		wantOK   bool
	}{
		{"human account", "alice", "/home/alice", true},
		{"service account with /nonexistent home", "mailsvc", "/nonexistent", true},
		{"root", "root", "/root", true},
		{"missing account", "ghost", "", false},
	}
	for _, c := range cases {
		home, ok := ParsePasswdHome(sampleGetent, c.user)
		if ok != c.wantOK || home != c.wantHome {
			t.Errorf("%s: ParsePasswdHome = (%q, %v), want (%q, %v)", c.name, home, ok, c.wantHome, c.wantOK)
		}
	}
}

func TestParsePasswdHomeMalformed(t *testing.T) {
	// Too few fields, blank lines, and CRLF must not panic or false-match.
	in := "\r\nbad:line\r\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\r\n"
	home, ok := ParsePasswdHome(in, "alice")
	if !ok || home != "/home/alice" {
		t.Fatalf("ParsePasswdHome = (%q, %v), want (/home/alice, true)", home, ok)
	}
	if _, ok := ParsePasswdHome(in, "bad"); ok {
		t.Fatal("a malformed line must not match")
	}
}

func TestExpandHome(t *testing.T) {
	cases := []struct {
		path, home, want string
	}{
		{"~/.config/sops/age", "/home/alice", filepath.Join("/home/alice", ".config", "sops", "age")},
		{"~", "/home/alice", "/home/alice"},
		{"/etc/svc/keys", "/home/alice", "/etc/svc/keys"}, // absolute is left alone
		{"~/.config/sops/age", "", "~/.config/sops/age"},  // no home: unresolved
	}
	for _, c := range cases {
		if got := ExpandHome(c.path, c.home); got != c.want {
			t.Errorf("ExpandHome(%q, %q) = %q, want %q", c.path, c.home, got, c.want)
		}
	}
}

func TestValidUsername(t *testing.T) {
	ok := []string{"alice", "mailsvc", "_svc", "svc-1", "app.user", "WIN-PC$", "a"}
	bad := []string{
		"", "svc$(reboot)", "a;b", "-x", "a b", "a|b", "a&b", "a`b`", "a>b", "a<b",
		"a'b", "a\"b", "a\\b", "a\nb", "a$b", "svc$x", "a(b)", strings.Repeat("a", 33),
	}
	for _, u := range ok {
		if !ValidUsername(u) {
			t.Errorf("ValidUsername(%q) = false, want true", u)
		}
	}
	for _, u := range bad {
		if ValidUsername(u) {
			t.Errorf("ValidUsername(%q) = true, want false", u)
		}
	}
}

func TestValidKeystorePath(t *testing.T) {
	ok := []string{"", "/etc/svc/keys", "~/.config/sops/age", `Z:\keys\sops`, "/srv/secure keys", "/a-b_c.d", `Z:\alice\personal\keys\alice\sops`}
	bad := []string{
		"/mnt/x; rm -rf /", "/a$(reboot)", "/a`b`", "/a|b", "/a&b", "/a>b", "/a<b",
		"/a'b", "/a\"b", "-rf", "-x/keys", "/a\nb", "/a\x00b", "/a*b", "/a?b",
		`C:\k%USERPROFILE%\x`, `C:\k^x`, // reach cmd.exe (mklink): %VAR% expansion, ^ escape
	}
	for _, p := range ok {
		if !ValidKeystorePath(p) {
			t.Errorf("ValidKeystorePath(%q) = false, want true", p)
		}
	}
	for _, p := range bad {
		if ValidKeystorePath(p) {
			t.Errorf("ValidKeystorePath(%q) = true, want false", p)
		}
	}
}

func TestSymlinkDecision(t *testing.T) {
	create, cmd := SymlinkDecision("/srv/sopshq-keys/keys.txt", "/home/alice/.config/sops/age/keys.txt", true)
	if !create || cmd != "" {
		t.Errorf("writable -> (%v, %q), want (true, \"\")", create, cmd)
	}
	create, cmd = SymlinkDecision("/srv/sopshq-keys/keys.txt", "/home/svc/.config/sops/age/keys.txt", false)
	want := "sudo ln -s '/srv/sopshq-keys/keys.txt' '/home/svc/.config/sops/age/keys.txt'"
	if create || cmd != want {
		t.Errorf("not writable -> (%v, %q), want (false, %q)", create, cmd, want)
	}
}

// TestCommandsQuoting proves the builders single-quote interpolated values so that a
// value which somehow reached them (defense-in-depth; the boundary already rejects
// these) cannot break out into a live command. Single quotes are escaped the POSIX
// way (close the quote, add an escaped quote, reopen).
func TestCommandsQuoting(t *testing.T) {
	missing := Account{Username: "svc'x", Supported: true}
	in := Input{Username: "svc'x", KeyBase: "/etc/svc x/keys", Account: missing, KeyBaseWritable: false}
	got := in.Commands()
	want := []string{
		`sudo useradd -m -d '/home/svc'\''x' 'svc'\''x'`,
		`sudo mkdir -p '/etc/svc x/keys' && sudo chown 'svc'\''x':'svc'\''x' '/etc/svc x/keys' && sudo chmod 700 '/etc/svc x/keys'`,
	}
	if !equal(got, want) {
		t.Errorf("quoting:\n got  %#v\n want %#v", got, want)
	}
}

func TestCommands(t *testing.T) {
	exists := Account{Username: "alice", Supported: true, Exists: true, Home: "/home/alice", HasHome: true}
	homeless := Account{Username: "mailsvc", Supported: true, Exists: true, Home: "/nonexistent"}
	missing := Account{Username: "newsvc", Supported: true}
	winlike := Account{Username: "alice", Supported: false}

	cases := []struct {
		name string
		in   Input
		want []string
	}{
		{
			name: "own account, own keystore: nothing to run",
			in:   Input{Username: "alice", KeyBase: "/home/alice/.config/sops/age", Account: exists, KeyBaseWritable: true},
			want: nil,
		},
		{
			name: "existing account, another account's keystore: make+own it",
			in:   Input{Username: "alice", KeyBase: "/etc/alice/keys", Account: exists, KeyBaseWritable: false},
			want: []string{"sudo mkdir -p '/etc/alice/keys' && sudo chown 'alice':'alice' '/etc/alice/keys' && sudo chmod 700 '/etc/alice/keys'"},
		},
		{
			name: "homeless service account: explicit account-owned keystore",
			in:   Input{Username: "mailsvc", KeyBase: "/etc/mailsvc/keys", Account: homeless, KeyBaseWritable: false},
			want: []string{"sudo mkdir -p '/etc/mailsvc/keys' && sudo chown 'mailsvc':'mailsvc' '/etc/mailsvc/keys' && sudo chmod 700 '/etc/mailsvc/keys'"},
		},
		{
			name: "account does not exist: create it with a home, then make its keystore",
			in:   Input{Username: "newsvc", KeyBase: "/etc/newsvc/keys", Account: missing, KeyBaseWritable: false},
			want: []string{
				"sudo useradd -m -d '/home/newsvc' 'newsvc'",
				"sudo mkdir -p '/etc/newsvc/keys' && sudo chown 'newsvc':'newsvc' '/etc/newsvc/keys' && sudo chmod 700 '/etc/newsvc/keys'",
			},
		},
		{
			name: "unsupported platform: no commands",
			in:   Input{Username: "alice", KeyBase: "C:/keys", Account: winlike, KeyBaseWritable: true},
			want: nil,
		},
		{
			name: "no keystore chosen: no commands",
			in:   Input{Username: "mailsvc", KeyBase: "", Account: homeless, KeyBaseWritable: false},
			want: nil,
		},
	}
	for _, c := range cases {
		got := c.in.Commands()
		if !equal(got, c.want) {
			t.Errorf("%s:\n got  %#v\n want %#v", c.name, got, c.want)
		}
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
