package permmap

import (
	"errors"
	"reflect"
	"runtime"
	"testing"
)

// entryFor parses a single getfacl block, assembles it with the given find type
// letter, and returns the resulting Entry. It fails the test if the block did
// not yield exactly one entry for path.
func entryFor(t *testing.T, block, path, ftype string) Entry {
	t.Helper()
	facl := parseGetfacl(block)
	got := assemble(map[string]string{path: ftype}, facl, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	if got[0].Path != path {
		t.Fatalf("expected path %q, got %q", path, got[0].Path)
	}
	return got[0]
}

func TestFlagRules(t *testing.T) {
	tests := []struct {
		name  string
		block string
		path  string
		ftype string

		wantWorldWritable bool
		wantHasACL        bool
		wantACLOverride   bool
		wantSuidSgid      bool
		wantDangerous     bool
	}{
		{
			name: "named user acl",
			block: "# file: /srv/proj\n" +
				"# owner: root\n" +
				"# group: root\n" +
				"user::rwx\n" +
				"user:alice:rwx\n" +
				"group::r-x\n" +
				"mask::rwx\n" +
				"other::r-x\n",
			path:            "/srv/proj",
			ftype:           "d",
			wantHasACL:      true,
			wantACLOverride: true,
			wantDangerous:   false,
		},
		{
			name: "world writable file",
			block: "# file: /srv/share/data.txt\n" +
				"# owner: root\n" +
				"# group: root\n" +
				"user::rw-\n" +
				"group::r--\n" +
				"other::rw-\n",
			path:              "/srv/share/data.txt",
			ftype:             "f",
			wantWorldWritable: true,
			wantDangerous:     true,
		},
		{
			name: "setuid file",
			block: "# file: /usr/bin/passwd\n" +
				"# owner: root\n" +
				"# group: root\n" +
				"# flags: s--\n" +
				"user::rwx\n" +
				"group::r-x\n" +
				"other::r-x\n",
			path:          "/usr/bin/passwd",
			ftype:         "f",
			wantSuidSgid:  true,
			wantDangerous: true,
		},
		{
			name: "world writable dir without sticky",
			block: "# file: /srv/pub\n" +
				"# owner: root\n" +
				"# group: root\n" +
				"user::rwx\n" +
				"group::rwx\n" +
				"other::rwx\n",
			path:              "/srv/pub",
			ftype:             "d",
			wantWorldWritable: true,
			wantDangerous:     true,
		},
		{
			name: "world writable dir with sticky is not dangerous",
			block: "# file: /tmp\n" +
				"# owner: root\n" +
				"# group: root\n" +
				"# flags: --t\n" +
				"user::rwx\n" +
				"group::rwx\n" +
				"other::rwx\n",
			path:              "/tmp",
			ftype:             "d",
			wantWorldWritable: true,
			wantDangerous:     false, // sticky bit exempts the /tmp pattern
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := entryFor(t, tc.block, tc.path, tc.ftype)
			if e.WorldWritable != tc.wantWorldWritable {
				t.Errorf("WorldWritable = %v, want %v", e.WorldWritable, tc.wantWorldWritable)
			}
			if e.HasACL != tc.wantHasACL {
				t.Errorf("HasACL = %v, want %v", e.HasACL, tc.wantHasACL)
			}
			if e.ACLOverride != tc.wantACLOverride {
				t.Errorf("ACLOverride = %v, want %v", e.ACLOverride, tc.wantACLOverride)
			}
			if e.SuidSgid != tc.wantSuidSgid {
				t.Errorf("SuidSgid = %v, want %v", e.SuidSgid, tc.wantSuidSgid)
			}
			if e.Dangerous != tc.wantDangerous {
				t.Errorf("Dangerous = %v, want %v", e.Dangerous, tc.wantDangerous)
			}
		})
	}
}

func TestNamedACLParsed(t *testing.T) {
	block := "# file: /srv/proj\n" +
		"# owner: root\n" +
		"# group: root\n" +
		"user::rwx\n" +
		"user:alice:rwx\n" +
		"group:devs:r-x\n" +
		"mask::rwx\n" +
		"other::r-x\n"
	e := entryFor(t, block, "/srv/proj", "d")
	want := []string{"u:alice:rwx", "g:devs:r-x"}
	if !reflect.DeepEqual(e.ACL, want) {
		t.Fatalf("ACL = %v, want %v", e.ACL, want)
	}
}

func TestDefaultACLParsed(t *testing.T) {
	block := "# file: /srv/team\n" +
		"# owner: root\n" +
		"# group: devs\n" +
		"# flags: -s-\n" +
		"user::rwx\n" +
		"group::rwx\n" +
		"group:devs:rwx\n" +
		"mask::rwx\n" +
		"other::r-x\n" +
		"default:user::rwx\n" +
		"default:user:alice:rwx\n" +
		"default:group::rwx\n" +
		"default:group:devs:rwx\n" +
		"default:mask::rwx\n" +
		"default:other::r-x\n"
	e := entryFor(t, block, "/srv/team", "d")

	wantDefault := []string{"u:alice:rwx", "g:devs:rwx"}
	if !reflect.DeepEqual(e.DefaultACL, wantDefault) {
		t.Fatalf("DefaultACL = %v, want %v", e.DefaultACL, wantDefault)
	}
	if !e.Setgid {
		t.Errorf("Setgid = false, want true (flags -s-)")
	}
	// The named group entry is a real ACL principal.
	if !e.HasACL {
		t.Errorf("HasACL = false, want true (group:devs present)")
	}
}

func TestOctalMode(t *testing.T) {
	tests := []struct {
		name                   string
		uperm, gperm, operm    int
		setuid, setgid, sticky bool
		wantStr                string
		wantNum                int
	}{
		{"setuid 4755", 7, 5, 5, true, false, false, "4755", 0o4755},
		{"plain 0644", 6, 4, 4, false, false, false, "0644", 0o0644},
		{"sticky 1777", 7, 7, 7, false, false, true, "1777", 0o1777},
		{"setgid 2770", 7, 7, 0, false, true, false, "2770", 0o2770},
		{"plain 0755", 7, 5, 5, false, false, false, "0755", 0o0755},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotStr, gotNum := octalMode(tc.uperm, tc.gperm, tc.operm, tc.setuid, tc.setgid, tc.sticky)
			if gotStr != tc.wantStr {
				t.Errorf("mode string = %q, want %q", gotStr, tc.wantStr)
			}
			if gotNum != tc.wantNum {
				t.Errorf("mode num = %d, want %d", gotNum, tc.wantNum)
			}
		})
	}
}

func TestPermToOctal(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"rwx", 7},
		{"r-x", 5},
		{"rw-", 6},
		{"r--", 4},
		{"---", 0},
		{"rws", 7}, // setuid glyph counts as execute
		{"r-S", 5}, // setuid without execute still sets the execute slot
		{"rwt", 7}, // sticky glyph counts as execute
	}
	for _, tc := range tests {
		if got := permToOctal(tc.in); got != tc.want {
			t.Errorf("permToOctal(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestModeReconstructionInEntry(t *testing.T) {
	block := "# file: /usr/bin/passwd\n" +
		"# owner: root\n" +
		"# group: root\n" +
		"# flags: s--\n" +
		"user::rwx\n" +
		"group::r-x\n" +
		"other::r-x\n"
	e := entryFor(t, block, "/usr/bin/passwd", "f")
	if e.Mode != "4755" {
		t.Errorf("Mode = %q, want %q", e.Mode, "4755")
	}
	if e.ModeNum != 0o4755 {
		t.Errorf("ModeNum = %d, want %d", e.ModeNum, 0o4755)
	}
}

func TestParseMultipleBlocks(t *testing.T) {
	text := "# file: /a\n" +
		"# owner: root\n" +
		"# group: root\n" +
		"user::rwx\n" +
		"group::r-x\n" +
		"other::r-x\n" +
		"\n" +
		"# file: /b\n" +
		"# owner: bob\n" +
		"# group: bob\n" +
		"user::rw-\n" +
		"group::r--\n" +
		"other::rw-\n"
	got := parseGetfacl(text)
	if len(got) != 2 {
		t.Fatalf("expected 2 blocks, got %d", len(got))
	}
	if got["/a"] == nil || got["/a"].Owner != "root" {
		t.Errorf("/a parsed wrong: %+v", got["/a"])
	}
	if got["/b"] == nil || got["/b"].Owner != "bob" || got["/b"].OPerm != 6 {
		t.Errorf("/b parsed wrong: %+v", got["/b"])
	}
}

func TestSymlinkOnlyInFind(t *testing.T) {
	// A symlink appears in find output but not in getfacl: assemble must still
	// produce an entry for it, carrying the type and empty ACL data.
	got := assemble(map[string]string{"/srv/link": "l"}, nil, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	if got[0].Type != "l" {
		t.Errorf("Type = %q, want %q", got[0].Type, "l")
	}
	if got[0].HasACL || got[0].Dangerous {
		t.Errorf("symlink-only entry should carry no flags: %+v", got[0])
	}
}

func TestCollectNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Collect runs a real scan on Linux")
	}
	if _, err := Collect("", []string{"."}); !errors.Is(err, ErrNotLinux) {
		t.Fatalf("Collect on %s: want ErrNotLinux, got %v", runtime.GOOS, err)
	}
}
