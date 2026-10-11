package main

import "testing"

// TestParseRegQueryPath covers extracting the user PATH value and registry type
// from `reg query` output: values with spaces and %-expandables survive intact,
// and output with no Path value reports ok=false.
func TestParseRegQueryPath(t *testing.T) {
	out := "\r\nHKEY_CURRENT_USER\\Environment\r\n    Path    REG_EXPAND_SZ    C:\\Program Files\\Go\\bin;%USERPROFILE%\\bin\r\n\r\n"
	val, typ, ok := parseRegQueryPath(out)
	if !ok {
		t.Fatalf("ok = false, want true")
	}
	if typ != "REG_EXPAND_SZ" {
		t.Fatalf("regType = %q, want REG_EXPAND_SZ", typ)
	}
	if val != `C:\Program Files\Go\bin;%USERPROFILE%\bin` {
		t.Fatalf("value = %q", val)
	}

	if _, _, ok := parseRegQueryPath("ERROR: The system was unable to find the specified registry key or value.\r\n"); ok {
		t.Fatalf("ok = true for output with no Path value, want false")
	}
}

// TestMergeUserPath covers the append/dedup rules: an absent dir is appended with
// one separator, a present dir (any case, with or without a trailing backslash)
// leaves the value untouched, and an empty current value becomes just dir.
func TestMergeUserPath(t *testing.T) {
	tests := []struct {
		name        string
		cur, dir    string
		want        string
		wantChanged bool
	}{
		{"append", `C:\Go\bin`, `C:\ProgramData\sopshq`, `C:\Go\bin;C:\ProgramData\sopshq`, true},
		{"already present", `C:\Go\bin;C:\ProgramData\sopshq`, `C:\ProgramData\sopshq`, `C:\Go\bin;C:\ProgramData\sopshq`, false},
		{"present, different case + trailing slash", `c:\programdata\SOPSHQ\`, `C:\ProgramData\sopshq`, `c:\programdata\SOPSHQ\`, false},
		{"empty current", "", `C:\ProgramData\sopshq`, `C:\ProgramData\sopshq`, true},
		{"trailing separator on current", `C:\Go\bin;`, `C:\ProgramData\sopshq`, `C:\Go\bin;C:\ProgramData\sopshq`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := mergeUserPath(tt.cur, tt.dir)
			if got != tt.want || changed != tt.wantChanged {
				t.Fatalf("mergeUserPath(%q, %q) = (%q, %v), want (%q, %v)", tt.cur, tt.dir, got, changed, tt.want, tt.wantChanged)
			}
		})
	}
}
