package main

import (
	"runtime"
	"strings"
	"testing"
)

// TestNormalizeFlagArgs covers the case-folding rules: the flag-name portion
// (up to `=`, or the whole token) is lowercased, the value after `=` keeps its case,
// a token after a bare `--` terminator is untouched, and an already-lowercase flag is
// a no-op.
func TestNormalizeFlagArgs(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"single dash upper", []string{"-DIR", "C:\\SopsHQ"}, []string{"-dir", "C:\\SopsHQ"}},
		{"single dash mixed case", []string{"-Dir", "C:\\SopsHQ"}, []string{"-dir", "C:\\SopsHQ"}},
		{"double dash upper with hyphen", []string{"--DRY-RUN"}, []string{"--dry-run"}},
		{"equals form preserves value case", []string{"-Name=FooBar"}, []string{"-name=FooBar"}},
		{"already lowercase is a no-op", []string{"-dir", "-config=x"}, []string{"-dir", "-config=x"}},
		{"terminator stops transform", []string{"-DIR", "x", "--", "-STILL-UPPER"}, []string{"-dir", "x", "--", "-STILL-UPPER"}},
		{"bare dash is not a flag", []string{"-"}, []string{"-"}},
		{"non-flag tokens untouched", []string{"serve", "-Config", "path/To/File"}, []string{"serve", "-config", "path/To/File"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeFlagArgs(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("normalizeFlagArgs(%q) = %q; want %q", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("normalizeFlagArgs(%q)[%d] = %q; want %q", tt.in, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestStripTrailingQuoteValue covers the GOOS-independent stripping core: a value
// ending in exactly one literal `"` loses it; any other value (including empty) is
// untouched.
func TestStripTrailingQuoteValue(t *testing.T) {
	tests := []struct {
		name         string
		in           string
		wantCleaned  string
		wantStripped bool
	}{
		{"trailing quote stripped", `C:\SopsHQ\"`, `C:\SopsHQ\`, true},
		{"normal value untouched", `C:\SopsHQ`, `C:\SopsHQ`, false},
		{"empty value untouched", "", "", false},
		{"quote in the middle untouched", `C:\"Sop"shq`, `C:\"Sop"shq`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleaned, stripped := stripTrailingQuoteValue(tt.in)
			if cleaned != tt.wantCleaned || stripped != tt.wantStripped {
				t.Fatalf("stripTrailingQuoteValue(%q) = %q,%v; want %q,%v", tt.in, cleaned, stripped, tt.wantCleaned, tt.wantStripped)
			}
		})
	}
}

// TestStripTrailingQuoteGOOSGate confirms stripTrailingQuote only strips on Windows:
// on this platform it must behave exactly like stripTrailingQuoteValue; on any other
// platform it must never modify the value, even when the value ends in a quote.
func TestStripTrailingQuoteGOOSGate(t *testing.T) {
	const withQuote = `C:\SopsHQ\"`
	cleaned, stripped := stripTrailingQuote("dir", withQuote)
	if runtime.GOOS == "windows" {
		if !stripped || cleaned != `C:\SopsHQ\` {
			t.Fatalf("stripTrailingQuote on windows = %q,%v; want %q,true", cleaned, stripped, `C:\SopsHQ\`)
		}
	} else {
		if stripped || cleaned != withQuote {
			t.Fatalf("stripTrailingQuote on %s = %q,%v; want %q,false (non-Windows must never strip)", runtime.GOOS, cleaned, stripped, withQuote)
		}
	}
}

// TestApplyTrailingQuoteFixNotesOnStrip is a light integration check: on Windows a
// trailing-quote value is rewritten in place; on any other platform the value passes
// through untouched. It does not assert on the printed stderr note (that would need
// capturing os.Stderr); the note text itself is reviewed by inspection.
func TestApplyTrailingQuoteFixNotesOnStrip(t *testing.T) {
	val := `C:\SopsHQ\"`
	applyTrailingQuoteFix("dir", &val)
	if runtime.GOOS == "windows" {
		if val != `C:\SopsHQ\` {
			t.Fatalf("applyTrailingQuoteFix on windows left %q; want %q", val, `C:\SopsHQ\`)
		}
	} else if val != `C:\SopsHQ\"` {
		t.Fatalf("applyTrailingQuoteFix on %s modified the value to %q; want it untouched", runtime.GOOS, val)
	}
}

// subcommandFlagNames lists every flag name each subcommand's flag.FlagSet defines,
// exactly as declared in main.go/unlock.go/setup.go/lifecycle.go. This is the source
// of truth TestNoFlagNameCollisions checks against: if a future flag addition would
// collide with an existing one once both are lowercased, this test fails loudly
// instead of normalizeFlagArgs silently letting one flag shadow another.
var subcommandFlagNames = map[string][]string{
	"init":             {"dir", "config", "name", "set-default", "keys"},
	"export":           {"config", "out"},
	"restore":          {"in", "dir"},
	"reset-2fa":        {"config", "user"},
	"reset-admin":      {"config", "user"},
	"serve":            {"config"},
	"unlock":           {"runtime-dir", "config"},
	"status":           {"runtime-dir"},
	"setup":            {"prefix", "data", "keybase", "user", "force-home", "yes", "unattended", "dry-run"},
	"start":            {"config"},
	"stop":             {"config"},
	"install-launcher": {"config"},
}

// TestNoFlagNameCollisions verifies that, within every subcommand's flag set, no two
// distinct flag names collide once normalizeFlagArgs lowercases them. Case-insensitive
// flag matching would otherwise let two differently-cased flags silently shadow one
// another; this fails loudly (a test failure) rather than picking one at random.
func TestNoFlagNameCollisions(t *testing.T) {
	for sub, names := range subcommandFlagNames {
		t.Run(sub, func(t *testing.T) {
			seen := make(map[string]string, len(names))
			for _, n := range names {
				lower := strings.ToLower(n)
				if orig, ok := seen[lower]; ok && orig != n {
					t.Fatalf("subcommand %q: flags %q and %q collide once lowercased to %q", sub, orig, n, lower)
				}
				seen[lower] = n
			}
		})
	}
}
