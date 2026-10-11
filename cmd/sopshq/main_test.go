package main

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestPointerDecision covers the guard that stops `sopshq init` from silently
// hijacking the machine-wide default-install location pointer.
func TestPointerDecision(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()

	tests := []struct {
		name            string
		existing        string
		existingOK      bool
		newDir          string
		setDefault      bool
		wantWrite       bool
		wantMsgContains string // lowercased substring; "" means the message must be empty
	}{
		{"no pointer yet -> set it", "", false, a, false, true, "default install"},
		{"same dir -> no-op", a, true, a, false, false, ""},
		{"different dir, no flag -> keep existing", a, true, b, false, false, "still"},
		{"different dir, -set-default -> repoint", a, true, b, true, true, "changed"},
		{"same dir even with -set-default -> still no-op", a, true, a, true, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			write, msg := pointerDecision(tt.existing, tt.existingOK, tt.newDir, tt.setDefault)
			if write != tt.wantWrite {
				t.Fatalf("write = %v, want %v", write, tt.wantWrite)
			}
			if tt.wantMsgContains == "" {
				if msg != "" {
					t.Fatalf("message = %q, want empty", msg)
				}
				return
			}
			if !strings.Contains(strings.ToLower(msg), tt.wantMsgContains) {
				t.Fatalf("message = %q, want it to contain %q", msg, tt.wantMsgContains)
			}
		})
	}
}

// TestResolveConfigPath covers the bare-run config discovery precedence: explicit
// -config wins over everything; the machine pointer wins over the per-user pointer;
// the per-user pointer wins over the default dir; and with no pointer at all the
// default-dir config is the (not-located) fallback.
func TestResolveConfigPath(t *testing.T) {
	const (
		explicit = "/explicit/config.jsonc"
		machine  = "/machine/base"
		user     = "/user/base"
		def      = "/default/dir"
	)
	tests := []struct {
		name        string
		explicit    string
		machineBase string
		userBase    string
		wantPath    string
		wantLocated bool
	}{
		{"explicit wins over all", explicit, machine, user, explicit, true},
		{"machine wins over user and default", "", machine, user, filepath.Join(machine, "config.jsonc"), true},
		{"user wins over default", "", "", user, filepath.Join(user, "config.jsonc"), true},
		{"nothing -> default, not located", "", "", "", filepath.Join(def, "config.jsonc"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, located := resolveConfigPath(tt.explicit, tt.machineBase, tt.userBase, def)
			if path != tt.wantPath || located != tt.wantLocated {
				t.Fatalf("resolveConfigPath(%q,%q,%q) = %q,%v; want %q,%v",
					tt.explicit, tt.machineBase, tt.userBase, path, located, tt.wantPath, tt.wantLocated)
			}
		})
	}
}

// TestShouldPauseBeforeExit covers the single call site that decides whether main()
// pauses for a keypress before the process exits. Because main() consults this pure
// function exactly once per run, a bare Windows run fires the pause exactly once (never
// twice, regardless of whether run() errored) and every other combination (a subcommand
// given, or any non-Windows GOOS) never fires it at all.
func TestShouldPauseBeforeExit(t *testing.T) {
	tests := []struct {
		name string
		argc int
		goos string
		want bool
	}{
		{"bare run on windows -> pause", 0, "windows", true},
		{"bare run on linux -> no pause", 0, "linux", false},
		{"bare run on darwin -> no pause", 0, "darwin", false},
		{"subcommand given on windows -> no pause", 1, "windows", false},
		{"subcommand given on linux -> no pause", 1, "linux", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldPauseBeforeExit(tt.argc, tt.goos); got != tt.want {
				t.Fatalf("shouldPauseBeforeExit(%d, %q) = %v, want %v", tt.argc, tt.goos, got, tt.want)
			}
		})
	}
}

func TestSamePath(t *testing.T) {
	d := t.TempDir()
	if !samePath(d, d) {
		t.Fatalf("samePath(%q, %q) = false, want true", d, d)
	}
	if samePath(d, t.TempDir()) {
		t.Fatalf("samePath of two distinct temp dirs = true, want false")
	}
	if runtime.GOOS == "windows" && !samePath(d, strings.ToUpper(d)) {
		t.Fatalf("samePath should be case-insensitive on Windows")
	}
}

func TestPathWithin(t *testing.T) {
	base := t.TempDir()
	tests := []struct {
		name   string
		child  string
		parent string
		want   bool
	}{
		{"same dir", base, base, true},
		{"direct child", filepath.Join(base, "sub"), base, true},
		{"deep child", filepath.Join(base, "a", "b", "c"), base, true},
		{"parent is not within child", base, filepath.Join(base, "sub"), false},
		{"sibling escapes", filepath.Join(base, "..", "other"), base, false},
		{"unrelated dir", t.TempDir(), base, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pathWithin(tt.child, tt.parent); got != tt.want {
				t.Fatalf("pathWithin(%q, %q) = %v, want %v", tt.child, tt.parent, got, tt.want)
			}
		})
	}
}

// TestPointerInsideBase verifies init's skip guard: when the user config dir resolves
// inside the data base (a homeless service account whose HOME is the data base), the
// per-user pointer would land on the data volume itself and is skipped; when the config
// dir is elsewhere, the pointer is written normally.
func TestPointerInsideBase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.UserConfigDir uses %AppData% on Windows, not XDG_CONFIG_HOME")
	}
	base := t.TempDir()

	// HOME/XDG_CONFIG_HOME inside the data base -> pointer lands under it -> skip.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, ".config"))
	if !pointerInsideBase(base) {
		t.Fatalf("pointerInsideBase = false when config dir is inside the data base, want true")
	}

	// Config dir on a separate path -> pointer is reachable -> write it.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if pointerInsideBase(base) {
		t.Fatalf("pointerInsideBase = true when config dir is outside the data base, want false")
	}
}
