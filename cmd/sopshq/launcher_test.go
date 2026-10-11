package main

import (
	"strings"
	"testing"
)

// TestBuildLauncherScriptContent checks the Startup-folder script polls forever for
// the config file (no timeout branch that gives up), then launches "serve -config" on
// the given binary and config path, and pauses afterward so an error stays readable
// instead of the window vanishing. This is pure string content, so it is tested on any
// OS regardless of which platform actually writes the file.
func TestBuildLauncherScriptContent(t *testing.T) {
	const bin = `C:\SopsHQ\sopshq.exe`
	const cfg = `C:\SopsHQ\config.jsonc`
	got := buildLauncherScript(bin, cfg)

	mustContain := []string{bin, cfg, ":wait", "goto wait", "serve -config", "pause", "timeout /t"}
	for _, want := range mustContain {
		if !strings.Contains(got, want) {
			t.Fatalf("launcher script missing %q; got:\n%s", want, got)
		}
	}
}
