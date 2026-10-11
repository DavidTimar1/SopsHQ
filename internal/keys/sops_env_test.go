package keys

import (
	"strings"
	"testing"
)

// TestSopsChildEnvScrubsDiscoveryVars proves the child environment sops runs with
// contains ONLY the SOPS_AGE_KEY SopsHQ passes: every ambient age-identity-discovery
// variable (a key file path, an SSH identity, etc.) is removed so sops cannot pick
// up an unintended identity from the operator's shell or a parallel test.
//
// t.Setenv forbids t.Parallel, which is correct here: this test mutates process
// environment variables that other tests must not observe concurrently.
func TestSopsChildEnvScrubsDiscoveryVars(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY_FILE", "/some/ambient/path")
	t.Setenv("SOPS_AGE_SSH_PRIVATE_KEY_FILE", "/some/ambient/id_ed25519")

	const want = "AGE-SECRET-KEY-1PASSEDVALUE"
	env := sopsChildEnv(want)

	var sopsAgeKeyCount int
	var sawPath bool
	for _, kv := range env {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		switch name {
		case "SOPS_AGE_KEY":
			sopsAgeKeyCount++
			if got := strings.TrimPrefix(kv, "SOPS_AGE_KEY="); got != want {
				t.Fatalf("SOPS_AGE_KEY value = %q, want %q", got, want)
			}
		case "SOPS_AGE_KEY_FILE",
			"SOPS_AGE_KEY_CMD",
			"SOPS_AGE_SSH_PRIVATE_KEY_FILE",
			"SOPS_AGE_SSH_PRIVATE_KEY_CMD":
			t.Fatalf("discovery var leaked into child env: %q", kv)
		case "PATH":
			sawPath = true
		}
	}

	if sopsAgeKeyCount != 1 {
		t.Fatalf("SOPS_AGE_KEY entries = %d, want exactly 1", sopsAgeKeyCount)
	}
	if !sawPath {
		t.Fatal("PATH was dropped from child env; only discovery vars should be removed")
	}
}
