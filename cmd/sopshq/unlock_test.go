package main

import (
	"strings"
	"testing"
)

// TestCmdUnlockNotRunning verifies `sopshq unlock` fails with a clear "not running"
// message (and never prompts for the key) when there is no unlock socket. The
// -runtime-dir points at an empty temp dir so no socket exists.
func TestCmdUnlockNotRunning(t *testing.T) {
	dir := t.TempDir()
	err := cmdUnlock([]string{"-runtime-dir", dir})
	if err == nil {
		t.Fatal("expected an error when the socket is absent")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "not running") || !strings.Contains(msg, "unlock socket") {
		t.Fatalf("error %q does not read as a clear not-running message", err.Error())
	}
	if !strings.Contains(msg, "systemctl start sopshq") {
		t.Fatalf("error %q should tell the operator how to start SopsHQ", err.Error())
	}
}

// TestCmdStatusNotRunning verifies `sopshq status` treats an absent socket as "not
// running" and returns nil (a valid answer, not a failure).
func TestCmdStatusNotRunning(t *testing.T) {
	dir := t.TempDir()
	if err := cmdStatus([]string{"-runtime-dir", dir}); err != nil {
		t.Fatalf("cmdStatus(not running) = %v, want nil", err)
	}
}

// TestUnlockPathMismatch covers the stale-process guard: a matching data path (including
// differently-spelled but equivalent paths) proceeds, a genuinely different one refuses,
// and an empty running/expected value skips the check.
func TestUnlockPathMismatch(t *testing.T) {
	if err := unlockPathMismatch("/srv/sopshq", "/srv/sopshq"); err != nil {
		t.Fatalf("identical paths should proceed, got %v", err)
	}
	if err := unlockPathMismatch("/srv/sopshq/", "/srv/sopshq"); err != nil {
		t.Fatalf("equivalent paths should proceed, got %v", err)
	}
	if err := unlockPathMismatch("", "/srv/sopshq"); err != nil {
		t.Fatalf("empty running value should skip the guard, got %v", err)
	}
	if err := unlockPathMismatch("/srv/sopshq", ""); err != nil {
		t.Fatalf("empty expected value should skip the guard, got %v", err)
	}
	err := unlockPathMismatch("/srv/secrets", "/srv/sopshq")
	if err == nil {
		t.Fatal("mismatched paths should refuse")
	}
	msg := err.Error()
	if !strings.Contains(msg, "/srv/secrets") || !strings.Contains(msg, "/srv/sopshq") {
		t.Fatalf("refusal %q should name both the running and expected data paths", msg)
	}
	if !strings.Contains(strings.ToLower(msg), "stale") {
		t.Fatalf("refusal %q should call the running process stale", msg)
	}
}
