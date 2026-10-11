package main

import (
	"strings"
	"testing"
)

// TestInstanceLockDecision covers the pure single-instance refusal wording: acquiring
// the lock proceeds; a held lock refuses, naming the holder pid when known.
func TestInstanceLockDecision(t *testing.T) {
	const dataDir = "/srv/sopshq/data"
	if err := instanceLockDecision(true, 0, dataDir); err != nil {
		t.Fatalf("acquired lock should proceed, got %v", err)
	}
	err := instanceLockDecision(false, 1234, dataDir)
	if err == nil {
		t.Fatal("held lock should refuse")
	}
	msg := err.Error()
	if !strings.Contains(msg, dataDir) || !strings.Contains(msg, "1234") {
		t.Fatalf("refusal %q should name the data dir and holder pid", msg)
	}
	err = instanceLockDecision(false, 0, dataDir)
	if err == nil || !strings.Contains(err.Error(), dataDir) {
		t.Fatalf("held lock (unknown pid) should still refuse and name the data dir, got %v", err)
	}
}
