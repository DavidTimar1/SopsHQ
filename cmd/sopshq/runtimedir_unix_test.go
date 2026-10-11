//go:build unix

package main

import "testing"

// TestDefaultRuntimeDir covers the Unix runtime-directory resolution: the
// systemd-provided RUNTIME_DIRECTORY (first of a colon-separated list) wins, else the
// /run/sopshq default.
func TestDefaultRuntimeDir(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		t.Setenv("RUNTIME_DIRECTORY", "")
		if got := defaultRuntimeDir(); got != "/run/sopshq" {
			t.Fatalf("defaultRuntimeDir = %q, want /run/sopshq", got)
		}
	})
	t.Run("systemd single", func(t *testing.T) {
		t.Setenv("RUNTIME_DIRECTORY", "/run/sopshq")
		if got := defaultRuntimeDir(); got != "/run/sopshq" {
			t.Fatalf("defaultRuntimeDir = %q", got)
		}
	})
	t.Run("systemd colon list takes first", func(t *testing.T) {
		t.Setenv("RUNTIME_DIRECTORY", "/run/sopshq:/run/other")
		if got := defaultRuntimeDir(); got != "/run/sopshq" {
			t.Fatalf("defaultRuntimeDir = %q, want the first path", got)
		}
	})
}
