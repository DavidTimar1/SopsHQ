package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParsePID covers the pid-file content parser: only a positive integer (ignoring
// surrounding whitespace) is a valid pid; everything else reads as "no pid".
func TestParsePID(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantPID int
		wantOK  bool
	}{
		{"plain", "123", 123, true},
		{"trailing newline", "42\n", 42, true},
		{"surrounding whitespace", "  7\t\n", 7, true},
		{"empty", "", 0, false},
		{"whitespace only", "  \n", 0, false},
		{"non-numeric", "abc", 0, false},
		{"zero", "0", 0, false},
		{"negative", "-5", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pid, ok := parsePID(tt.in)
			if pid != tt.wantPID || ok != tt.wantOK {
				t.Fatalf("parsePID(%q) = %d,%v; want %d,%v", tt.in, pid, ok, tt.wantPID, tt.wantOK)
			}
		})
	}
}

// TestPIDFileWriteRead confirms a written pid round-trips and, with a live process,
// pidFileRunning reports it as running.
func TestPIDFileWriteRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), pidFileName)
	if err := writePIDFile(path, 4321); err != nil {
		t.Fatalf("writePIDFile: %v", err)
	}
	alive := func(int) bool { return true }
	pid, running := pidFileRunning(path, alive)
	if pid != 4321 || !running {
		t.Fatalf("pidFileRunning(live) = %d,%v; want 4321,true", pid, running)
	}
}

// TestPIDFileStale confirms that a pid file naming a dead process is reported as
// not-running (stale), so the caller can safely overwrite/clear it.
func TestPIDFileStale(t *testing.T) {
	path := filepath.Join(t.TempDir(), pidFileName)
	if err := writePIDFile(path, 9999); err != nil {
		t.Fatalf("writePIDFile: %v", err)
	}
	dead := func(int) bool { return false }
	pid, running := pidFileRunning(path, dead)
	if pid != 9999 || running {
		t.Fatalf("pidFileRunning(dead) = %d,%v; want 9999,false", pid, running)
	}
}

// TestPIDFileMissing confirms an absent pid file reads as pid 0 / not running (nothing
// to stop), never an error.
func TestPIDFileMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), pidFileName) // never written
	pid, running := pidFileRunning(path, func(int) bool { return true })
	if pid != 0 || running {
		t.Fatalf("pidFileRunning(missing) = %d,%v; want 0,false", pid, running)
	}
}

// TestPIDFileCorrupt confirms an empty or garbage pid file reads as pid 0 / not
// running, so a corrupt file is treated like an absent one.
func TestPIDFileCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), pidFileName)
	if err := os.WriteFile(path, []byte("not-a-pid\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	pid, running := pidFileRunning(path, func(int) bool { return true })
	if pid != 0 || running {
		t.Fatalf("pidFileRunning(corrupt) = %d,%v; want 0,false", pid, running)
	}
}
