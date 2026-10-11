//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBinaryInPlace covers the pure decision that gates the install copy: the running
// binary already being the install target (same file -> skip the copy), versus a
// different or absent destination (-> copy). The privileged chown/chmod that follow a
// skip are not exercised here (they need root); this only tests the decision.
func TestBinaryInPlace(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "sopshq-src")
	dst := filepath.Join(dir, "sopshq-dst")
	if err := os.WriteFile(src, []byte("binary-a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("binary-b"), 0o755); err != nil {
		t.Fatal(err)
	}
	srcInfo, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	dstInfo, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}

	// Same file (source == destination): skip the copy.
	if !binaryInPlace(srcInfo, srcInfo) {
		t.Fatal("binaryInPlace(same file) = false, want true (should skip the copy)")
	}
	// A symlinked spelling of the same file still resolves to the same identity.
	link := filepath.Join(dir, "sopshq-link")
	if err := os.Symlink(src, link); err != nil {
		t.Fatal(err)
	}
	linkInfo, err := os.Stat(link) // follows the symlink to src
	if err != nil {
		t.Fatal(err)
	}
	if !binaryInPlace(srcInfo, linkInfo) {
		t.Fatal("binaryInPlace(file, symlink to it) = false, want true")
	}
	// Different files: copy.
	if binaryInPlace(srcInfo, dstInfo) {
		t.Fatal("binaryInPlace(different files) = true, want false (should copy)")
	}
	// Destination absent (nil info): copy.
	if binaryInPlace(srcInfo, nil) {
		t.Fatal("binaryInPlace(src, nil dest) = true, want false (should copy)")
	}
}

// TestPathSymlinkDecision covers the pure decision that gates the PATH symlink work:
// create when nothing is there, leave a symlink already pointing at the binary, repoint
// one pointing elsewhere, and refuse to clobber a non-symlink file in the way.
func TestPathSymlinkDecision(t *testing.T) {
	const want = "/opt/sopshq/sopshq"
	tests := []struct {
		name          string
		exists        bool
		isSymlink     bool
		currentTarget string
		wantAction    pathLinkAction
	}{
		{"absent", false, false, "", pathLinkCreate},
		{"symlink to us", true, true, want, pathLinkLeave},
		{"symlink elsewhere", true, true, "/usr/bin/other", pathLinkRepoint},
		{"non-symlink file", true, false, "", pathLinkRefuse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pathSymlinkDecision(tt.exists, tt.isSymlink, tt.currentTarget, want)
			if got != tt.wantAction {
				t.Fatalf("pathSymlinkDecision = %d, want %d", got, tt.wantAction)
			}
		})
	}
}

// TestBuildInitHandoff checks the privilege-dropped init command: the installed binary
// with `-dir <data>`, a Unix Credential carrying the service account's uid/gid, and an
// environment with exactly one HOME (the data base).
func TestBuildInitHandoff(t *testing.T) {
	plan := resolvePlan(setupOptions{
		Prefix: "/opt/sopshq", Data: "/srv/sopshq", Keybase: "/srv/sopshq-keys", User: "sopshq",
	})
	const uid, gid = 4242, 4343
	cmd := buildInitHandoff(plan, uid, gid)

	if cmd.Path != "/opt/sopshq/sopshq" {
		t.Fatalf("Path = %q, want /opt/sopshq/sopshq", cmd.Path)
	}
	wantArgs := []string{"/opt/sopshq/sopshq", "init", "-dir", "/srv/sopshq"}
	if len(cmd.Args) != len(wantArgs) {
		t.Fatalf("Args = %v, want %v", cmd.Args, wantArgs)
	}
	for i := range wantArgs {
		if cmd.Args[i] != wantArgs[i] {
			t.Fatalf("Args[%d] = %q, want %q", i, cmd.Args[i], wantArgs[i])
		}
	}

	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil {
		t.Fatalf("SysProcAttr.Credential is nil (privileges not dropped)")
	}
	if cmd.SysProcAttr.Credential.Uid != uid || cmd.SysProcAttr.Credential.Gid != gid {
		t.Fatalf("Credential = {%d,%d}, want {%d,%d}",
			cmd.SysProcAttr.Credential.Uid, cmd.SysProcAttr.Credential.Gid, uid, gid)
	}

	var homes int
	for _, e := range cmd.Env {
		if strings.HasPrefix(e, "HOME=") {
			homes++
			if e != "HOME=/srv/sopshq" {
				t.Fatalf("HOME = %q, want HOME=/srv/sopshq", e)
			}
		}
	}
	if homes != 1 {
		t.Fatalf("expected exactly one HOME entry, got %d", homes)
	}
}
