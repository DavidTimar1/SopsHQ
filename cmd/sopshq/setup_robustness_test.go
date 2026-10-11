package main

import (
	"os"
	"runtime"
	"testing"
)

// TestStaleServeMatch covers the pure argv parsing that identifies a `sopshq serve` and
// recovers its -config path (space form and = form, short and long flags), and rejects
// non-serve invocations.
func TestStaleServeMatch(t *testing.T) {
	tests := []struct {
		name       string
		argv       []string
		wantConfig string
		wantServe  bool
	}{
		{"serve with -config space", []string{"/opt/sopshq/sopshq", "serve", "-config", "/srv/sopshq/config.jsonc"}, "/srv/sopshq/config.jsonc", true},
		{"serve with --config=", []string{"sopshq", "serve", "--config=/data/config.jsonc"}, "/data/config.jsonc", true},
		{"serve with -config=", []string{"sopshq", "serve", "-config=/x/config.jsonc"}, "/x/config.jsonc", true},
		{"serve no config", []string{"sopshq", "serve"}, "", true},
		{"not serve", []string{"sopshq", "status"}, "", false},
		{"init is not serve", []string{"sopshq", "init", "-dir", "/x"}, "", false},
		{"empty argv", []string{}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCfg, gotServe := staleServeMatch(tt.argv)
			if gotServe != tt.wantServe || gotCfg != tt.wantConfig {
				t.Fatalf("staleServeMatch(%v) = (%q, %v), want (%q, %v)", tt.argv, gotCfg, gotServe, tt.wantConfig, tt.wantServe)
			}
		})
	}
}

// TestJunctionOffLimits covers the path-permission review guardrail that protects the
// root, any first-level directory, and any mount point from being weakened - notably an
// encrypted mount root such as /srv/vol - while allowing the leaf data dir and any
// ordinary intermediate directory.
func TestJunctionOffLimits(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("exercises Linux absolute-path semantics; host filepath must be Linux")
	}
	mounts := map[string]bool{"/srv/vol": true, "/": true}
	isMount := func(d string) bool { return mounts[d] }
	tests := []struct {
		path string
		want bool
	}{
		{"/", true},                      // filesystem root
		{"/mnt", true},                   // first-level directory
		{"/opt", true},                   // first-level directory
		{"/home", true},                  // first-level directory
		{"/srv/vol", true},               // the encrypted mount root (a mount point)
		{"/srv/vol/sopshq", false},       // leaf data dir - fixable
		{"/srv/vol/keys", false},         // keybase root - fixable
		{"/srv/apps/sopshq/data", false}, // ordinary nested path - fixable
	}
	for _, tt := range tests {
		if got := junctionOffLimits(tt.path, isMount); got != tt.want {
			t.Fatalf("junctionOffLimits(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// TestServiceCanTraverse covers the POSIX search-permission precedence used to decide
// whether the service account can descend through a junction: an existing ACL grant wins,
// then owner / group / other execute bits by identity. The ACL-wins case also stands in
// for path-permission review idempotence - a re-run over an already-ACL'd junction sees it as traversable and
// applies nothing.
func TestServiceCanTraverse(t *testing.T) {
	const svcUID, svcGID = 4242, 4343
	svcGIDs := []int{svcGID}
	tests := []struct {
		name               string
		perm               os.FileMode
		ownerUID, ownerGID int
		aclExec            bool
		want               bool
	}{
		{"acl grants (idempotent re-run)", 0o700, 0, 0, true, true},
		{"owner x, we own it", 0o700, svcUID, 0, false, true},
		{"owner has no x", 0o600, svcUID, 0, false, false},
		{"group x, we are in group", 0o710, 0, svcGID, false, true},
		{"group no x", 0o700, 0, svcGID, false, false},
		{"other x, not owner/group", 0o711, 0, 0, false, true},
		{"other no x, blocked", 0o700, 0, 0, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := serviceCanTraverse(tt.perm, tt.ownerUID, tt.ownerGID, svcUID, svcGIDs, tt.aclExec)
			if got != tt.want {
				t.Fatalf("serviceCanTraverse(%04o, owner %d:%d, acl=%v) = %v, want %v",
					tt.perm.Perm(), tt.ownerUID, tt.ownerGID, tt.aclExec, got, tt.want)
			}
		})
	}
}
