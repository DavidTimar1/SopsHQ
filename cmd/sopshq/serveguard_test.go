package main

import (
	"strings"
	"testing"
)

// TestServeGuardDecision covers the pure yes/no logic that refuses to serve as root
// or from a data directory this process does not own.
func TestServeGuardDecision(t *testing.T) {
	const dataDir = "/srv/sopshq/data"
	tests := []struct {
		name         string
		euid         int
		procUID      int
		dataUID      int
		ownerKnown   bool
		wantErr      bool
		errSubstring string // lowercased; checked only when wantErr is true
	}{
		{"non-unix (euid -1) -> allow", -1, 0, 0, true, false, ""},
		{"root -> refuse", 0, 0, 1000, true, true, "root"},
		{"owned by this user -> allow", 1000, 1000, 1000, true, false, ""},
		{"owned by another user -> refuse", 1000, 1000, 0, true, true, "owned by uid"},
		{"owner unknown -> allow", 1000, 1000, 0, false, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := serveGuardDecision(tt.euid, tt.procUID, tt.dataUID, tt.ownerKnown, dataDir)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil")
				}
				if !strings.Contains(strings.ToLower(err.Error()), tt.errSubstring) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstring)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}
