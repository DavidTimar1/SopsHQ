package main

import (
	"runtime"
	"strings"
	"testing"
)

// TestClassifyDirProbe covers the truthful distinction the preflight draws between a
// MISSING directory (which the systemd sandbox would otherwise misreport as read-only)
// and a present-but-unwritable one, plus the healthy case.
func TestClassifyDirProbe(t *testing.T) {
	tests := []struct {
		name     string
		exists   bool
		writable bool
		hint     string
		wantErr  bool
		substrs  []string
	}{
		{"healthy", true, true, "", false, nil},
		{"missing", false, false, "", true, []string{"does not exist", "/mnt/vol/sopshq"}},
		{"missing with mount hint", false, false, "the volume at /mnt/vol does not appear to be mounted", true,
			[]string{"does not exist", "does not appear to be mounted"}},
		{"present not writable", true, false, "", true, []string{"not writable", "sopshq"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := classifyDirProbe("data", "/mnt/vol/sopshq", "sopshq", tt.exists, tt.writable, tt.hint)
			if tt.wantErr != (err != nil) {
				t.Fatalf("classifyDirProbe wantErr=%v, got err=%v", tt.wantErr, err)
			}
			if err == nil {
				return
			}
			for _, s := range tt.substrs {
				if !strings.Contains(err.Error(), s) {
					t.Fatalf("error %q missing %q", err.Error(), s)
				}
			}
		})
	}
}

// TestUnmountedMountHint verifies the hint fires only when a directory directly under a
// conventional mount parent (/mnt/<x>, /media/<x>) is not currently a mount point.
func TestUnmountedMountHint(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("exercises Linux absolute-path semantics; host filepath must be Linux")
	}
	tests := []struct {
		name    string
		path    string
		mounted map[string]bool
		want    string
	}{
		{"volume not mounted", "/mnt/vol/sopshq", map[string]bool{}, "the volume at /mnt/vol does not appear to be mounted"},
		{"volume mounted", "/mnt/vol/sopshq", map[string]bool{"/mnt/vol": true}, ""},
		{"not under a mount parent", "/opt/sopshq/data", map[string]bool{}, ""},
		{"media not mounted", "/media/vault/keys", map[string]bool{}, "the volume at /media/vault does not appear to be mounted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isMounted := func(d string) bool { return tt.mounted[d] }
			if got := unmountedMountHint(tt.path, isMounted); got != tt.want {
				t.Fatalf("unmountedMountHint(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// TestPathJunctions covers the ordered root-to-leaf component walk shared by the preflight
// and the path-permission review.
func TestPathJunctions(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("exercises Linux absolute-path semantics; host filepath must be Linux")
	}
	got := pathJunctions("/mnt/vol/sopshq")
	want := []string{"/", "/mnt", "/mnt/vol", "/mnt/vol/sopshq"}
	if len(got) != len(want) {
		t.Fatalf("pathJunctions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pathJunctions[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if r := pathJunctions("/"); len(r) != 1 || r[0] != "/" {
		t.Fatalf("pathJunctions(/) = %v, want [/]", r)
	}
	if r := pathJunctions("relative/path"); r != nil {
		t.Fatalf("pathJunctions(relative) = %v, want nil", r)
	}
}
