package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestReleaseRepoRoundTrips confirms the release source survives a save and load and
// stays empty while unset.
func TestReleaseRepoRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.jsonc")
	c := Default(path, dir, "n")
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || got.ReleaseRepo != "" {
		t.Fatalf("unset release_repo = %q err=%v, want empty", got.ReleaseRepo, err)
	}
	got.ReleaseRepo = "owner/repo"
	if err := got.Save(); err != nil {
		t.Fatal(err)
	}
	again, err := Load(path)
	if err != nil || again.ReleaseRepo != "owner/repo" {
		t.Fatalf("release_repo = %q err=%v, want owner/repo", again.ReleaseRepo, err)
	}
}

// TestSaveDoesNotWriteThroughPlantedLink guards the root-caller case: a symlink left at
// the temp name is replaced, never followed, so the link's target is untouched.
func TestSaveDoesNotWriteThroughPlantedLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.jsonc")
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path+".tmp"); err != nil {
		t.Fatal(err)
	}
	c := Default(path, dir, "n")
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "original" {
		t.Fatalf("Save wrote through the planted link; target now holds %q", b)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("config not written: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %v err=%v, want 0600", fi.Mode().Perm(), err)
	}
}

// TestSaveRefusesANonRegularConfig confirms a config that is a symlink is neither
// followed nor replaced.
func TestSaveRefusesANonRegularConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "real.jsonc")
	if err := Default(real, dir, "n").Save(); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "config.jsonc")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	c := Default(link, dir, "n")
	if err := c.Save(); err == nil {
		t.Fatal("Save replaced a symlinked config")
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink was replaced: %v %v", fi, err)
	}
}
