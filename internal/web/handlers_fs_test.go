package web

import (
	"os"
	"path/filepath"
	"testing"
)

// TestListFoldersListsSubdirs checks the folder browser lists sub-directories of a
// real path, offers a parent to step up into, and never returns files.
func TestListFoldersListsSubdirs(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "alpha"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "beta"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "a-file.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	got := listFolders(root)
	if got.Error != "" {
		t.Fatalf("unexpected error: %s", got.Error)
	}
	if len(got.Dirs) != 2 {
		t.Fatalf("want 2 sub-folders (files excluded), got %d: %+v", len(got.Dirs), got.Dirs)
	}
	if got.Dirs[0].Name != "alpha" || got.Dirs[1].Name != "beta" {
		t.Fatalf("sub-folders should be sorted: %+v", got.Dirs)
	}
	if got.Parent == nil {
		t.Fatal("a non-root folder should offer a parent to step up into")
	}
}

// TestListFoldersBadPath reports an error rather than panicking on a missing path.
func TestListFoldersBadPath(t *testing.T) {
	got := listFolders(filepath.Join(t.TempDir(), "does-not-exist"))
	if got.Error == "" {
		t.Fatal("expected an error for a missing folder")
	}
}

// TestListFoldersIncludesSymlinkDirs checks the browser lists a symlink that
// resolves to a directory (a moved project folder reached through a link) and skips
// a symlink to a file and a broken (dangling) symlink.
func TestListFoldersIncludesSymlinkDirs(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real-dir")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("mkdir real dir: %v", err)
	}
	realFile := filepath.Join(root, "real-file.txt")
	if err := os.WriteFile(realFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := os.Symlink(realDir, filepath.Join(root, "link-to-dir")); err != nil {
		t.Skipf("cannot create symlinks on this host (need privilege): %v", err)
	}
	if err := os.Symlink(realFile, filepath.Join(root, "link-to-file")); err != nil {
		t.Fatalf("symlink to file: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "gone"), filepath.Join(root, "broken-link")); err != nil {
		t.Fatalf("broken symlink: %v", err)
	}

	got := listFolders(root)
	if got.Error != "" {
		t.Fatalf("unexpected error: %s", got.Error)
	}
	names := map[string]bool{}
	for _, d := range got.Dirs {
		names[d.Name] = true
	}
	if !names["real-dir"] {
		t.Errorf("real directory should be listed: %+v", got.Dirs)
	}
	if !names["link-to-dir"] {
		t.Errorf("a symlink that resolves to a directory should be listed: %+v", got.Dirs)
	}
	if names["link-to-file"] {
		t.Errorf("a symlink to a file must not be listed: %+v", got.Dirs)
	}
	if names["broken-link"] {
		t.Errorf("a broken symlink must not be listed: %+v", got.Dirs)
	}
	if names["real-file.txt"] {
		t.Errorf("a plain file must not be listed: %+v", got.Dirs)
	}
}
