package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"sopshq/internal/auth"
)

// drivesSentinel is the pseudo-path that lists Windows drive roots. It is returned
// as the "parent" of a volume root so the operator can step up to pick another
// drive, and accepted as an incoming path to render that drive list.
const drivesSentinel = "\x00drives"

// fsEntry is one selectable sub-folder: its display name and full path.
type fsEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// fsListing is the JSON the folder-picker modal consumes. Parent is null when there
// is no folder to step up into (the root of a Linux filesystem).
type fsListing struct {
	Path   string    `json:"path"`
	Parent *string   `json:"parent,omitempty"`
	Dirs   []fsEntry `json:"dirs"`
	Error  string    `json:"error,omitempty"`
}

// browseFolder lists the sub-folders of a directory on THIS machine for the
// folder-picker modal. It is login-gated and read-only: it returns directory NAMES
// only and never opens or returns any file's contents. It cannot see other
// machines' filesystems (the panel runs on one machine), so remote paths are typed.
func (s *Server) browseFolder(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	listing := listFolders(r.URL.Query().Get("path"))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(listing)
}

// listFolders builds the listing for one directory. An empty path starts at the
// operator's home directory (or the Windows drive list).
func listFolders(path string) fsListing {
	path = strings.TrimSpace(path)
	if runtime.GOOS == "windows" && (path == "" || path == drivesSentinel) {
		return fsListing{Path: drivesSentinel, Dirs: windowsDrives()}
	}
	if path == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			path = home
		} else {
			path = string(os.PathSeparator)
		}
	}
	path = filepath.Clean(path)

	entries, err := os.ReadDir(path)
	if err != nil {
		return fsListing{Path: path, Error: "Cannot open this folder."}
	}
	dirs := make([]fsEntry, 0, len(entries))
	for _, e := range entries {
		if isListableDir(path, e) {
			dirs = append(dirs, fsEntry{Name: e.Name(), Path: filepath.Join(path, e.Name())})
		}
	}
	sort.Slice(dirs, func(i, j int) bool {
		return strings.ToLower(dirs[i].Name) < strings.ToLower(dirs[j].Name)
	})

	out := fsListing{Path: path, Dirs: dirs}
	if parent := filepath.Dir(path); parent != path {
		out.Parent = &parent
	} else if runtime.GOOS == "windows" {
		// At a volume root (e.g. C:\): step up to the drive list.
		d := drivesSentinel
		out.Parent = &d
	}
	return out
}

// isListableDir reports whether a directory entry should appear as a selectable
// sub-folder. A plain directory qualifies directly. A symlink is followed once with
// os.Stat (which resolves the link) and qualifies when it points at a directory, so
// a project moved behind a symlink is reachable; a broken or non-directory symlink is
// skipped. The link is shown as a folder to select, not descended into recursively.
func isListableDir(dir string, e os.DirEntry) bool {
	if e.IsDir() {
		return true
	}
	if e.Type()&os.ModeSymlink == 0 {
		return false
	}
	fi, err := os.Stat(filepath.Join(dir, e.Name()))
	return err == nil && fi.IsDir()
}

// windowsDrives returns the existing drive roots (C:\, Z:\, ...) as selectable
// entries. It probes A: through Z: and keeps the ones that stat.
func windowsDrives() []fsEntry {
	var drives []fsEntry
	for c := 'A'; c <= 'Z'; c++ {
		root := string(c) + ":\\"
		if _, err := os.Stat(root); err == nil {
			drives = append(drives, fsEntry{Name: root, Path: root})
		}
	}
	return drives
}
