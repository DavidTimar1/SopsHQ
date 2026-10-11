package update

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"time"
)

// KeepBackups is how many old binaries a successful update leaves in the backups
// folder.
const KeepBackups = 3

// backupPrefix starts every backup name this package writes: backupPrefix + version.
// The pruner deletes only names of exactly this shape, so a file an operator dropped in
// the folder is never touched.
const backupPrefix = "sopshq-"

var backupNameRe = regexp.MustCompile(`^` + backupPrefix + `((0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))$`)

// Backup is one saved binary in the backups folder.
type Backup struct {
	Name    string
	Version string
	ModTime time.Time
}

// BackupName is the file name the binary of version is saved under.
func BackupName(version string) (string, error) {
	if _, err := ParseVersion(version); err != nil {
		return "", fmt.Errorf("backup name: %w", err)
	}
	return backupPrefix + version, nil
}

// ListBackups returns the backups in dir, highest version first (by the version in the
// file name, never by modification time). Only regular files with a name
// BackupName could have produced are listed; symlinks, directories and other names are
// ignored. A missing folder is an empty list.
func ListBackups(dir string) ([]Backup, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list backups in %s: %w", dir, err)
	}
	var out []Backup
	for _, e := range entries {
		m := backupNameRe.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, fmt.Errorf("stat backup %s: %w", e.Name(), err)
		}
		out = append(out, Backup{Name: e.Name(), Version: m[1], ModTime: info.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool {
		vi, _ := ParseVersion(out[i].Version)
		vj, _ := ParseVersion(out[j].Version)
		return vi.Compare(vj) > 0
	})
	return out, nil
}

// PruneBackups deletes every backup in dir except the keep highest versions and any name
// in protect (for example the backup written in this very run), and returns the
// names it removed. It deletes only entries ListBackups returned, each by joining its
// own listed name onto dir, so nothing outside the folder or off the naming pattern
// can be removed.
func PruneBackups(dir string, keep int, protect ...string) ([]string, error) {
	backups, err := ListBackups(dir)
	if err != nil {
		return nil, err
	}
	if len(backups) <= keep {
		return nil, nil
	}
	var removed []string
	for _, b := range backups[keep:] {
		if slices.Contains(protect, b.Name) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, b.Name)); err != nil {
			return removed, fmt.Errorf("remove old backup %s: %w", b.Name, err)
		}
		removed = append(removed, b.Name)
	}
	return removed, nil
}
