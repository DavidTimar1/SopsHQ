package update

import "os"

// GHPaths are the only places the GitHub CLI is looked for. A program that runs as root,
// or that signs a release, is never found through PATH: PATH can name a folder another
// user can write to.
var GHPaths = []string{"/usr/bin/gh", "/usr/local/bin/gh", "/bin/gh", "/snap/bin/gh"}

// FirstExecutable returns the first of paths that is a regular file, or "" when none is.
func FirstExecutable(paths []string) string {
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

// Names returns the asset names SHA256SUMS lists, in no particular order.
func (s Sums) Names() []string {
	names := make([]string, 0, len(s.files))
	for n := range s.files {
		names = append(names, n)
	}
	return names
}
