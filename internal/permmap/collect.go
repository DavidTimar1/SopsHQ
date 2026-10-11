package permmap

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// ErrNotLinux is returned by Collect on any non-Linux host. The POSIX
// permission scan relies on find/getfacl/getcap and the POSIX ACL model, which
// only exist on Linux; Windows uses a different ACL model and is out of scope.
var ErrNotLinux = errors.New("permmap: POSIX permission scan requires Linux")

// ErrToolsMissing is returned when the required collector binaries (find,
// getfacl) are not on PATH. getcap is optional; its absence only means no file
// capabilities are reported.
var ErrToolsMissing = errors.New("permmap: required tools not found on PATH (install findutils and the acl package)")

// Collect scans the given roots and returns one Entry per discovered path. It
// executes the standard Linux collectors:
//
//	find <root> -printf "%y\t%p\n"   entry type per path
//	getfacl -R -p <root>             owner, group, mode, special bits, ACL, default ACL
//	getcap -r <root>                 file capabilities (sparse)
//
// and merges their output by path through the pure parser and flag rules. All
// subprocess stdout is decoded as UTF-8 explicitly (paths and names are data we
// did not author and may contain non-ASCII bytes); invalid bytes are tolerated
// rather than rejected.
//
// When scanUser is non-empty each collector is run via `sudo -n -u <scanUser>`,
// so the scan executes as the dedicated, locked-down scan user rather than as the
// SopsHQ process. An empty scanUser runs the collectors directly (as the current
// user) - useful for tests and for a setup where SopsHQ itself can already read
// the roots.
//
// Collect runs only on Linux and returns ErrNotLinux elsewhere, so the package
// still builds on Windows. Roots that are empty or do not exist are skipped.
func Collect(scanUser string, roots []string) ([]Entry, error) {
	if runtime.GOOS != "linux" {
		return nil, ErrNotLinux
	}
	if _, err := exec.LookPath("find"); err != nil {
		return nil, ErrToolsMissing
	}
	if _, err := exec.LookPath("getfacl"); err != nil {
		return nil, ErrToolsMissing
	}

	types := make(map[string]string)
	facl := make(map[string]*faclAttrs)
	caps := make(map[string]string)

	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		if _, err := os.Stat(root); err != nil {
			continue
		}
		mergeTypes(types, runStdout(scanUser, "find", root, "-printf", "%y\t%p\n"))
		for path, a := range parseGetfacl(runStdout(scanUser, "getfacl", "-R", "-p", root)) {
			facl[path] = a
		}
		mergeCaps(caps, runStdout(scanUser, "getcap", "-r", root))
	}
	return assemble(types, facl, caps), nil
}

// sudoWrap returns the command name and argument list to run name+args as
// scanUser. With an empty scanUser the command runs directly; otherwise it is
// wrapped in `sudo -n -u <scanUser>` (-n: never prompt, so a missing sudoers rule
// fails fast rather than hanging on a password prompt).
func sudoWrap(scanUser, name string, args []string) (string, []string) {
	if scanUser == "" {
		return name, args
	}
	return "sudo", append([]string{"-n", "-u", scanUser, name}, args...)
}

// runStdout runs a command (optionally as scanUser) and returns its stdout decoded
// as UTF-8. Stderr is discarded. A missing binary or a non-zero exit yields
// whatever was captured (empty on a missing binary), mirroring the reference
// engine's best-effort collection.
func runStdout(scanUser, name string, args ...string) string {
	n, a := sudoWrap(scanUser, name, args)
	cmd := exec.Command(n, a...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil // connect child stderr to the null device
	_ = cmd.Run()
	return out.String()
}

// mergeTypes records path -> type letter from `find -printf "%y\t%p\n"` output.
func mergeTypes(dst map[string]string, out string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue
		}
		dst[line[tab+1:]] = line[:tab]
	}
}

// mergeCaps records path -> capabilities string from `getcap -r` output. Each
// line is "<path> <caps>"; the path may contain spaces, so the cap token is the
// last space-separated field. getcap sometimes prints "<path> =<caps>", which
// is normalized away.
func mergeCaps(dst map[string]string, out string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		idx := strings.LastIndexByte(line, ' ')
		if idx <= 0 {
			continue
		}
		path, c := strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])
		if strings.HasSuffix(path, " =") {
			path = strings.TrimSpace(path[:len(path)-2])
		}
		dst[path] = c
	}
}
