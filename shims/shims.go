// Package shims embeds the optional "sops" usage-reporter wrapper scripts so SopsHQ
// can install them on a machine straight from the running binary (a deployed binary
// has no repository checkout to copy from). The same files live here as plain,
// human-readable scripts that can also be installed by hand.
//
// These scripts only REPORT usage to the panel and then run the real sops; they
// never carry key material. See docs/architecture/keys.md "Key-usage tracking".
package shims

import "embed"

// FS holds the wrapper scripts and the Windows launcher.
//
//go:embed sops-wrapper.sh sops-wrapper.ps1 sops.cmd
var FS embed.FS

// Names of the embedded files, so callers do not hardcode strings.
const (
	WrapperSh   = "sops-wrapper.sh"
	WrapperPS1  = "sops-wrapper.ps1"
	LauncherCmd = "sops.cmd"
)
