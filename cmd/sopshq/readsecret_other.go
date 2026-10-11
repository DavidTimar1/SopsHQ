//go:build !windows && !linux

package main

// termReadSecret has no no-echo implementation on this platform; the caller falls
// back to a plain (visible) read. SopsHQ targets Windows and Linux, so this path
// is only hit on other operating systems.
func termReadSecret(prompt string) (string, error) {
	return "", errNoEcho
}

// stdinIsTTY conservatively reports no terminal on this platform; the caller then
// uses the ordinary reader. SopsHQ targets Windows and Linux, so this path is only
// hit on other operating systems.
func stdinIsTTY() bool { return false }
