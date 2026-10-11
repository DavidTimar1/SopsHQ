package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// normalizeFlagArgs lowercases the flag-NAME portion of every flag-looking token in
// args, so `-DIR`, `-Dir`, and `-dir` all reach flag.FlagSet.Parse as `-dir` (Go's
// flag package matches flag names case-sensitively, so a capitalized flag typed at a
// Windows prompt would otherwise be silently treated as "not a recognized flag"). A
// token counts as flag-looking when it starts with `-` and is more than one
// character (a bare `-` is a conventional "read from stdin" value, not a flag, and is
// left untouched). For a `name=value` token, only the part up to (and excluding) the
// first `=` is lowercased; the value keeps its original case. A bare `--` terminator
// stops the transform: it and every token after it pass through unchanged, matching
// how flag.FlagSet itself treats `--` as "everything after this is a positional
// argument". Every non-flag token is left untouched throughout.
func normalizeFlagArgs(args []string) []string {
	out := make([]string, 0, len(args))
	terminated := false
	for _, tok := range args {
		switch {
		case terminated:
			out = append(out, tok)
		case tok == "--":
			terminated = true
			out = append(out, tok)
		case len(tok) > 1 && tok[0] == '-':
			out = append(out, lowerFlagName(tok))
		default:
			out = append(out, tok)
		}
	}
	return out
}

// lowerFlagName lowercases the flag-name portion of a single flag-looking token:
// everything up to (and excluding) the first `=`, or the whole token when there is no
// `=`. It is the per-token transform normalizeFlagArgs applies.
func lowerFlagName(tok string) string {
	if idx := strings.IndexByte(tok, '='); idx >= 0 {
		return strings.ToLower(tok[:idx]) + tok[idx:]
	}
	return strings.ToLower(tok)
}

// stripTrailingQuoteValue removes exactly one trailing literal `"` from value, when
// present. It is the GOOS-independent core of stripTrailingQuote, kept separate so
// the stripping logic itself is unit-tested without depending on the host platform.
func stripTrailingQuoteValue(value string) (cleaned string, stripped bool) {
	if value == "" || value[len(value)-1] != '"' {
		return value, false
	}
	return value[:len(value)-1], true
}

// stripTrailingQuote defends against a Windows quoting quirk: a path flag passed as
// `-dir "C:\some path\"` (a trailing backslash right before the closing quote escapes
// that quote for `cmd.exe`/PowerShell argument splitting, so the literal `"` lands in
// the value Go's flag package sees) leaves a stray trailing `"` on the value. It is
// gated to Windows (runtime.GOOS == "windows") - never touches a value on any other
// platform, where a trailing quote is presumed intentional. flagName is not used to
// decide whether to strip; callers that print the operator-facing note need it, so it
// travels with the value being cleaned rather than being reconstructed at each call
// site.
func stripTrailingQuote(flagName, value string) (cleaned string, stripped bool) {
	if runtime.GOOS != "windows" {
		return value, false
	}
	return stripTrailingQuoteValue(value)
}

// applyTrailingQuoteFix strips a stray trailing quote from *val (via stripTrailingQuote)
// and, when it fires, rewrites *val in place and prints one operator-facing note to
// stderr naming the flag and the cleaned value actually used. Call it once per
// path-valued flag, after fs.Parse succeeds.
func applyTrailingQuoteFix(flagName string, val *string) {
	cleaned, stripped := stripTrailingQuote(flagName, *val)
	if !stripped {
		return
	}
	*val = cleaned
	fmt.Fprintf(os.Stderr, "note: stripped a trailing \" from -%s (Windows quoting quirk); using: %s\n", flagName, cleaned)
}
