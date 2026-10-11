// Package keys is SopsHQ's key engine. It generates age keypairs, writes the
// per-project .sops.yaml recipient list, and drives `sops updatekeys`. It works
// by executing the already-installed `age-keygen` and `sops` binaries rather
// than reimplementing them, which keeps the module dependency-free and the
// behavior identical to the hand-run tools.
//
// SECURITY: a generated private key (AGE-SECRET-KEY-1...) is returned to the
// caller so it can be vault-sealed immediately. It is never logged, and the
// helpers here never write it to disk; on-disk placement is the place package's
// job, done under the right ownership and permissions.
package keys

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ErrAgeKeygenMissing means the age-keygen binary is not on PATH.
var ErrAgeKeygenMissing = errors.New("keys: age-keygen not found on PATH (install age)")

// ageKeygenTimeout bounds every age-keygen invocation. Public-key derivation runs on
// the panel's render path (once per keystore during the on-disk key scan), so a hung
// or wedged age-keygen must not block a request goroutine indefinitely. A var, not a
// const, so a test can shorten it to exercise the deadline path. 5s is generous:
// age-keygen normally returns in milliseconds.
var ageKeygenTimeout = 5 * time.Second

// runAgeKeygen executes age-keygen with a deadline and returns its stdout. stdin, when
// non-empty, is fed on the child's STDIN (never as an argument, never to a file) - this
// is how a private key is passed for public-key derivation, so it never lands in argv
// or a temp file. On timeout it returns a clear error; on failure it includes STDERR
// only, never STDOUT (which may hold a freshly generated private key).
func runAgeKeygen(args []string, stdin string) (string, error) {
	bin, err := resolveAgeKeygen()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), ageKeygenTimeout)
	defer cancel()
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	cmd.Stdout = &out
	cmd.Stderr = &errb
	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("keys: age-keygen timed out after %s", ageKeygenTimeout)
	}
	if runErr != nil {
		// Do not include stdout (it may hold a secret) in the error.
		return "", fmt.Errorf("keys: age-keygen failed: %w: %s", runErr, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// Keypair is a freshly generated age identity. Private is SECRET.
type Keypair struct {
	Recipient string // age1... (public, safe to display)
	Private   string // AGE-SECRET-KEY-1... (SECRET: seal immediately, never log)
}

// ageKeygenPath is overridable in tests; empty means "resolve from PATH".
var ageKeygenPath string

func resolveAgeKeygen() (string, error) {
	if ageKeygenPath != "" {
		return ageKeygenPath, nil
	}
	p, err := exec.LookPath("age-keygen")
	if err != nil {
		return "", ErrAgeKeygenMissing
	}
	return p, nil
}

// Generate creates a new age keypair by running `age-keygen` and parsing its
// output. age-keygen prints three lines:
//
//	# created: <timestamp>
//	# public key: age1...
//	AGE-SECRET-KEY-1...
//
// We capture stdout (so the private key never touches disk) and extract both
// halves. The output is plain ASCII.
func Generate() (Keypair, error) {
	out, err := runAgeKeygen(nil, "")
	if err != nil {
		return Keypair{}, err
	}
	return parseAgeKeygen(out)
}

// RecipientFor derives the PUBLIC age recipient (age1...) for an existing private
// key by running `age-keygen -y` with the key on STDIN. It is the import path's
// companion to Generate: when SopsHQ ADOPTS a hand-placed key (REUSE), it must
// know the key's recipient to write .sops.yaml, but it never generates new
// material.
//
// SECURITY: the private key is passed only on the child's stdin - never as an
// argument and never to a file - and is not included in any returned error.
// age-keygen -y prints only the recipient.
func RecipientFor(private string) (string, error) {
	out, err := runAgeKeygen([]string{"-y"}, private)
	if err != nil {
		return "", err
	}
	rec := strings.TrimSpace(out)
	if !strings.HasPrefix(rec, "age1") {
		return "", errors.New("keys: could not derive recipient from private key")
	}
	return rec, nil
}

// RecipientsFor derives the PUBLIC recipients for an identity file that may hold
// MORE THAN ONE private key (a user assigned several project keys keeps them all in
// one keys.txt; age tries each). It runs `age-keygen -y` with the whole file on
// STDIN, which prints one recipient per identity line, and returns them all.
//
// SECURITY: the private keys are passed only on the child's stdin and never logged.
func RecipientsFor(identities string) ([]string, error) {
	out, err := runAgeKeygen([]string{"-y"}, identities)
	if err != nil {
		return nil, err
	}
	var recs []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "age1") {
			recs = append(recs, line)
		}
	}
	if len(recs) == 0 {
		return nil, errors.New("keys: could not derive any recipient from the key file")
	}
	return recs, nil
}

// parseAgeKeygen extracts the recipient and private key from age-keygen output.
// Split out so it can be unit-tested without invoking the binary.
func parseAgeKeygen(s string) (Keypair, error) {
	var kp Keypair
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "# public key:"):
			kp.Recipient = strings.TrimSpace(strings.TrimPrefix(line, "# public key:"))
		case strings.HasPrefix(line, "AGE-SECRET-KEY-"):
			kp.Private = strings.TrimSpace(line)
		}
	}
	if !strings.HasPrefix(kp.Recipient, "age1") {
		return Keypair{}, errors.New("keys: could not parse recipient from age-keygen output")
	}
	if !strings.HasPrefix(kp.Private, "AGE-SECRET-KEY-1") {
		return Keypair{}, errors.New("keys: could not parse private key from age-keygen output")
	}
	return kp, nil
}
