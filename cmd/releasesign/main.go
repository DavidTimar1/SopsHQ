// Command releasesign is the release-side half of `sopshq update`: it creates the
// release signing key, writes the signed SHA256SUMS, and signs it. It is stdlib only
// and never prints the private seed.
//
//	releasesign keygen [-seed-out FILE] [-pub-out FILE]
//	releasesign sums   -version X.Y.Z -out SHA256SUMS FILE...
//	releasesign sign   -in SHA256SUMS -out SHA256SUMS.sig
//	releasesign publish -tag vX.Y.Z -seed FILE [-repo OWNER/REPO]
//
// Releases are signed on the operator's own machine and the seed never reaches GitHub.
// "publish" takes the draft release the pipeline built, signs its SHA256SUMS with the
// seed file, uploads the signature and publishes the draft. "sign" does the signing
// step alone, reading the hex seed from the SOPSHQ_RELEASE_SIGNING_SEED environment
// variable. Both refuse to sign unless the seed matches a public key embedded in this
// source tree, so a release that no installed binary could verify is never published.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"sopshq/internal/update"
)

// seedEnv is the environment variable holding the hex signing seed.
const seedEnv = "SOPSHQ_RELEASE_SIGNING_SEED"

// embeddedKeys are the public keys sign must match (the primary or the next one). It is
// a variable so a test can supply them; the shipped key files are placeholders until the
// operator embeds the real key.
var embeddedKeys = update.EmbeddedKeys

// Public key files keygen writes, one header per slot; the embedded-key parser ignores
// comment lines.
const (
	primaryHeader = `# The release signing PUBLIC key (ML-DSA-65), as one hex string, embedded into the
# binary at build time. Releases are signed with the matching private key, which only
# the release operator holds; "sopshq update" refuses every update while this file holds
# no key.
# Lines starting with # and blank lines are ignored.
`
	nextHeader = `# The NEXT release signing public key (optional), same format as release_pubkey.hex.
# Leave it empty except during a key rotation: put the new key here, ship a release,
# sign with the new key, then move it into release_pubkey.hex and empty this file.
# An empty release_pubkey.hex still refuses every update, whatever is here.
# Lines starting with # and blank lines are ignored.
`
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Getenv); err != nil {
		fmt.Fprintf(os.Stderr, "releasesign: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer, getenv func(string) string) error {
	if len(args) == 0 {
		return errors.New("usage: releasesign keygen|sums|sign|publish [flags]")
	}
	switch args[0] {
	case "keygen":
		return cmdKeygen(args[1:], stdout)
	case "sums":
		return cmdSums(args[1:], stdout)
	case "sign":
		return cmdSign(args[1:], stdout, getenv)
	case "publish":
		return cmdPublish(args[1:], stdout, getenv)
	default:
		return fmt.Errorf("unknown subcommand %q (want keygen, sums, sign or publish)", args[0])
	}
}

// cmdKeygen creates a keypair. The seed goes to a new file (0600, never overwritten,
// never inside a git work tree) and is not printed; the public key goes to the file the
// binary embeds for the chosen slot.
func cmdKeygen(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	seedOut := fs.String("seed-out", "", "REQUIRED: file to write the private seed to (mode 0600, must not exist, must be outside any git work tree)")
	slot := fs.String("slot", "primary", `which embedded key slot to fill: "primary" or "next" (for a rotation)`)
	pubOut := fs.String("pub-out", "", "file to write the public key to (default: the slot's file under internal/update)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *seedOut == "" {
		return errors.New("-seed-out is required: name a file outside the repository for the private seed")
	}
	if inside, err := insideGitWorkTree(*seedOut); err != nil {
		return err
	} else if inside {
		return fmt.Errorf("%s is inside a git work tree; the private seed must never be kept in a repository", *seedOut)
	}
	header := primaryHeader
	defaultOut := "release_pubkey.hex"
	switch *slot {
	case "primary":
	case "next":
		header, defaultOut = nextHeader, "release_pubkey_next.hex"
	default:
		return fmt.Errorf("-slot must be primary or next, got %q", *slot)
	}
	if *pubOut == "" {
		*pubOut = filepath.Join("internal", "update", defaultOut)
	}
	if existing, err := os.ReadFile(*pubOut); err == nil {
		if _, perr := update.ParsePublicKey(string(existing)); !errors.Is(perr, update.ErrNoKey) {
			return fmt.Errorf("%s already holds a public key; remove it by hand to replace it (a new key invalidates every release signed with the old one)", *pubOut)
		}
	}
	sk, err := update.GenerateKey()
	if err != nil {
		return err
	}
	seedFile, err := os.OpenFile(*seedOut, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s (it must not already exist): %w", *seedOut, err)
	}
	_, werr := seedFile.WriteString(update.SeedHex(sk) + "\n")
	if cerr := seedFile.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(*seedOut)
		return fmt.Errorf("write %s: %w", *seedOut, werr)
	}
	pub := header + update.EncodePublicKey(sk.PublicKey()) + "\n"
	if err := os.WriteFile(*pubOut, []byte(pub), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", *pubOut, err)
	}
	fmt.Fprintf(stdout, "private seed written to %s (mode 0600; it is not shown here)\n", *seedOut)
	fmt.Fprintf(stdout, "public key written to %s\n", *pubOut)
	return nil
}

// cmdSums writes SHA256SUMS: the version header and the SHA-256 of each named file.
func cmdSums(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("sums", flag.ContinueOnError)
	version := fs.String("version", "", "the release version, X.Y.Z")
	out := fs.String("out", "SHA256SUMS", "file to write")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := update.ParseVersion(*version); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("name at least one release file to checksum")
	}
	files := make(map[string]string, fs.NArg())
	for _, path := range fs.Args() {
		sum, err := hashFile(path)
		if err != nil {
			return err
		}
		files[filepath.Base(path)] = sum
	}
	body := update.FormatSums(*version, files)
	if _, err := update.ParseSums(body); err != nil {
		return fmt.Errorf("the SHA256SUMS this would write is not valid: %w", err)
	}
	if err := os.WriteFile(*out, body, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s for release %s\n", *out, *version)
	return nil
}

// cmdSign signs a SHA256SUMS file with the seed from the environment, then verifies the
// signature against the embedded public key before keeping it.
func cmdSign(args []string, stdout io.Writer, getenv func(string) string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	in := fs.String("in", "SHA256SUMS", "the SHA256SUMS file to sign")
	out := fs.String("out", "SHA256SUMS.sig", "the signature file to write")
	if err := fs.Parse(args); err != nil {
		return err
	}
	seed := getenv(seedEnv)
	if seed == "" {
		return fmt.Errorf("%s is not set", seedEnv)
	}
	sk, err := update.PrivateKeyFromSeedHex(seed)
	if err != nil {
		return err
	}
	sums, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	if _, err := update.ParseSums(sums); err != nil {
		return err
	}
	sig, err := update.Sign(sk, sums)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	keys, err := embeddedKeys()
	if err != nil {
		return err
	}
	if !keys.Matches(sk) {
		return errors.New("the signing seed matches neither public key embedded in internal/update (release_pubkey.hex, release_pubkey_next.hex); " +
			"no installed binary could verify this release, so it is not signed")
	}
	if _, err := update.VerifySums(keys, sums, sig); err != nil {
		return err
	}
	if err := os.WriteFile(*out, sig, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "signed %s -> %s (verified against the embedded public keys)\n", *in, *out)
	return nil
}

// insideGitWorkTree reports whether path (which may not exist yet) lies inside a git work
// tree: some folder above it holds a .git entry.
func insideGitWorkTree(path string) (bool, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	dir := filepath.Dir(abs)
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return true, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false, nil
		}
		dir = parent
	}
}

// hashFile returns the hex SHA-256 of the file at path.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
