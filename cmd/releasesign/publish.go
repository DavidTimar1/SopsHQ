package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"sopshq/internal/update"
)

// ghBinary finds the GitHub CLI at a fixed absolute system path, never through PATH. It
// is a variable so a test can point it at a fake.
var ghBinary = func() string { return update.FirstExecutable(update.GHPaths) }

var publishTagRe = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// draftRelease is the part of `gh release view --json` that publish reads.
type draftRelease struct {
	TagName string `json:"tagName"`
	IsDraft bool   `json:"isDraft"`
	Assets  []struct {
		Name string `json:"name"`
	} `json:"assets"`
}

func (d draftRelease) hasAsset(name string) bool {
	for _, a := range d.Assets {
		if a.Name == name {
			return true
		}
	}
	return false
}

// ghHost runs the GitHub CLI as the operator who runs releasesign, with their own login.
// No token is read, passed or printed here.
type ghHost struct{ bin string }

func (g ghHost) run(stdout io.Writer, args ...string) error {
	cmd := exec.Command(g.bin, args...)
	cmd.Env = append(os.Environ(), "GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1", "NO_COLOR=1")
	cmd.Stdout, cmd.Stderr = stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gh %s %s: %w", args[0], args[1], err)
	}
	return nil
}

func (g ghHost) view(repo, tag string) (draftRelease, error) {
	var out bytes.Buffer
	if err := g.run(&out, "release", "view", tag, "--repo", repo, "--json", "tagName,isDraft,assets"); err != nil {
		return draftRelease{}, fmt.Errorf("%w (is gh logged in as you, with access to %s?)", err, repo)
	}
	var d draftRelease
	if err := json.Unmarshal(out.Bytes(), &d); err != nil {
		return draftRelease{}, fmt.Errorf("gh printed an unreadable release description: %w", err)
	}
	return d, nil
}

// cmdPublish completes a release on the operator's machine: it takes the draft the
// release job built, signs its SHA256SUMS locally, uploads the signature and publishes
// the draft. The seed never leaves this machine and is never printed.
func cmdPublish(args []string, stdout io.Writer, getenv func(string) string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	tag := fs.String("tag", "", "the release tag, vX.Y.Z")
	seedPath := fs.String("seed", "", "file holding the hex signing seed (kept outside the repository)")
	repoFlag := fs.String("repo", "", "GitHub OWNER/REPO that holds the draft release (used when "+update.EnvRepo+" is not set)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !publishTagRe.MatchString(*tag) {
		return fmt.Errorf("-tag must look like v1.2.3, got %q", *tag)
	}
	if *seedPath == "" {
		return errors.New("-seed is required: the file holding the signing seed")
	}
	repo := strings.TrimSpace(getenv(update.EnvRepo))
	if repo == "" {
		repo = strings.TrimSpace(*repoFlag)
	}
	if repo == "" {
		return fmt.Errorf("no release repository: set %s=OWNER/REPO or pass -repo", update.EnvRepo)
	}
	if err := update.ValidateRepo(repo); err != nil {
		return err
	}
	gh := ghBinary()
	if gh == "" {
		return fmt.Errorf("the GitHub CLI (gh) was not found at %s", strings.Join(update.GHPaths, ", "))
	}

	// Everything that needs no network comes first: the key must be the embedded one.
	keys, err := embeddedKeys()
	if err != nil {
		return err
	}
	seed, err := os.ReadFile(*seedPath)
	if err != nil {
		return fmt.Errorf("read the seed file: %w", err)
	}
	sk, err := update.PrivateKeyFromSeedHex(string(seed))
	if err != nil {
		return err
	}
	if !keys.Matches(sk) {
		return errors.New("the signing seed matches neither public key embedded in internal/update; " +
			"no installed binary could verify this release, so it is not signed")
	}

	host := ghHost{bin: gh}
	rel, err := host.view(repo, *tag)
	if err != nil {
		return err
	}
	switch {
	case !rel.IsDraft:
		return fmt.Errorf("release %s of %s is not a draft; refusing to sign a release that is already public", *tag, repo)
	case rel.hasAsset(update.SigFile):
		return fmt.Errorf("release %s already has %s; refusing to sign it twice", *tag, update.SigFile)
	case !rel.hasAsset(update.SumsFile):
		return fmt.Errorf("release %s has no %s to sign", *tag, update.SumsFile)
	}

	work, err := os.MkdirTemp("", "releasesign-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	if err := host.run(io.Discard, "release", "download", *tag, "--repo", repo, "--dir", work, "--pattern", update.SumsFile); err != nil {
		return err
	}
	sums, err := os.ReadFile(filepath.Join(work, update.SumsFile))
	if err != nil {
		return err
	}
	parsed, err := update.ParseSums(sums)
	if err != nil {
		return err
	}
	if want := strings.TrimPrefix(*tag, "v"); parsed.Version != want {
		return fmt.Errorf("%s names version %s but the tag is %s; refusing to sign", update.SumsFile, parsed.Version, *tag)
	}
	for _, name := range parsed.Names() {
		if !rel.hasAsset(name) {
			return fmt.Errorf("%s lists %s but the draft has no such asset; refusing to sign", update.SumsFile, name)
		}
	}
	sig, err := update.Sign(sk, sums)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if _, err := update.VerifySums(keys, sums, sig); err != nil {
		return fmt.Errorf("the new signature does not verify: %w", err)
	}
	sigPath := filepath.Join(work, update.SigFile)
	if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
		return err
	}
	if err := host.run(io.Discard, "release", "upload", *tag, sigPath, "--repo", repo); err != nil {
		return err
	}
	if err := host.run(io.Discard, "release", "edit", *tag, "--repo", repo, "--draft=false"); err != nil {
		return fmt.Errorf("%w (the signature is uploaded; publish the draft by hand)", err)
	}
	fmt.Fprintf(stdout, "signed and published release %s of %s (signature verified against the embedded public keys)\n", *tag, repo)
	return nil
}
