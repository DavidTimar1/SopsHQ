// Package update holds the pure parts of `sopshq update`: release versions and their
// ordering, the signed checksum file and its verification against the embedded release
// key, release asset names, and the binary backups kept for rollback. The commands
// that download and swap the running binary live in cmd/sopshq.
package update

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// EnvRepo is the environment variable that names the GitHub repository releases come
// from. It outranks the config file and the prompt.
const EnvRepo = "SOPSHQ_RELEASE_REPO"

// ConfigKey is the config.jsonc field that names the release repository.
const ConfigKey = "release_repo"

// repoRe is OWNER/REPO on github.com: no host, and no leading dash, so the value can
// never be read as a command-line flag by gh.
var repoRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ValidateRepo checks that s is a GitHub OWNER/REPO.
func ValidateRepo(s string) error {
	if !repoRe.MatchString(s) {
		return fmt.Errorf("%q is not a GitHub repository in OWNER/REPO form", s)
	}
	return nil
}

// SourceInputs are the places a release repository can come from, in the order they
// are tried. A nil Config, Prompt or Save means that place is not available.
type SourceInputs struct {
	// Env is the value of EnvRepo.
	Env string
	// Config returns the config file's release_repo, or "" when it is not set.
	Config func() (string, error)
	// ConfigHint names the config file, for the refusal message.
	ConfigHint string
	// Prompt asks the operator on an interactive terminal; nil when there is none.
	Prompt func() (string, error)
	// Save stores a prompted answer in the config file.
	Save func(repo string) error
}

// Source is the resolved release repository and where it came from.
type Source struct {
	Repo   string
	Origin string // "environment", "config" or "prompt"
	// SaveErr is set when a prompted answer could not be saved; the repository is still
	// usable for this run.
	SaveErr error
}

// ResolveRepo picks the release repository: the environment variable, then the config
// field, then a prompt whose answer is saved. A value that is set but malformed is an
// error and never falls through to the next place. With nothing set and no terminal it
// refuses, naming the exact setting to add.
func ResolveRepo(in SourceInputs) (Source, error) {
	if env := strings.TrimSpace(in.Env); env != "" {
		if err := ValidateRepo(env); err != nil {
			return Source{}, fmt.Errorf("%s: %w", EnvRepo, err)
		}
		return Source{Repo: env, Origin: "environment"}, nil
	}
	if in.Config != nil {
		cfg, err := in.Config()
		if err != nil {
			return Source{}, err
		}
		if cfg = strings.TrimSpace(cfg); cfg != "" {
			if err := ValidateRepo(cfg); err != nil {
				return Source{}, fmt.Errorf("config %q: %w", ConfigKey, err)
			}
			return Source{Repo: cfg, Origin: "config"}, nil
		}
	}
	if in.Prompt == nil {
		return Source{}, fmt.Errorf("no release source is set: add %q: \"OWNER/REPO\" to %s, or set %s=OWNER/REPO",
			ConfigKey, in.ConfigHint, EnvRepo)
	}
	answer, err := in.Prompt()
	if err != nil {
		return Source{}, err
	}
	answer = strings.TrimSpace(answer)
	if answer == "" {
		return Source{}, errors.New("no release source given")
	}
	if err := ValidateRepo(answer); err != nil {
		return Source{}, err
	}
	src := Source{Repo: answer, Origin: "prompt"}
	if in.Save != nil {
		src.SaveErr = in.Save(answer)
	}
	return src, nil
}
