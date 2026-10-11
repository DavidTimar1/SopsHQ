//go:build windows

package place

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

// restrictKeyFile makes keys.txt readable/writable by the owner only - the
// Windows analogue of chmod 600 - by disabling inheritance and granting only the
// current user (icacls).
func restrictKeyFile(path string) error {
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("current user: %w", err)
	}
	grant := fmt.Sprintf("%s:(R,W)", u.Username)
	cmd := exec.Command("icacls", path, "/inheritance:r", "/grant:r", grant)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// configureDiscovery wires sops discovery on Windows: a junction at
// %USERPROFILE%\.sops pointing at the key store (so ~/.sops/keys.txt resolves
// while the bytes live wherever Base is), and a persisted SOPS_AGE_KEY_FILE.
//
// It is conservative: it will not clobber an existing ~/.sops that points
// somewhere else (that would be a hand-made store); it reports that instead.
func configureDiscovery(o Opts) error {
	if effectsDisabled {
		return nil
	}
	if profile := os.Getenv("USERPROFILE"); profile != "" {
		link := filepath.Join(profile, ".sops")
		if err := ensureJunction(link, o.Base); err != nil {
			return err
		}
	}
	// Persist SOPS_AGE_KEY_FILE at User scope so new shells and tools find it.
	if err := exec.Command("setx", "SOPS_AGE_KEY_FILE", KeyFile(o.Base)).Run(); err != nil {
		return fmt.Errorf("place: setx SOPS_AGE_KEY_FILE: %w", err)
	}
	return nil
}

// envName is the environment variable sops reads to locate the key file.
const envName = "SOPS_AGE_KEY_FILE"

// EnsureDiscovery repairs ONLY the sops-discovery artifacts that are missing or
// broken for one keystore, and never clobbers a deliberate different setup:
//
//   - the User-scope SOPS_AGE_KEY_FILE persisted with setx, and
//   - the junction at %USERPROFILE%\.sops.
//
// It is idempotent and safe to call repeatedly, including in the reuse/adopt path
// where the operator may have kept a custom pointer (a conflict is left in place and
// reported, not overwritten). It uses only o.Base (no key material).
//
// For a placement that is not for the process user it returns a benign "not applicable"
// report WITHOUT touching a home, mirroring the Linux cross-user behavior. The base is
// validated first, so an unsafe base is refused regardless of who the target is.
func EnsureDiscovery(o Opts) DiscoveryReport {
	if err := discoveryBaseOK(o.Base); err != nil {
		return refusedReport(err)
	}
	if self, serr := isSelfPlacement(o); serr != nil || !self {
		return notApplicableReport()
	}
	env, link := gatherDiscoveryFacts(o)
	eff := discoveryEffects{
		envName:  envName,
		linkKind: "junction",
		setEnv: func(v string) error {
			if effectsDisabled {
				return nil
			}
			return exec.Command("setx", envName, v).Run()
		},
		setLink: func() error {
			if effectsDisabled {
				return nil
			}
			return setJunction(link.path, o.Base)
		},
	}
	return applyEnsure(env, link, eff)
}

// InspectDiscovery reports how sops discovery is currently wired for a keystore,
// WITHOUT changing anything. It is the read-only view behind the panel's discovery
// status line. For a placement that is not for the process user it reports "not
// applicable" WITHOUT touching a home, mirroring the Linux cross-user behavior.
func InspectDiscovery(o Opts) DiscoveryStatus {
	if self, err := isSelfPlacement(o); err != nil || !self {
		return notApplicableStatus(envName, "junction")
	}
	st := DiscoveryStatus{EnvName: envName, LinkKind: "junction"}
	env, link := gatherDiscoveryFacts(o)
	return fillStatus(st, env, link)
}

// gatherDiscoveryFacts reads the current, non-destructive state of both discovery
// artifacts for a keystore. The junction lives at %USERPROFILE%\.sops and points at
// the keystore Base (a directory); SOPS_AGE_KEY_FILE is read LIVE from the User-scope
// registry (see currentEnvKeyFile), so a value setx just wrote is reflected at once.
func gatherDiscoveryFacts(o Opts) (env envFacts, link linkFacts) {
	env = envFacts{current: currentEnvKeyFile(), want: KeyFile(o.Base)}
	env.currentExists = fileExists(env.current)

	link = linkFacts{want: o.Base}
	profile := os.Getenv("USERPROFILE")
	if profile == "" {
		return env, link
	}
	linkPath := filepath.Join(profile, ".sops")
	link.path = linkPath
	if samePath(linkPath, o.Base) {
		link.selfSame = true
		return env, link
	}
	if _, lerr := os.Lstat(linkPath); lerr == nil {
		link.exists = true
		// A junction is a name-surrogate reparse point; Readlink returns its target.
		// A plain directory returns an error, leaving target "" (then treated as
		// "exists, not readable" - left untouched, never a false conflict).
		if tgt, rerr := os.Readlink(linkPath); rerr == nil {
			link.target = tgt
		}
		if _, serr := os.Stat(linkPath); serr == nil {
			link.targetExists = true
		}
	}
	return env, link
}

// setJunction creates (or recreates a dangling) junction link -> target. It is
// called only when EnsureDiscovery's decision is "set" (absent or dangling), so a
// stale link is removed first before mklink re-creates it.
//
// This sink runs `mklink` through cmd.exe, which re-parses its arguments, so an
// unsafe target would be a command-injection vector. EnsureDiscovery already refuses
// an unsafe base at the effect boundary; this re-check is defense-in-depth so the
// shell sink can never be reached with a metacharacter-bearing target.
func setJunction(link, target string) error {
	if err := discoveryBaseOK(target); err != nil {
		return fmt.Errorf("junction: %w", err)
	}
	_ = os.Remove(link) // clear a dangling junction; a no-op when absent
	if err := exec.Command("cmd", "/c", "mklink", "/J", link, target).Run(); err != nil {
		return fmt.Errorf("junction %s -> %s: %w", link, target, err)
	}
	return nil
}

// caseInsensitiveFS reports that Windows paths compare case-insensitively.
const caseInsensitiveFS = true

// readKeyFile reads a key-store file with a size cap. On Windows there is no extra
// permission handling needed to read it back; the cap keeps a KeyBase pointed at a
// huge file from being loaded whole on the render-path scan.
func readKeyFile(path string) ([]byte, error) { return ReadCappedFile(path) }

// currentEnvKeyFile returns the SOPS_AGE_KEY_FILE value the operator currently has
// PERSISTED at User scope (the same scope `setx` writes). It reads the LIVE value
// straight from the User environment in the registry (HKCU\Environment), NOT from
// the process environment: a long-running panel keeps the env it inherited at
// launch, so after any setx - including the panel's own "Fix discovery" - os.Getenv
// would report a stale value and the status/repair decision would disagree with
// reality. Reading the registry reflects the change immediately. Empty means "not
// set". The read is non-destructive (it only queries; it never calls setx).
//
// In tests effectsDisabled is set (see main_test.go / DisableEffectsForTest), and
// this falls back to the process env - which tests populate with t.Setenv - so
// `go test` never shells out to reg.exe or touches the real registry.
func currentEnvKeyFile() string {
	if effectsDisabled {
		return strings.TrimSpace(os.Getenv(envName))
	}
	return strings.TrimSpace(userEnvFromRegistry(envName))
}

// userEnvFromRegistry returns the LIVE User-scope value of a Windows environment
// variable read from HKCU\Environment via `reg query`, or "" when it is unset (reg
// exits non-zero) or reg.exe could not be run. It uses a fixed argv - no shell - so
// name is never re-parsed by cmd.exe.
func userEnvFromRegistry(name string) string {
	out, err := exec.Command("reg", "query", `HKCU\Environment`, "/v", name).Output()
	if err != nil {
		return ""
	}
	return parseRegQueryValue(string(out), name)
}

// parseRegQueryValue extracts the string value for name from `reg query ... /v name`
// output. Each value prints on one line as three fields separated by runs of
// whitespace: the value NAME, its TYPE (REG_SZ or REG_EXPAND_SZ for a string), and
// the DATA. The data may itself contain spaces (e.g. C:\dir with space\keys.txt), so
// it is everything AFTER the type token, not merely the last field. Returns "" when
// no matching string-typed value line is present.
func parseRegQueryValue(out, name string) string {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.EqualFold(fields[0], name) {
			continue
		}
		typeTok := fields[1]
		if !strings.EqualFold(typeTok, "REG_SZ") && !strings.EqualFold(typeTok, "REG_EXPAND_SZ") {
			continue
		}
		idx := strings.Index(line, typeTok)
		return strings.TrimSpace(line[idx+len(typeTok):])
	}
	return ""
}

// ensureJunction creates a directory junction link -> target if absent. If link
// already exists it is left untouched (we never silently replace a user's store).
func ensureJunction(link, target string) error {
	if fi, err := os.Lstat(link); err == nil {
		// Already exists - leave it. InspectDiscovery reports a target that does
		// not match Base.
		_ = fi
		return nil
	}
	if err := exec.Command("cmd", "/c", "mklink", "/J", link, target).Run(); err != nil {
		return fmt.Errorf("place: junction %s -> %s: %w", link, target, err)
	}
	return nil
}
