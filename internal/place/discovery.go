package place

import (
	"errors"
	"os"
	"strings"

	"sopshq/internal/keysetup"
)

// This file holds the OS-INDEPENDENT core of "ensure sops discovery": the pure
// decision for each discovery artifact (what to do about SOPS_AGE_KEY_FILE and the
// junction/symlink), the report types, and the read-only status view. The actual
// side effects (setx / mklink on Windows, the ~/.bashrc export + symlink on Linux)
// live in place_windows.go / place_linux.go, which gather the on-disk facts and
// call the shared orchestration here.
//
// Splitting DECISION from EFFECT keeps the risky part (setx / real symlinks) thin
// and lets the decision be unit-tested with plain structs - no real environment,
// home directory, or filesystem link is ever touched by a test of the deciders.

// Discovery artifact states, returned per artifact in a DiscoveryReport. All ASCII.
const (
	// DiscoveryCreated: the artifact was missing or broken and EnsureDiscovery set it.
	DiscoveryCreated = "ok-created"
	// DiscoveryAlready: the artifact was already correct; left untouched.
	DiscoveryAlready = "ok-already"
	// DiscoveryConflict: the artifact points at a DIFFERENT, real target (a deliberate
	// custom setup); left untouched and flagged so the operator can decide.
	DiscoveryConflict = "conflict"
	// DiscoveryError: the artifact needed setting but the side effect failed.
	DiscoveryError = "error"
	// DiscoveryNotApplicable: discovery wiring does not apply to this keystore because
	// it is not the SopsHQ process user's own store (a cross-user shared-root keystore
	// reached through a POSIX ACL, not a home env/symlink). No effect was run and no
	// home was touched. It is neither an error nor a conflict.
	DiscoveryNotApplicable = "not-applicable"
)

// Discovery verdicts for InspectDiscovery (a one-word read-only summary). All ASCII.
const (
	// VerdictFound: sops can find this keystore's key (env or link points here).
	VerdictFound = "found"
	// VerdictNotWired: nothing points here, so apps cannot find this key.
	VerdictNotWired = "not-wired"
	// VerdictConflict: env or link points at a different, real target.
	VerdictConflict = "conflict"
	// VerdictNotApplicable: this keystore is not the SopsHQ process user's own store (a
	// cross-user shared-root keystore), so home discovery wiring does not apply. The
	// user reaches their key through the POSIX ACL grant and calls sops with explicit
	// key/secret paths. The panel shows this as an "n/a" state, never a "not wired"
	// problem.
	VerdictNotApplicable = "n/a"
)

// DiscoveryItem is the outcome for one discovery artifact. It carries only
// non-secret facts (an artifact label, a state, and a path-only detail).
type DiscoveryItem struct {
	Artifact string // "SOPS_AGE_KEY_FILE" or "symlink"/"junction"
	State    string // one of the Discovery* state constants
	Detail   string // non-secret, plain-language explanation (paths only)
}

// DiscoveryReport is what EnsureDiscovery repaired/left/flagged, safe to render.
type DiscoveryReport struct {
	Items []DiscoveryItem
}

// HasConflict reports whether any artifact was left as a conflict (points elsewhere).
func (r DiscoveryReport) HasConflict() bool {
	for _, it := range r.Items {
		if it.State == DiscoveryConflict {
			return true
		}
	}
	return false
}

// HasError reports whether any artifact failed to be set.
func (r DiscoveryReport) HasError() bool {
	for _, it := range r.Items {
		if it.State == DiscoveryError {
			return true
		}
	}
	return false
}

// DiscoveryStatus is the read-only view of how sops discovery is wired for one
// keystore, for display in the panel. Non-secret (paths only).
type DiscoveryStatus struct {
	EnvName    string // "SOPS_AGE_KEY_FILE"
	EnvValue   string // current persisted value, "" if unset
	EnvHere    bool   // the env value points at this keystore's keys.txt
	LinkKind   string // "junction" (Windows) or "symlink" (Linux)
	LinkPath   string // where the junction/symlink lives
	LinkTarget string // where it points ("" if absent or unreadable)
	LinkExists bool   // a junction/symlink is present (or the keystore is at the default path)
	LinkHere   bool   // the link points at this keystore
	Verdict    string // one of Verdict*
}

// discoveryPlan is the decision for one artifact, before any effect runs.
type discoveryPlan int

const (
	planLeave    discoveryPlan = iota // already correct; do nothing
	planSet                           // missing or broken; set/create it to our target
	planConflict                      // points at a different real target; do NOT touch
)

// envFacts is what we observed about SOPS_AGE_KEY_FILE (Windows: User-scope env;
// Linux: the ~/.bashrc marked export). It is the pure input to decideEnv.
type envFacts struct {
	current       string // current persisted value ("" = unset)
	currentExists bool   // the current value names a file that exists on disk
	want          string // the path it SHOULD point at (KeyFile(Base))
}

// linkFacts is what we observed about the junction/symlink. Pure input to decideLink.
type linkFacts struct {
	exists       bool   // a link/junction is present at path
	target       string // where it points ("" if absent or its target could not be read)
	targetExists bool   // the link resolves to an existing path (not dangling)
	want         string // the target it SHOULD point at (Base on Windows, KeyFile(Base) on Linux)
	path         string // where the link lives (for messages)
	selfSame     bool   // the keystore already sits AT the default discovery path (no link needed)
}

// decideEnv decides what to do about SOPS_AGE_KEY_FILE. Repair-only: it sets the
// value when unset or dangling, leaves it when already correct, and flags (without
// touching) a value that points at a different, existing file.
func decideEnv(f envFacts) (discoveryPlan, string) {
	switch {
	case f.current == "":
		return planSet, "SOPS_AGE_KEY_FILE was unset; pointing it at " + f.want
	case samePath(f.current, f.want):
		return planLeave, "SOPS_AGE_KEY_FILE already points at this keystore"
	case !f.currentExists:
		return planSet, "SOPS_AGE_KEY_FILE pointed at a missing file (" + f.current + "); re-pointing to " + f.want
	default:
		return planConflict, "SOPS_AGE_KEY_FILE points at a different existing file (" + f.current + "); left as is"
	}
}

// decideLink decides what to do about the junction/symlink. Repair-only: it
// creates the link when absent or dangling, leaves it when already correct, and
// flags (without touching) a link that points at a different, valid target.
func decideLink(f linkFacts) (discoveryPlan, string) {
	switch {
	case f.selfSame:
		return planLeave, "keystore is at the default sops location; no link needed"
	case !f.exists:
		return planSet, "no link at " + f.path + "; creating it -> " + f.want
	case f.target != "" && samePath(f.target, f.want):
		return planLeave, "link at " + f.path + " already points at this keystore"
	case !f.targetExists:
		return planSet, "link at " + f.path + " was dangling; re-pointing it -> " + f.want
	case f.target == "":
		// The link exists and resolves, but its target could not be read (e.g. a
		// plain folder, or an unreadable reparse point). Do not touch it and do not
		// claim a conflict we cannot prove.
		return planLeave, "link at " + f.path + " exists (target not readable); left as is"
	default:
		return planConflict, "link at " + f.path + " points elsewhere (" + f.target + "); left as is"
	}
}

// discoveryEffects are the OS-specific write actions EnsureDiscovery runs when a
// plan says "set". Each returns nil once the artifact is set.
type discoveryEffects struct {
	envName  string // "SOPS_AGE_KEY_FILE"
	linkKind string // "symlink" or "junction"
	setEnv   func(value string) error
	setLink  func() error
}

// applyEnsure is the shared orchestration: given the observed facts and the OS
// effects, it decides per artifact, runs only the needed effect, and builds the
// report. Repair-only by construction (planLeave/planConflict never call an effect).
func applyEnsure(env envFacts, link linkFacts, eff discoveryEffects) DiscoveryReport {
	var rep DiscoveryReport
	envPlan, envDetail := decideEnv(env)
	rep.Items = append(rep.Items, runPlan(eff.envName, envPlan, envDetail, func() error { return eff.setEnv(env.want) }))
	linkPlan, linkDetail := decideLink(link)
	rep.Items = append(rep.Items, runPlan(eff.linkKind, linkPlan, linkDetail, eff.setLink))
	return rep
}

// runPlan executes one artifact's plan and turns it into a report item.
func runPlan(artifact string, plan discoveryPlan, detail string, do func() error) DiscoveryItem {
	switch plan {
	case planSet:
		if err := do(); err != nil {
			return DiscoveryItem{Artifact: artifact, State: DiscoveryError, Detail: detail + " (failed: " + err.Error() + ")"}
		}
		return DiscoveryItem{Artifact: artifact, State: DiscoveryCreated, Detail: detail}
	case planConflict:
		return DiscoveryItem{Artifact: artifact, State: DiscoveryConflict, Detail: detail}
	default:
		return DiscoveryItem{Artifact: artifact, State: DiscoveryAlready, Detail: detail}
	}
}

// fillStatus turns observed facts into the read-only DiscoveryStatus (verdict + the
// displayable env/link details). It runs the same deciders as EnsureDiscovery but
// performs no effect, so "would this be repaired?" and "what will EnsureDiscovery do?"
// can never disagree.
func fillStatus(st DiscoveryStatus, env envFacts, link linkFacts) DiscoveryStatus {
	st.EnvValue = env.current
	envPlan, _ := decideEnv(env)
	st.EnvHere = envPlan == planLeave

	st.LinkPath = link.path
	st.LinkTarget = link.target
	st.LinkExists = link.exists || link.selfSame
	linkPlan, _ := decideLink(link)
	st.LinkHere = linkPlan == planLeave

	switch {
	case st.EnvHere || st.LinkHere:
		st.Verdict = VerdictFound
	case envPlan == planConflict || linkPlan == planConflict:
		st.Verdict = VerdictConflict
	default:
		st.Verdict = VerdictNotWired
	}
	return st
}

// discoveryBaseOK validates a keystore base at the EFFECT BOUNDARY, before any
// EnsureDiscovery side effect runs. This is the security backstop: a KeyBase is
// validated when an OS user is created, but a REPLICATED os_user record (stored
// verbatim by store.ApplyRemote) can carry an unvalidated value, and both the
// reuse/adopt wire path and the panel's "Fix discovery" action re-derive effects
// from it. On Windows the base reaches cmd.exe via `mklink`, so an unsafe value
// (e.g. `C:\k&calc.exe`) would be re-parsed and executed. Refusing here guarantees
// no shell/exec effect ever runs with an unsafe base, regardless of caller, without
// dropping the replicated record (which would risk cluster divergence).
//
// It reuses keysetup.ValidKeystorePath so the allow/deny set has a single source of
// truth (no shell metacharacters, control characters, leading dash, `%`, or `^`).
func discoveryBaseOK(base string) error {
	if strings.TrimSpace(base) == "" {
		return errors.New("place: empty keystore base")
	}
	if !keysetup.ValidKeystorePath(base) {
		return errors.New("place: keystore path contains unsafe characters; discovery refused")
	}
	return nil
}

// refusedReport is the report EnsureDiscovery returns when the base fails validation:
// a single error item and NO effects run.
func refusedReport(err error) DiscoveryReport {
	return DiscoveryReport{Items: []DiscoveryItem{{Artifact: "keystore", State: DiscoveryError, Detail: err.Error()}}}
}

// notApplicableStatus is the read-only discovery status for a keystore that home
// discovery wiring does not apply to: a cross-user shared-root store the target user
// reaches through a POSIX ACL. It reports N/A WITHOUT reading the target user's home.
func notApplicableStatus(envName, linkKind string) DiscoveryStatus {
	return DiscoveryStatus{EnvName: envName, LinkKind: linkKind, Verdict: VerdictNotApplicable}
}

// notApplicableReport is the EnsureDiscovery report for a cross-user shared-root store:
// a single benign item recording that home discovery wiring does not apply. No effect is
// run and no home is touched; it is not an error and not a conflict.
func notApplicableReport() DiscoveryReport {
	return DiscoveryReport{Items: []DiscoveryItem{{
		Artifact: "discovery",
		State:    DiscoveryNotApplicable,
		Detail:   "cross-user shared-root keystore; the key is reached through a POSIX ACL, so no home export or symlink is needed",
	}}}
}

// effectsDisabled, when true, turns the OS-level discovery side effects into
// no-ops: the Windows setx/mklink and the Linux ~/.bashrc export + symlink are
// skipped, while the decision logic and reports run unchanged. It is the
// defense-in-depth backstop that guarantees no test can mutate the host's
// SOPS_AGE_KEY_FILE, junction, or bashrc even if it reaches a real placement or
// discovery path. It is never set outside tests.
var effectsDisabled bool

// cleanupTB is the minimal testing.TB subset DisableEffectsForTest needs. It lets
// this hook live in the package's normal source without importing "testing".
type cleanupTB interface {
	Helper()
	Cleanup(func())
}

// DisableEffectsForTest makes the discovery side effects no-ops for the duration
// of a test, restoring the previous state on cleanup. Call it from any test (or
// test harness) that could reach place.Place or place.EnsureDiscovery, so no real
// setx/mklink/bashrc/symlink runs against the host.
func DisableEffectsForTest(t cleanupTB) {
	t.Helper()
	prev := effectsDisabled
	effectsDisabled = true
	t.Cleanup(func() { effectsDisabled = prev })
}

// fileExists reports whether p names an existing filesystem entry. Empty is false.
func fileExists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}
