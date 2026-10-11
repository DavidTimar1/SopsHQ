package keysvc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"sopshq/internal/audit"
	"sopshq/internal/keys"
	"sopshq/internal/place"
	"sopshq/internal/stamps"
)

// ErrChangedExternally signals that a managed file changed on disk since SopsHQ
// last wrote it: somebody edited it OUTSIDE SopsHQ. A write that would clobber the
// change is refused so the operator can reconcile it first. errors.Is matches the
// typed *ExternalChange that carries the (non-secret) diff.
var ErrChangedExternally = errors.New("keysvc: managed file changed outside SopsHQ")

// Managed-file kinds a ChangeDiff can describe.
const (
	ChangeKeysTxt     = "keys.txt"
	ChangeSopsYAML    = "sops.yaml"
	ChangeSecretsYAML = "secrets.yaml"
)

// ChangeDiff is the NON-SECRET description of how an on-disk managed file differs
// from what SopsHQ last wrote. It carries names, recipients, and paths only -
// never a secret value, private key, or passphrase - so it is safe to render in
// the panel, return to the caller, and write to the audit log.
type ChangeDiff struct {
	Kind   string // one of the Change* constants
	Path   string // the managed file's path
	Target string // project or OS-user name, for display

	// ProjectID/OSUserID identify the reconcile target so the panel can drive an
	// adopt/overwrite without re-deriving it. ProjectID is set for sops.yaml and
	// secrets.yaml; OSUserID is set for keys.txt.
	ProjectID string
	OSUserID  string

	// sops.yaml: recipients (age1...) added or removed on disk versus SopsHQ's
	// desired set (public recipients only, never a private key).
	RecipientsAdded   []string
	RecipientsRemoved []string

	// secrets.yaml: secret NAMES added or removed on disk versus the recorded
	// name-set (names only, never values).
	NamesAdded   []string
	NamesRemoved []string

	// keys.txt: a short non-secret note (a key store cannot be diffed by name).
	Note string
}

// ExternalChange is the typed error a guarded write returns when the on-disk file
// changed. errors.As(err, &ec) recovers the diff; errors.Is(err,
// ErrChangedExternally) matches the sentinel.
type ExternalChange struct{ Diff ChangeDiff }

func (e *ExternalChange) Error() string {
	return ErrChangedExternally.Error() + " (" + e.Diff.Kind + " at " + e.Diff.Path + ")"
}

// Is lets errors.Is(err, ErrChangedExternally) match an *ExternalChange.
func (e *ExternalChange) Is(target error) bool { return target == ErrChangedExternally }

// SetStamps wires the machine-local external-change guard. When nil (the default,
// and in unit tests that do not exercise the guard) the guarded writers behave
// exactly like a direct write: no check, no stamp.
func (s *Service) SetStamps(st *stamps.Store) { s.stamps = st }

// guardWrite is the check half of a guarded managed write. It reads the on-disk
// content at path and, if a stamp exists whose hash differs, refuses with an
// *ExternalChange built by diffFn (which receives the current bytes and the
// recorded name-set). With no stamp (first sight) or no stamp store wired it
// returns nil so the write proceeds; the caller then writes and calls restamp.
func (s *Service) guardWrite(path, kind, target, projectID, osUserID string,
	diffFn func(current []byte, prevNames []string) ChangeDiff) error {
	if s.stamps == nil {
		return nil
	}
	current, _ := os.ReadFile(path) // a missing file hashes as empty
	changed, prevNames, hadStamp := s.stamps.Check(path, current)
	if hadStamp && changed {
		d := diffFn(current, prevNames)
		d.Kind, d.Path, d.Target, d.ProjectID, d.OSUserID = kind, path, target, projectID, osUserID
		return &ExternalChange{Diff: d}
	}
	return nil
}

// restamp records the current on-disk content of a managed file as the new stamp.
// names is the secret name-set for a secrets.yaml (nil otherwise). A nil stamp
// store, or a file that has vanished, is a no-op.
func (s *Service) restamp(path string, names []string) error {
	if s.stamps == nil {
		return nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return s.stamps.Put(path, content, names)
}

// ---- guarded managed writes ----------------------------------------------

// guardedPlace places (or re-places) an OS user's key store through the guard,
// then re-stamps the written file. placeFn is the actual placement (s.placer or
// place.WriteKeyStore).
func (s *Service) guardedPlace(opts place.Opts, osUserID, target string, placeFn func(place.Opts) error) error {
	path := place.KeyFile(opts.Base)
	if err := s.guardWrite(path, ChangeKeysTxt, target, "", osUserID,
		func(_ []byte, _ []string) ChangeDiff {
			return ChangeDiff{Note: "the key store was changed outside SopsHQ (an unexpected key is present)"}
		}); err != nil {
		return err
	}
	return s.placeAndStamp(opts, placeFn)
}

// placeAndStamp performs a key-store placement and re-stamps it, without the
// pre-write check. Used by reconcile-overwrite (the operator already chose to
// overwrite).
func (s *Service) placeAndStamp(opts place.Opts, placeFn func(place.Opts) error) error {
	if err := placeFn(opts); err != nil {
		return err
	}
	return s.restamp(place.KeyFile(opts.Base), nil)
}

// guardedSopsYAML writes a project's .sops.yaml through the guard, then re-stamps.
func (s *Service) guardedSopsYAML(dir, projectID, target string, recips []keys.Recipient) error {
	path := filepath.Join(dir, ".sops.yaml")
	if err := s.guardWrite(path, ChangeSopsYAML, target, projectID, "",
		func(current []byte, _ []string) ChangeDiff {
			added, removed := diffSets(parseAgeLine(string(current)), recipientAges(recips))
			return ChangeDiff{RecipientsAdded: added, RecipientsRemoved: removed}
		}); err != nil {
		return err
	}
	return s.writeSopsYAMLAndStamp(dir, recips)
}

// writeSopsYAMLAndStamp writes .sops.yaml and re-stamps it, without the pre-write
// check. Used by reconcile-overwrite.
func (s *Service) writeSopsYAMLAndStamp(dir string, recips []keys.Recipient) error {
	if err := keys.WriteSopsYAML(dir, recips); err != nil {
		return err
	}
	return s.restamp(filepath.Join(dir, ".sops.yaml"), nil)
}

// guardedSetSecret sets a project secret through the guard, then re-stamps the
// secrets file with its new name-set.
func (s *Service) guardedSetSecret(dir, priv, projectID, target, name, value string) error {
	if err := s.guardSecrets(dir, priv, projectID, target); err != nil {
		return err
	}
	if err := keys.SetSecret(dir, name, value, priv); err != nil {
		return err
	}
	return s.restampSecrets(dir, priv)
}

// guardedUnsetSecret removes a project secret through the guard, then re-stamps.
func (s *Service) guardedUnsetSecret(dir, priv, projectID, target, name string) error {
	if err := s.guardSecrets(dir, priv, projectID, target); err != nil {
		return err
	}
	if err := keys.UnsetSecret(dir, name, priv); err != nil {
		return err
	}
	return s.restampSecrets(dir, priv)
}

// guardedUpdateKeys re-keys a project's secret files (sops updatekeys) through the
// guard, then re-stamps secrets.yaml. It returns the file count, like the wrapped
// keys.UpdateKeysInDir.
func (s *Service) guardedUpdateKeys(dir, priv, projectID, target string) (int, error) {
	if err := s.guardSecrets(dir, priv, projectID, target); err != nil {
		return 0, err
	}
	n, err := keys.UpdateKeysInDir(dir, priv)
	if err != nil {
		return 0, err
	}
	_ = s.restampSecrets(dir, priv)
	return n, nil
}

// guardSecrets is the check half for a secrets.yaml write. The diff decrypts the
// on-disk file ON DEMAND to read its NAMES only (never values) and compares them
// to the recorded name-set.
func (s *Service) guardSecrets(dir, priv, projectID, target string) error {
	path := filepath.Join(dir, keys.SecretFileName)
	return s.guardWrite(path, ChangeSecretsYAML, target, projectID, "",
		func(_ []byte, prevNames []string) ChangeDiff {
			var d ChangeDiff
			if names, err := keys.ListSecretNames(dir, priv); err == nil {
				d.NamesAdded, d.NamesRemoved = diffSets(names, prevNames)
			}
			return d
		})
}

// restampSecrets re-stamps secrets.yaml with its current name-set (read on demand).
func (s *Service) restampSecrets(dir, priv string) error {
	path := filepath.Join(dir, keys.SecretFileName)
	names, _ := keys.ListSecretNames(dir, priv)
	return s.restamp(path, names)
}

// ---- reconcile -----------------------------------------------------------

// ReconcileAdopt accepts the on-disk version of a managed file: it re-stamps the
// current content so SopsHQ stops flagging it, and - for a key store - imports the
// manually-added private key into the vault via the REUSE path (so it is now in
// custody). Nothing on disk is overwritten. Every decision is audited by target +
// action, never a value.
func (s *Service) ReconcileAdopt(kind, projectID, osUserID, actor string) error {
	switch kind {
	case ChangeKeysTxt:
		u, err := s.store.OSUsers.Get(osUserID)
		if err != nil {
			return err
		}
		base := s.userKeyBase(u)
		if priv, rerr := place.ReadPrivateKey(base); rerr == nil {
			rec, derr := keys.RecipientFor(priv)
			if derr != nil {
				return derr
			}
			// Import via the shared adopt path (no assignment here: this reconcile
			// re-stamps a keys.txt that changed on disk, it does not attach the key to a
			// project or user placement plan). It dedups by public key, so a key already
			// in custody is not imported twice.
			if _, err := s.recordAdoptedKey(u, priv, rec, "adopted-"+u.Username, false, actor); err != nil {
				return err
			}
		}
		_ = s.restamp(place.KeyFile(base), nil)
		_ = s.audit.Record(actor, "reconcile_adopt", "keys.txt "+u.Username, audit.OK, "")
		return nil
	case ChangeSopsYAML:
		p, err := s.store.Projects.Get(projectID)
		if err != nil {
			return err
		}
		_ = s.restamp(filepath.Join(s.localProjectPath(p), ".sops.yaml"), nil)
		_ = s.audit.Record(actor, "reconcile_adopt", "sops.yaml "+p.Name, audit.OK, "")
		return nil
	case ChangeSecretsYAML:
		p, err := s.store.Projects.Get(projectID)
		if err != nil {
			return err
		}
		dir, priv, err := s.resolveEditable(projectID)
		if err != nil {
			return err
		}
		_ = s.restampSecrets(dir, priv)
		_ = s.audit.Record(actor, "reconcile_adopt", "secrets.yaml "+p.Name, audit.OK, "")
		return nil
	}
	return fmt.Errorf("keysvc: unknown reconcile kind %q", kind)
}

// ReconcileOverwrite re-asserts SopsHQ's desired state for a managed file
// (explicit, operator-chosen, audited) and re-stamps the result: re-place the OS
// user's key set for a key store, write the desired recipients for a .sops.yaml,
// or re-key (sops updatekeys, values preserved) for a secrets.yaml.
func (s *Service) ReconcileOverwrite(kind, projectID, osUserID, actor string) error {
	switch kind {
	case ChangeKeysTxt:
		u, err := s.store.OSUsers.Get(osUserID)
		if err != nil {
			return err
		}
		priv, pub, names, err := s.userKeyMaterial(s.localMachineID, u.M.UUID)
		if err != nil {
			return err
		}
		if len(names) == 0 {
			_ = s.restamp(place.KeyFile(s.userKeyBase(u)), nil)
			return nil
		}
		if err := s.placeAndStamp(s.localPlaceOpts(u, pub, priv), s.placer); err != nil {
			return err
		}
		_ = s.audit.Record(actor, "reconcile_overwrite", "keys.txt "+u.Username, audit.OK, "")
		return nil
	case ChangeSopsYAML:
		p, err := s.store.Projects.Get(projectID)
		if err != nil {
			return err
		}
		recips, _ := s.projectRecipients(p)
		if err := s.writeSopsYAMLAndStamp(s.localProjectPath(p), recips); err != nil {
			return err
		}
		_ = s.audit.Record(actor, "reconcile_overwrite", "sops.yaml "+p.Name, audit.OK, "")
		return nil
	case ChangeSecretsYAML:
		p, err := s.store.Projects.Get(projectID)
		if err != nil {
			return err
		}
		dir, priv, err := s.resolveEditable(projectID)
		if err != nil {
			return err
		}
		if _, err := keys.UpdateKeysInDir(dir, priv); err != nil {
			return err
		}
		_ = s.restampSecrets(dir, priv)
		_ = s.audit.Record(actor, "reconcile_overwrite", "secrets.yaml "+p.Name, audit.OK, "")
		return nil
	}
	return fmt.Errorf("keysvc: unknown reconcile kind %q", kind)
}

// ---- helpers --------------------------------------------------------------

// recipientAges returns the age public recipients of a recipient list.
func recipientAges(rs []keys.Recipient) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Age)
	}
	return out
}

// diffSets returns the elements present in have but not base (added) and those
// present in base but not have (removed), each sorted. It is used for both the
// recipient diff (.sops.yaml) and the name diff (secrets.yaml).
func diffSets(have, base []string) (added, removed []string) {
	h := make(map[string]bool, len(have))
	for _, x := range have {
		h[x] = true
	}
	b := make(map[string]bool, len(base))
	for _, x := range base {
		b[x] = true
	}
	for x := range h {
		if !b[x] {
			added = append(added, x)
		}
	}
	for x := range b {
		if !h[x] {
			removed = append(removed, x)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}
