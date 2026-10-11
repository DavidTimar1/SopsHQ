package keysvc

import (
	"fmt"
	"sort"

	"sopshq/internal/audit"
	"sopshq/internal/keys"
)

// Mass update: change a secret's name and/or value once and propagate it to every
// place that holds the EXACT same (name, value) - across project secrets.yaml files
// AND global sets on this machine. Identity is name+value (a same-named secret with
// a different value, or a same-valued secret under a different name, is left alone).
// Values are decrypted only to MATCH and to write the new value; they are never
// logged or returned.

// SecretOccurrence is one place a (name, value) secret currently lives.
type SecretOccurrence struct {
	Kind  string // "project" | "global"
	ID    string // project UUID or global-set UUID
	Label string // project name or set name (for display)
	Name  string // the secret name at this place (the matched name)
}

// MassUpdateResult is the per-place outcome of a mass update.
type MassUpdateResult struct {
	Kind  string
	Label string
	OK    bool
	Err   string
}

// projectSecrets returns a locally-readable project's decrypted name->value map, or
// nil if it cannot be read here.
func (s *Service) projectSecrets(projectID string) map[string]string {
	dir, priv, err := s.resolveEditable(projectID)
	if err != nil {
		return nil
	}
	m, err := keys.ReadSecrets(dir, priv)
	if err != nil {
		return nil
	}
	return m
}

// globalSetSecrets returns a set's decrypted name->value map, or nil if unreadable.
func (s *Service) globalSetSecrets(setID string) map[string]string {
	r, err := s.resolveSet(setID)
	if err != nil {
		return nil
	}
	m, err := keys.ReadSecrets(r.primaryDir, r.priv)
	if err != nil {
		return nil
	}
	return m
}

// FindSecretOccurrences returns every locally-readable place (project or global set)
// whose secret named `name` currently holds exactly `value`. Decrypts on demand; the
// value is used only to match and is discarded. This is a mass-decrypt surface
// (admin-only at the handler).
func (s *Service) FindSecretOccurrences(name, value string) []SecretOccurrence {
	var out []SecretOccurrence
	for _, p := range s.store.Projects.List() {
		if v, ok := s.projectSecrets(p.M.UUID)[name]; ok && v == value {
			out = append(out, SecretOccurrence{Kind: "project", ID: p.M.UUID, Label: p.Name, Name: name})
		}
	}
	for _, set := range s.GlobalSets() {
		if v, ok := s.globalSetSecrets(set.M.UUID)[name]; ok && v == value {
			out = append(out, SecretOccurrence{Kind: "global", ID: set.M.UUID, Label: set.Name, Name: name})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Label < out[j].Label
	})
	return out
}

// MassUpdateSecret applies a rename/revalue to each occurrence: it sets
// newName=newValue, and (when renaming) removes oldName. Each place is independent -
// one failing does not roll back the others; the per-place result says what
// happened. Audited by name + count; values never logged.
func (s *Service) MassUpdateSecret(occ []SecretOccurrence, oldName, newName, newValue, actor string) []MassUpdateResult {
	rename := newName != oldName
	var results []MassUpdateResult
	ok := 0
	for _, o := range occ {
		r := MassUpdateResult{Kind: o.Kind, Label: o.Label, OK: true}
		var setErr, delErr error
		switch o.Kind {
		case "project":
			setErr = s.SetSecret(o.ID, newName, newValue, actor)
			if setErr == nil && rename {
				delErr = s.DeleteSecret(o.ID, oldName, actor)
			}
		case "global":
			setErr = s.SetGlobalSecret(o.ID, newName, newValue, actor)
			if setErr == nil && rename {
				delErr = s.DeleteGlobalSecret(o.ID, oldName, actor)
			}
		default:
			setErr = fmt.Errorf("unknown occurrence kind %q", o.Kind)
		}
		if setErr != nil {
			r.OK = false
			r.Err = "update failed"
		} else if delErr != nil {
			r.OK = false
			r.Err = "new value set but old name not removed"
		}
		if r.OK {
			ok++
		}
		results = append(results, r)
	}
	_ = s.audit.Record(actor, "secret_mass_update", oldName+" -> "+newName,
		audit.OK, fmt.Sprintf("%d/%d place(s) updated", ok, len(occ)))
	return results
}
