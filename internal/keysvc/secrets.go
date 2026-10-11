package keysvc

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"

	"sopshq/internal/audit"
	"sopshq/internal/keys"
	"sopshq/internal/model"
)

// Errors surfaced to the panel when a precondition for the secrets editor is not
// met. They are friendly, action-oriented messages (the handler shows them as-is).
var (
	// ErrProjectNoLocalPath means the project has no folder on this machine, so
	// there is nowhere to write the encrypted secrets file.
	ErrProjectNoLocalPath = errors.New("keysvc: set this project's folder path on the local machine first")
	// ErrProjectNotWired means the project has no generated key assigned on the
	// local machine yet, so there is no key to encrypt/decrypt with. The onboarding
	// glue (EnsureProjectWired) fixes this.
	ErrProjectNotWired = errors.New("keysvc: this project has no key wired on the local machine yet")
	// ErrNoLocalOSUser means there is no OS user recorded on the local machine, so
	// wiring has no account whose keystore can hold the project's private key. The
	// OS user is a deliberate security choice and is never auto-created; the operator
	// must add one first (OS users -> Add).
	ErrNoLocalOSUser = errors.New("keysvc: create an OS user on this machine first (OS users -> Add), then wire the project")
)

// resolveEditable returns the project's LOCAL folder and a private key able to
// decrypt/encrypt its secrets (unsealed from the vault). It does NOT require the
// key to be placed on disk; the private material comes straight from the vault,
// matching the encrypt-and-forget custody model.
func (s *Service) resolveEditable(projectID string) (dir, priv string, err error) {
	if s.localMachineID == "" {
		return "", "", ErrNoLocalMachine
	}
	p, err := s.store.Projects.Get(projectID)
	if err != nil {
		return "", "", err
	}
	dir = s.localProjectPath(p)
	if dir == "" {
		return "", "", ErrProjectNoLocalPath
	}
	priv = s.projectPriv(p)
	if priv == "" {
		return "", "", ErrProjectNotWired
	}
	return dir, priv, nil
}

// projectPriv returns the private material of the first generated key assigned to
// the project (any machine, since the encrypted file is shared), unsealed from
// the vault. Empty if no generated key is assigned. Never logged.
func (s *Service) projectPriv(p *model.Project) string {
	for _, a := range s.store.Assignments.List() {
		if a.ProjectID != p.M.UUID {
			continue
		}
		k, err := s.store.Keys.Get(a.KeyID)
		if err != nil || k.Recipient == "" {
			continue
		}
		if priv, err := s.unsealPriv(k); err == nil {
			return priv
		}
	}
	return ""
}

// ProjectWiredLocally reports whether the project can be edited on this machine
// right now: a local path is set AND a generated key is assigned. The panel uses
// this to decide whether to show the editor or the "wire this project" prompt.
func (s *Service) ProjectWiredLocally(projectID string) bool {
	_, _, err := s.resolveEditable(projectID)
	return err == nil
}

// ProjectAppliedLocally reports whether the project is not just wired (a generated
// key is assigned with a local path) but ALSO has its .sops.yaml written into the
// local folder - the point at which secrets can actually be encrypted. The panel
// shows the editor only when this is true, and an "Apply" prompt when the project
// is wired in the store but its .sops.yaml has not been written yet.
func (s *Service) ProjectAppliedLocally(projectID string) bool {
	dir, _, err := s.resolveEditable(projectID)
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(dir, ".sops.yaml"))
	return err == nil
}

// ListSecrets returns the secret NAMES in the project's local secrets file,
// sorted. Values are never read out. An empty result with no error means the
// project has no secrets yet.
func (s *Service) ListSecrets(projectID string) ([]string, error) {
	dir, priv, err := s.resolveEditable(projectID)
	if err != nil {
		return nil, err
	}
	return keys.ListSecretNames(dir, priv)
}

// GetSecretValue decrypts and returns ONE secret value, for prefilling the edit
// form. The value crosses in the HTTP response body to the already-authenticated
// admin; the panel is served over plain HTTP by default on loopback, so front it
// with a TLS terminator before binding it off-loopback. It is never logged or
// audited.
func (s *Service) GetSecretValue(projectID, name string) (string, error) {
	dir, priv, err := s.resolveEditable(projectID)
	if err != nil {
		return "", err
	}
	return keys.GetSecretValue(dir, name, priv)
}

// RevealSecret decrypts one secret value for display in the panel and records a
// secret_reveal audit event by NAME. Unlike GetSecretValue (used silently to
// prefill the edit form), this is the operator-initiated "Show" action, so it is
// audited. The value crosses in the HTTP response body to the authenticated
// session; the panel is served over plain HTTP by default on loopback, so front
// it with a TLS terminator before binding it off-loopback. It is never logged or
// written to the audit detail.
func (s *Service) RevealSecret(projectID, name, actor string) (string, error) {
	dir, priv, err := s.resolveEditable(projectID)
	if err != nil {
		return "", err
	}
	p, _ := s.store.Projects.Get(projectID)
	v, err := keys.GetSecretValue(dir, name, priv)
	if err != nil {
		_ = s.audit.Record(actor, "secret_reveal", auditTarget(p, name), audit.Failed, "")
		return "", err
	}
	_ = s.audit.Record(actor, "secret_reveal", auditTarget(p, name), audit.OK, "")
	return v, nil
}

// SetSecret sets name=value in the project's secrets file (creating the file on
// first use) and re-encrypts it. The VALUE is never logged or audited; the audit
// row records the NAME only. actor is the panel username for the audit trail.
func (s *Service) SetSecret(projectID, name, value, actor string) error {
	dir, priv, err := s.resolveEditable(projectID)
	if err != nil {
		return err
	}
	p, _ := s.store.Projects.Get(projectID)
	if err := s.guardedSetSecret(dir, priv, projectID, projectName(p), name, value); err != nil {
		// An external-change refusal is not a failure to record (nothing was written
		// and the value never reached sops); the panel turns it into a reconcile
		// prompt. Any other error is a real set failure. keys.SetSecret never
		// includes the value in its error.
		if !errors.Is(err, ErrChangedExternally) {
			_ = s.audit.Record(actor, "secret_set", auditTarget(p, name), audit.Failed, "")
		}
		return err
	}
	_ = s.audit.Record(actor, "secret_set", auditTarget(p, name), audit.OK, "")
	return nil
}

// DeleteSecret removes name from the project's secrets file and re-encrypts it.
// Audited by name only.
func (s *Service) DeleteSecret(projectID, name, actor string) error {
	dir, priv, err := s.resolveEditable(projectID)
	if err != nil {
		return err
	}
	p, _ := s.store.Projects.Get(projectID)
	if err := s.guardedUnsetSecret(dir, priv, projectID, projectName(p), name); err != nil {
		if !errors.Is(err, ErrChangedExternally) {
			_ = s.audit.Record(actor, "secret_delete", auditTarget(p, name), audit.Failed, "")
		}
		return err
	}
	_ = s.audit.Record(actor, "secret_delete", auditTarget(p, name), audit.OK, "")
	return nil
}

// projectName returns a project's display name, tolerating a nil record (used for
// the reconcile diff target, never a value).
func projectName(p *model.Project) string {
	if p == nil {
		return ""
	}
	return p.Name
}

// auditTarget formats the audit "target" for a secret action as
// "<project> / <name>" - the NAME only, never the value.
func auditTarget(p *model.Project, name string) string {
	if p == nil {
		return name
	}
	return p.Name + " / " + name
}

// localOSUserID returns the UUID of an OS user on the local machine. An OS user is
// a deliberate security choice (its keystore holds private keys), so SopsHQ never
// creates one as a side effect of wiring: if none is recorded, it returns
// ErrNoLocalOSUser and the operator is told to add one first.
func (s *Service) localOSUserID() (string, error) {
	for _, u := range s.store.OSUsers.List() {
		if u.MachineID == s.localMachineID {
			return u.M.UUID, nil
		}
	}
	return "", ErrNoLocalOSUser
}

// currentOSUser returns the OS account and home directory the process runs as,
// with safe fallbacks so wiring still proceeds if the lookup fails.
func currentOSUser() (username, home string) {
	if u, err := user.Current(); err == nil {
		username = u.Username
		home = u.HomeDir
	}
	if username == "" {
		username = "sopshq"
	}
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return username, home
}

// defaultKeyBase returns the default key-store base for a home directory: a
// .sops folder under home, matching the placement contract on both OSes.
func defaultKeyBase(home string) string {
	if home == "" {
		// Last resort: a relative .sops; placement will create it under the CWD.
		return ".sops"
	}
	return filepath.Join(home, ".sops")
}
