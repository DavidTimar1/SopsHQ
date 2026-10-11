// Package keysvc is the application service that ties the key engine to the
// store and vault: it generates and rotates age keypairs (sealing the private
// key), and "applies" the desired state to the LOCAL machine - placing private
// keys into users' key stores and writing each project's .sops.yaml recipients,
// then re-keying existing secret files.
//
// Remote machines are reached through replication and the agent; this package only
// touches the machine it runs on, identified by localMachineID.
//
// SECURITY: private keys are unsealed from the vault only at the moment they are
// needed (placement, or as the current key for `sops updatekeys`) and are never
// logged. The audit log records key names/UUIDs only.
package keysvc

import (
	"errors"
	"fmt"
	"time"

	"sopshq/internal/audit"
	"sopshq/internal/keys"
	"sopshq/internal/model"
	"sopshq/internal/place"
	"sopshq/internal/stamps"
	"sopshq/internal/store"
	"sopshq/internal/usage"
	"sopshq/internal/vault"
)

// Service holds the dependencies for key operations.
type Service struct {
	store          *store.Store
	vault          *vault.Vault
	audit          *audit.Log
	localMachineID string

	// keybaseRoot is this machine's OPTIONAL shared keybase root (config keybase_root):
	// an absolute directory, owned by the SopsHQ account, under which a root-derived OS
	// user's key store lives at "<keybaseRoot>/<username>/keys.txt". It is machine-local
	// and never replicated. Empty (the default) keeps keys under each user's home. Only
	// LOCAL-machine OS users with an empty KeyBase derive from it (see userKeyBase).
	keybaseRoot string

	// placer performs on-disk placement. Defaults to place.Place (full discovery
	// wiring). Tests override it to avoid touching the real environment.
	placer func(place.Opts) error
	// discoverer repairs sops-discovery artifacts (SOPS_AGE_KEY_FILE + the
	// junction/symlink) for one keystore. Defaults to place.EnsureDiscovery, whose
	// real effects (setx/mklink on Windows, ~/.bashrc export + symlink on Linux) touch
	// the host. It is a separate seam from placer because the reuse/adopt wiring path
	// runs discovery WITHOUT the placer; tests override it to stay hermetic.
	discoverer func(place.Opts) place.DiscoveryReport
	// generate produces a keypair. Defaults to keys.Generate; overridable in tests.
	generate func() (keys.Keypair, error)
	// transferKey is the shared secret used to authenticate to peer agents over
	// HTTP. Empty until set; while empty the service does not dial peers.
	transferKey string
	// dialer resolves a Machine to a remote agent client; nil uses the default
	// (built from the transfer key + the Machine's address).
	dialer func(*model.Machine) (remote, bool)
	// usage is the best-effort key-usage log (nil disables usage tracking).
	usage *usage.Log
	// stamps is the machine-local external-change guard (SHA-384 content stamps per
	// managed file). nil disables the guard, so a write is a plain write with no
	// check and no stamp - the behavior unit tests that do not wire it rely on.
	stamps *stamps.Store
}

// New builds a Service. localMachineID is the UUID of the Machine record that
// represents this node (empty means "no local machine designated yet").
func New(st *store.Store, v *vault.Vault, a *audit.Log, localMachineID string) *Service {
	return &Service{
		store:          st,
		vault:          v,
		audit:          a,
		localMachineID: localMachineID,
		placer:         place.Place,
		discoverer:     place.EnsureDiscovery,
		generate:       keys.Generate,
	}
}

// SetPlacer overrides the placement function (used in tests).
func (s *Service) SetPlacer(f func(place.Opts) error) { s.placer = f }

// SetDiscoverer overrides the sops-discovery repair function (used in tests to
// avoid setx/mklink/bashrc effects on the host).
func (s *Service) SetDiscoverer(f func(place.Opts) place.DiscoveryReport) { s.discoverer = f }

// SetLocalMachine updates which Machine record represents this node.
func (s *Service) SetLocalMachine(id string) { s.localMachineID = id }

// SetKeybaseRoot sets this machine's shared keybase root (config keybase_root). Empty
// disables root-derived key stores (the default per-home behavior).
func (s *Service) SetKeybaseRoot(root string) { s.keybaseRoot = root }

// KeybaseRoot returns this machine's configured shared keybase root, or "" when none
// is set. The web layer reads it to decide whether a blank keystore path means a
// root-derived OS user.
func (s *Service) KeybaseRoot() string { return s.keybaseRoot }

// LocalMachine returns the designated local machine id (empty if none).
func (s *Service) LocalMachine() string { return s.localMachineID }

// SetGenerator overrides keypair generation (used in tests).
func (s *Service) SetGenerator(f func() (keys.Keypair, error)) { s.generate = f }

// Generate creates the age keypair for a key that does not have one yet, sealing
// the private key into the store. It is a no-op error if the key is already
// generated (use Rotate to replace it).
func (s *Service) Generate(keyID, actor string) error {
	k, err := s.store.Keys.Get(keyID)
	if err != nil {
		return err
	}
	if k.Recipient != "" {
		return errors.New("keysvc: key already generated (use Rotate)")
	}
	return s.setNewKeypair(k, 1, actor, "key_generate")
}

// EnsureGenerated makes sure a key has an age keypair, generating one when it does
// not yet have a public key. It is the "generate on first use" entry point: assign a
// key to a project or add it to a shared set, and its keypair is minted the moment it
// is first needed, so a defined-but-ungenerated key never blocks that action. It is
// idempotent - an already-generated key is left exactly as it is (no new keypair, no
// data loss) - and the generation it does perform is audited by key name via Generate.
func (s *Service) EnsureGenerated(keyID, actor string) error {
	k, err := s.store.Keys.Get(keyID)
	if err != nil {
		return err
	}
	if k.Recipient != "" {
		return nil
	}
	return s.Generate(keyID, actor)
}

// setNewKeypair generates, seals, and persists a keypair onto a key record.
func (s *Service) setNewKeypair(k *model.Key, gen int, actor, action string) error {
	kp, err := s.generate()
	if err != nil {
		return err
	}
	sealed, err := s.vault.Seal([]byte(kp.Private))
	if err != nil {
		return fmt.Errorf("keysvc: seal: %w", err)
	}
	k.Recipient = kp.Recipient
	k.PrivSealed = sealed
	k.Generation = gen
	k.Status = model.KeyActive
	k.EditedAt = time.Now().Unix()
	if k.CreatedAt == 0 {
		k.CreatedAt = k.EditedAt
	}
	if err := s.store.Keys.Put(k); err != nil {
		return err
	}
	_ = s.audit.Record(actor, action, k.Name, audit.OK, fmt.Sprintf("generation %d", gen))
	return nil
}

// unsealPriv returns a key's private material in the clear (for placement or as
// the current key for updatekeys). Never logged.
func (s *Service) unsealPriv(k *model.Key) (string, error) {
	if k.PrivSealed == "" {
		return "", fmt.Errorf("keysvc: key %q has no private material (generate it first)", k.Name)
	}
	b, err := s.vault.Open(k.PrivSealed)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
