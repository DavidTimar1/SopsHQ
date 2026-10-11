package keysvc

import (
	"path/filepath"
	"testing"

	"sopshq/internal/model"
	"sopshq/internal/store"
)

// TestUserKeyBaseResolver covers the three cases of the key-store base resolver:
// an explicit KeyBase always wins, a blank KeyBase derives "<root>/<username>" when a
// shared keybase root is configured for a LOCAL user, and it is "" when neither
// applies.
func TestUserKeyBaseResolver(t *testing.T) {
	svc, _, localID := build(t)

	explicit := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: "/home/dev/.sops"}
	rootDerived := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "mailsvc", KeyBase: ""}

	// No root configured: explicit wins, blank resolves to "".
	if got := svc.userKeyBase(explicit); got != "/home/dev/.sops" {
		t.Fatalf("explicit KeyBase should win; got %q", got)
	}
	if got := svc.userKeyBase(rootDerived); got != "" {
		t.Fatalf("blank KeyBase with no root should resolve to \"\"; got %q", got)
	}

	// Root configured: explicit still wins, blank derives "<root>/<username>".
	svc.SetKeybaseRoot("/srv/sopshq-keys")
	if got := svc.userKeyBase(explicit); got != "/home/dev/.sops" {
		t.Fatalf("explicit KeyBase must still win over the root; got %q", got)
	}
	want := filepath.Join("/srv/sopshq-keys", "mailsvc")
	if got := svc.userKeyBase(rootDerived); got != want {
		t.Fatalf("root-derived base should be %q; got %q", want, got)
	}

	// A nil user is safe.
	if got := svc.userKeyBase(nil); got != "" {
		t.Fatalf("nil user should resolve to \"\"; got %q", got)
	}
}

// TestUserKeyBaseReplicationSafety proves a root-derived OS user (empty KeyBase) is
// resolved against the LOCAL machine's keybase root only: on the machine the account
// belongs to it uses that machine's root, and a peer's account is never resolved
// against the local root (it returns "", so the peer manages its own store). The stored
// KeyBase stays empty on every machine, so nothing machine-local replicates.
func TestUserKeyBaseReplicationSafety(t *testing.T) {
	svcA, _, machineA := build(t)
	svcB, _, machineB := build(t)
	svcA.SetKeybaseRoot("/srv/sopshq-keys/A")
	svcB.SetKeybaseRoot("/srv/sopshq-keys/B")

	// The SAME account record exists on each machine (one record per machine), both
	// root-derived (empty KeyBase). Replication copies both records into both stores.
	userOnA := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: machineA, Username: "dev", KeyBase: ""}
	userOnB := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: machineB, Username: "dev", KeyBase: ""}

	// On machine B, B's own user derives under B's root; A's user is foreign -> "".
	if got := svcB.userKeyBase(userOnB); got != filepath.Join("/srv/sopshq-keys/B", "dev") {
		t.Fatalf("on B, B's user should derive under B's root; got %q", got)
	}
	if got := svcB.userKeyBase(userOnA); got != "" {
		t.Fatalf("on B, A's user must NOT derive under B's root; got %q", got)
	}

	// Symmetrically on machine A.
	if got := svcA.userKeyBase(userOnA); got != filepath.Join("/srv/sopshq-keys/A", "dev") {
		t.Fatalf("on A, A's user should derive under A's root; got %q", got)
	}
	if got := svcA.userKeyBase(userOnB); got != "" {
		t.Fatalf("on A, B's user must NOT derive under A's root; got %q", got)
	}

	// The KeyBase field never gained a value from resolution (it travels empty).
	if userOnA.KeyBase != "" || userOnB.KeyBase != "" {
		t.Fatalf("resolution must not mutate the stored KeyBase; A=%q B=%q", userOnA.KeyBase, userOnB.KeyBase)
	}
}
