package keysvc

import (
	"testing"

	"sopshq/internal/model"
	"sopshq/internal/place"
	"sopshq/internal/store"
)

// TestEnsureDiscoveryForOSUserRefusesUnsafeBase proves the panel "Fix discovery"
// path cannot be used to inject a shell command through a malicious KeyBase (e.g.
// one that arrived on a replicated os_user record). place.EnsureDiscovery validates
// the base at the effect boundary and returns an error item before any setx/mklink
// runs, so the outcome is a HasError report and NO side effect. Isolation-safe: the
// reject path executes nothing against the real environment or home.
func TestEnsureDiscoveryForOSUserRefusesUnsafeBase(t *testing.T) {
	svc, st, localID := build(t)

	for _, bad := range []string{`C:\k&calc.exe`, `C:\x&powershell -c bad`, `C:\k%USERPROFILE%\x`, `C:\k^x`} {
		u := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: localID, Username: "dev", KeyBase: bad}
		if err := st.OSUsers.Put(u); err != nil {
			t.Fatalf("osuser: %v", err)
		}
		rep, err := svc.EnsureDiscoveryForOSUser(u.M.UUID, "tester")
		if err != nil {
			t.Fatalf("EnsureDiscoveryForOSUser returned a hard error for %q: %v", bad, err)
		}
		if !rep.HasError() {
			t.Errorf("EnsureDiscoveryForOSUser(%q) did not refuse: %+v", bad, rep.Items)
		}
		for _, it := range rep.Items {
			if it.State == place.DiscoveryCreated {
				t.Errorf("EnsureDiscoveryForOSUser(%q) created an artifact from an unsafe base: %+v", bad, it)
			}
		}
	}
}
