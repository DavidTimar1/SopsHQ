package web

import (
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sopshq/internal/audit"
	"sopshq/internal/config"
	"sopshq/internal/keysvc"
	"sopshq/internal/model"
	"sopshq/internal/place"
	"sopshq/internal/store"
	"sopshq/internal/vault"
)

// TestLocalFollowMergePersistsConfig is the web half of the reinstall local-follow: when
// this node's own machine record is merged away (a reinstall confirmed elsewhere and
// replicated in), the reconcile pass driven by the panel rewrites cfg.LocalMachineID to
// the adopted identity AND persists it to the config file on disk, so the change
// survives a restart.
func TestLocalFollowMergePersistsConfig(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY_FILE", "")
	dir := t.TempDir()
	v, err := vault.Init(filepath.Join(dir, "vault"), "test-pass")
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	st, err := store.Open(filepath.Join(dir, "data"), "test-node", nil)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	a := audit.Open(filepath.Join(dir, "audit.jsonl"), "test-node", nil)
	cfgPath := filepath.Join(dir, "config.jsonc")
	cfg := config.Default(cfgPath, dir, "test-node")
	if err := cfg.Save(); err != nil {
		t.Fatalf("cfg save: %v", err)
	}
	ks := keysvc.New(st, v, a, "")
	ks.SetPlacer(place.WriteKeyStore)
	place.DisableEffectsForTest(t)
	srv, err := NewServer(st, v, a, ks, cfg, "test", time.Hour)
	if err != nil {
		t.Fatalf("server: %v", err)
	}

	// This node is linked to machine "old"; a surviving identity "new" also exists.
	if err := st.Machines.Put(&model.Machine{M: model.Meta{UUID: "old"}, Name: "host", OS: model.OSLinux, Canonical: true}); err != nil {
		t.Fatalf("old: %v", err)
	}
	if err := st.Machines.Put(&model.Machine{M: model.Meta{UUID: "new"}, Name: "host-new", OS: model.OSLinux, Canonical: true, Confirmed: true}); err != nil {
		t.Fatalf("new: %v", err)
	}
	cfg.LocalMachineID = "old"
	ks.SetLocalMachine("old")
	srv.reconcileCluster() // seed the acknowledged-peers set

	// A reinstall decision made elsewhere merges this node's own record into "new".
	old, _ := st.Machines.GetRaw("old")
	old.MergedInto = "new"
	if err := st.Machines.Put(old); err != nil {
		t.Fatalf("merge old: %v", err)
	}
	if err := st.Machines.Delete("old"); err != nil {
		t.Fatalf("tombstone old: %v", err)
	}

	srv.reconcileCluster()

	if cfg.LocalMachineID != "new" {
		t.Fatalf("in-memory local machine id must follow the merge to new, got %q", cfg.LocalMachineID)
	}
	if ks.LocalMachine() != "new" {
		t.Fatalf("key service local machine must follow the merge, got %q", ks.LocalMachine())
	}
	// Persisted to disk: a reload sees the new id.
	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if reloaded.LocalMachineID != "new" {
		t.Fatalf("local machine id must be persisted to config; reloaded %q", reloaded.LocalMachineID)
	}
}

// TestPeerPendingConfirmFlow drives the panel end to end: a third machine added while
// a confirmed peer already exists is held Pending and shown with the new-vs-reinstall
// prompt; confirming "new" clears it into a distinct machine.
func TestPeerPendingConfirmFlow(t *testing.T) {
	ts, st := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	post := func(path string, vals url.Values) {
		t.Helper()
		csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/machines"), "csrf")
		vals.Set("csrf", csrf)
		resp, err := c.PostForm(ts.URL+path, vals)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		resp.Body.Close()
	}
	idByName := func(name string) string {
		for _, mc := range st.Machines.List() {
			if mc.Name == name {
				return mc.M.UUID
			}
		}
		return ""
	}

	// Designate this node's machine (marks it canonical on reconcile).
	post("/machines", url.Values{"name": {"nodeA"}, "os": {"linux"}})
	post("/machines/"+idByName("nodeA")+"/local", url.Values{})

	// First peer: accepted, no prompt.
	post("/machines", url.Values{"name": {"nodeB"}, "os": {"linux"}})
	if idByName("nodeB") != "" {
		if mc, _ := st.Machines.GetRaw(idByName("nodeB")); mc.Pending {
			t.Fatal("the first peer must not be pending")
		}
	}

	// Third machine: held Pending for the operator's new-vs-reinstall decision.
	post("/machines", url.Values{"name": {"nodeC"}, "os": {"linux"}})
	cID := idByName("nodeC")
	if mc, _ := st.Machines.GetRaw(cID); !mc.Pending {
		t.Fatal("a new third peer must be pending confirmation")
	}
	// The Machines page renders the confirmation prompt.
	if body := getBody(t, c, ts.URL+"/machines"); !strings.Contains(body, "awaiting confirmation") {
		t.Fatal("the pending peer's confirmation prompt must render on the Machines page")
	}

	// Confirm it as a new, distinct machine.
	post("/machines/"+cID+"/confirm-new", url.Values{})
	mc, err := st.Machines.Get(cID)
	if err != nil {
		t.Fatalf("confirmed-new peer must stay live: %v", err)
	}
	if mc.Pending {
		t.Fatal("confirming new must clear the pending flag")
	}
	if n := len(st.Machines.List()); n != 3 {
		t.Fatalf("want 3 distinct machines after confirming new, got %d", n)
	}
}

// TestPeerReinstallConfirmWeb drives the reinstall path over HTTP: a pending peer is
// merged into an existing one and disappears as a separate record.
func TestPeerReinstallConfirmWeb(t *testing.T) {
	ts, st := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	post := func(path string, vals url.Values) {
		t.Helper()
		csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/machines"), "csrf")
		vals.Set("csrf", csrf)
		resp, err := c.PostForm(ts.URL+path, vals)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		resp.Body.Close()
	}
	idByName := func(name string) string {
		for _, mc := range st.Machines.List() {
			if mc.Name == name {
				return mc.M.UUID
			}
		}
		return ""
	}

	post("/machines", url.Values{"name": {"nodeA"}, "os": {"linux"}})
	post("/machines/"+idByName("nodeA")+"/local", url.Values{})
	post("/machines", url.Values{"name": {"workstation"}, "os": {"windows"}})
	existing := idByName("workstation")
	post("/machines", url.Values{"name": {"workstation-rebuilt"}, "os": {"windows"}})
	pending := idByName("workstation-rebuilt")
	if mc, _ := st.Machines.GetRaw(pending); !mc.Pending {
		t.Fatal("the rebuilt machine must be pending")
	}

	post("/machines/"+pending+"/confirm-reinstall", url.Values{"target": {existing}})

	if mc, _ := st.Machines.GetRaw(pending); !mc.M.Deleted || mc.MergedInto != existing {
		t.Fatalf("reinstall must merge the pending record into the existing one; got %+v", mc)
	}
	if _, err := st.Machines.Get(existing); err != nil {
		t.Fatalf("the existing machine must survive: %v", err)
	}
	if n := len(st.Machines.List()); n != 2 {
		t.Fatalf("after reinstall merge want 2 machines (nodeA, workstation), got %d", n)
	}
}
