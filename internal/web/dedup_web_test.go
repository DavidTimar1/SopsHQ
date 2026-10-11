package web

import (
	"net/url"
	"testing"

	"sopshq/internal/model"
	"sopshq/internal/store"
)

// TestCreateMachineRejectsDuplicateName confirms a second machine with the same name
// (case-insensitive) is rejected, leaving exactly one machine.
func TestCreateMachineRejectsDuplicateName(t *testing.T) {
	ts, st := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	post := func(vals url.Values) {
		t.Helper()
		csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/machines"), "csrf")
		vals.Set("csrf", csrf)
		resp, err := c.PostForm(ts.URL+"/machines", vals)
		if err != nil {
			t.Fatalf("post machine: %v", err)
		}
		resp.Body.Close()
	}

	post(url.Values{"name": {"linux-server"}, "os": {"linux"}})
	if n := len(st.Machines.List()); n != 1 {
		t.Fatalf("expected 1 machine, got %d", n)
	}
	// Same name, different case -> rejected.
	post(url.Values{"name": {"Linux-Server"}, "os": {"windows"}})
	if n := len(st.Machines.List()); n != 1 {
		t.Fatalf("duplicate machine name must be rejected; got %d", n)
	}
}

// TestCreateOSUserRejectsDuplicate confirms the same username on the same machine is
// rejected, leaving exactly one OS-user record.
func TestCreateOSUserRejectsDuplicate(t *testing.T) {
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

	post("/machines", url.Values{"name": {"local"}, "os": {"windows"}})
	machineID := extract(t, reMachineLocal, getBody(t, c, ts.URL+"/machines"), "machine id")

	post("/osusers", url.Values{"machine_id": {machineID}, "os_username": {"dev"}, "key_base": {t.TempDir()}})
	if n := len(st.OSUsers.List()); n != 1 {
		t.Fatalf("expected 1 os user, got %d", n)
	}
	// Same username on the same machine -> rejected.
	post("/osusers", url.Values{"machine_id": {machineID}, "os_username": {"dev"}, "key_base": {t.TempDir()}})
	if n := len(st.OSUsers.List()); n != 1 {
		t.Fatalf("duplicate OS user (same machine+username) must be rejected; got %d", n)
	}
}

// TestCreateOSUserWindowsCaseInsensitive: on a Windows machine "Dev" and "dev" are the
// same account (case-insensitive), so the second is rejected.
func TestCreateOSUserWindowsCaseInsensitive(t *testing.T) {
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

	post("/machines", url.Values{"name": {"win"}, "os": {"windows"}})
	machineID := extract(t, reMachineLocal, getBody(t, c, ts.URL+"/machines"), "machine id")

	post("/osusers", url.Values{"machine_id": {machineID}, "os_username": {"Dev"}, "key_base": {t.TempDir()}})
	post("/osusers", url.Values{"machine_id": {machineID}, "os_username": {"dev"}, "key_base": {t.TempDir()}})
	if n := len(st.OSUsers.List()); n != 1 {
		t.Fatalf("on Windows, Dev/dev are the same account; want 1 record, got %d", n)
	}
	// The stored casing is the operator's original ("Dev"), never folded.
	if u := st.OSUsers.List()[0]; u.Username != "Dev" {
		t.Fatalf("stored username casing must be preserved; got %q", u.Username)
	}
}

// TestCreateOSUserLinuxCaseSensitive: on a Linux machine "dev" and "Dev" are distinct
// accounts, so both are stored.
func TestCreateOSUserLinuxCaseSensitive(t *testing.T) {
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

	post("/machines", url.Values{"name": {"lin"}, "os": {"linux"}})
	machineID := extract(t, reMachineLocal, getBody(t, c, ts.URL+"/machines"), "machine id")

	post("/osusers", url.Values{"machine_id": {machineID}, "os_username": {"dev"}, "key_base": {t.TempDir()}})
	post("/osusers", url.Values{"machine_id": {machineID}, "os_username": {"Dev"}, "key_base": {t.TempDir()}})
	if n := len(st.OSUsers.List()); n != 2 {
		t.Fatalf("on Linux, dev/Dev are distinct accounts; want 2 records, got %d", n)
	}
}

// TestDeleteKeyBlockedByLiveAssignment: a shared/reused key that still backs a live
// assignment cannot be deleted (that would silently orphan the project's secrets);
// once the assignment is gone the key deletes normally.
func TestDeleteKeyBlockedByLiveAssignment(t *testing.T) {
	ts, st := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	// A key with a LIVE assignment pointing at it: the assignment's project and OS
	// user must really exist, otherwise the assignment is dangling and (correctly)
	// does not block.
	proj := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "p1"}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: "m1", Username: "u1"}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	k := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "adopted-alice", Type: model.KeyShared, Recipient: "age1shared"}
	if err := st.Keys.Put(k); err != nil {
		t.Fatalf("key: %v", err)
	}
	a := &model.Assignment{M: model.Meta{UUID: store.NewID()}, KeyID: k.M.UUID, ProjectID: proj.M.UUID, MachineID: "m1", OSUserID: osu.M.UUID}
	if err := st.Assignments.Put(a); err != nil {
		t.Fatalf("assignment: %v", err)
	}

	post := func(path string) {
		t.Helper()
		csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/machines"), "csrf")
		resp, err := c.PostForm(ts.URL+path, url.Values{"csrf": {csrf}})
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		resp.Body.Close()
	}

	// Delete is blocked while the assignment is live.
	post("/keys/" + k.M.UUID + "/delete")
	if _, err := st.Keys.Get(k.M.UUID); err != nil {
		t.Fatal("key with a live assignment must NOT be deleted")
	}

	// Remove the assignment, then the key deletes.
	if err := st.Assignments.Delete(a.M.UUID); err != nil {
		t.Fatalf("delete assignment: %v", err)
	}
	post("/keys/" + k.M.UUID + "/delete")
	if _, err := st.Keys.Get(k.M.UUID); err == nil {
		t.Fatal("unassigned key should delete normally")
	}
}

// TestDeleteProjectCascadesAndUnblocksKey reproduces the operator's report: a key
// used only by one project must become deletable after that project is removed.
// Deleting the project cascades its assignment to a tombstone, so the key no
// longer has any live assignment blocking it.
func TestDeleteProjectCascadesAndUnblocksKey(t *testing.T) {
	ts, st := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	proj := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "app"}
	if err := st.Projects.Put(proj); err != nil {
		t.Fatalf("project: %v", err)
	}
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: "m1", Username: "dev"}
	if err := st.OSUsers.Put(osu); err != nil {
		t.Fatalf("osuser: %v", err)
	}
	k := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "project-app", Type: model.KeyShared, Recipient: "age1proj"}
	if err := st.Keys.Put(k); err != nil {
		t.Fatalf("key: %v", err)
	}
	a := &model.Assignment{M: model.Meta{UUID: store.NewID()}, KeyID: k.M.UUID, ProjectID: proj.M.UUID, MachineID: "m1", OSUserID: osu.M.UUID}
	if err := st.Assignments.Put(a); err != nil {
		t.Fatalf("assignment: %v", err)
	}

	post := func(path string) {
		t.Helper()
		csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/machines"), "csrf")
		resp, err := c.PostForm(ts.URL+path, url.Values{"csrf": {csrf}})
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		resp.Body.Close()
	}

	// Remove the project: its assignment must be tombstoned by the cascade.
	post("/projects/" + proj.M.UUID + "/delete")
	if _, err := st.Assignments.Get(a.M.UUID); err == nil {
		t.Fatal("the deleted project's assignment must be tombstoned")
	}

	// With no live assignment left, the key deletes.
	post("/keys/" + k.M.UUID + "/delete")
	if _, err := st.Keys.Get(k.M.UUID); err == nil {
		t.Fatal("a key used only by a removed project must be deletable")
	}
}
