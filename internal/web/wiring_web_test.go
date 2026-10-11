package web

import (
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sopshq/internal/keys"
	"sopshq/internal/place"
)

// TestWiringReviewReuseFlowOverHTTP drives the safe-wiring decision flow through
// the real HTTP handlers: a project whose key base already holds an age key is
// wired, which must STOP at a reuse/re-create review screen (never overwrite). The
// operator then chooses REUSE, and wiring adopts the on-disk key (byte-identical)
// and makes the project editable.
func TestWiringReviewReuseFlowOverHTTP(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
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

	keyBase := t.TempDir()
	projDir := t.TempDir()

	post("/machines", url.Values{"name": {"local"}, "os": {"windows"}})
	machineID := extract(t, reMachineLocal, getBody(t, c, ts.URL+"/machines"), "machine id")
	post("/machines/"+machineID+"/local", url.Values{})
	post("/osusers", url.Values{"machine_id": {machineID}, "os_username": {"dev"}, "key_base": {keyBase}})

	post("/projects", url.Values{"name": {"app"}})
	projID := extract(t, reProjLink, getBody(t, c, ts.URL+"/projects"), "project id")
	post("/projects/"+projID+"/paths", url.Values{"machine_id": {machineID}, "path": {projDir}})

	// Plant a pre-existing private key at the key base.
	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	keyPath := place.KeyFile(keyBase)
	if err := os.WriteFile(keyPath, []byte(kp.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant key: %v", err)
	}
	before, _ := os.ReadFile(keyPath)

	// Wiring must STOP at the review screen and offer reuse/re-create - NOT wire.
	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/machines"), "csrf")
	resp, err := c.PostForm(ts.URL+"/projects/"+projID+"/wire", url.Values{"csrf": {csrf}})
	if err != nil {
		t.Fatalf("POST wire: %v", err)
	}
	body := readAll(t, resp)
	if !strings.Contains(body, "Review wiring") || !strings.Contains(body, "Reuse") {
		t.Fatalf("expected reuse/re-create review screen; got: %.400s", body)
	}
	if !strings.Contains(body, kp.Recipient) {
		t.Fatalf("review screen should show the existing key's recipient; got: %.400s", body)
	}
	// Nothing wired yet, and the on-disk key untouched.
	if len(st.Keys.List()) != 0 {
		t.Fatalf("no key should be created before a choice; got %d", len(st.Keys.List()))
	}
	if after, _ := os.ReadFile(keyPath); string(after) != string(before) {
		t.Fatal("the review must not modify the on-disk key")
	}

	// Choose REUSE for the key.
	post("/projects/"+projID+"/wire/resolve", url.Values{"key": {"reuse"}})

	// Now editable, the on-disk key adopted (recipient matches), file unchanged.
	if body := getBody(t, c, ts.URL+"/projects/"+projID); !strings.Contains(body, "No secrets yet") {
		t.Fatalf("expected an editable project after reuse; got: %.300s", body)
	}
	if len(st.Keys.List()) != 1 || st.Keys.List()[0].Recipient != kp.Recipient {
		t.Fatalf("reuse should adopt the on-disk key; keys=%d", len(st.Keys.List()))
	}
	if after, _ := os.ReadFile(keyPath); strings.TrimSpace(string(after)) != strings.TrimSpace(string(before)) {
		t.Fatal("reuse changed the on-disk private key")
	}
}

// TestAddOSUserAdoptsExistingKeyOverHTTP is the Item-C + Item-A integration through
// the real handlers: adding an OS user whose keystore already holds keys.txt must
// import that key (flash confirms it), and the Keys page must then show the adopted
// key with its user -> key-file location.
func TestAddOSUserAdoptsExistingKeyOverHTTP(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	ts, st := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	post := func(path string, vals url.Values) *http.Response {
		t.Helper()
		csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/machines"), "csrf")
		vals.Set("csrf", csrf)
		resp, err := c.PostForm(ts.URL+path, vals)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		return resp
	}

	keyBase := t.TempDir()
	post("/machines", url.Values{"name": {"local"}, "os": {"windows"}}).Body.Close()
	machineID := extract(t, reMachineLocal, getBody(t, c, ts.URL+"/machines"), "machine id")
	post("/machines/"+machineID+"/local", url.Values{}).Body.Close()

	// Plant an existing key in the keystore BEFORE adding the OS user that points at it.
	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	keyPath := place.KeyFile(keyBase)
	if err := os.WriteFile(keyPath, []byte(kp.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant key: %v", err)
	}
	before, _ := os.ReadFile(keyPath)

	// Adding the OS user must import the on-disk key; the flash confirms it.
	resp := post("/osusers", url.Values{"machine_id": {machineID}, "os_username": {"alice"}, "key_base": {keyBase}})
	flashBody := readAll(t, resp)
	if !strings.Contains(flashBody, "Imported the existing key for alice") {
		t.Fatalf("expected import flash; got: %.400s", flashBody)
	}

	// A Key record was created and the on-disk file left byte-identical.
	if len(st.Keys.List()) != 1 || st.Keys.List()[0].Recipient != kp.Recipient {
		t.Fatalf("expected the on-disk key adopted; keys=%d", len(st.Keys.List()))
	}
	if after, _ := os.ReadFile(keyPath); string(after) != string(before) {
		t.Fatal("adopt modified the on-disk key")
	}

	// The Keys page shows the adopted key with its user -> key-file location.
	body := getBody(t, c, ts.URL+"/keys")
	if !strings.Contains(body, "adopted-alice") {
		t.Fatalf("Keys page missing the adopted key; got: %.400s", body)
	}
	if !strings.Contains(body, "alice -&gt;") && !strings.Contains(body, "alice ->") {
		t.Fatalf("Keys page missing the user->location pairing; got: %.400s", body)
	}
}

// TestWiringReviewRecreateFlowOverHTTP: choosing RE-CREATE generates a fresh
// keypair and overwrites the on-disk key.
func TestWiringReviewRecreateFlowOverHTTP(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
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

	keyBase := t.TempDir()
	projDir := t.TempDir()
	post("/machines", url.Values{"name": {"local"}, "os": {"windows"}})
	machineID := extract(t, reMachineLocal, getBody(t, c, ts.URL+"/machines"), "machine id")
	post("/machines/"+machineID+"/local", url.Values{})
	post("/osusers", url.Values{"machine_id": {machineID}, "os_username": {"dev"}, "key_base": {keyBase}})
	post("/projects", url.Values{"name": {"app"}})
	projID := extract(t, reProjLink, getBody(t, c, ts.URL+"/projects"), "project id")
	post("/projects/"+projID+"/paths", url.Values{"machine_id": {machineID}, "path": {projDir}})

	kp, _ := keys.Generate()
	keyPath := place.KeyFile(keyBase)
	if err := os.WriteFile(keyPath, []byte(kp.Private+"\n"), 0o600); err != nil {
		t.Fatalf("plant key: %v", err)
	}

	post("/projects/"+projID+"/wire", url.Values{}) // hits the review
	post("/projects/"+projID+"/wire/resolve", url.Values{"key": {"recreate"}})

	if len(st.Keys.List()) != 1 || st.Keys.List()[0].Recipient == kp.Recipient {
		t.Fatalf("re-create should produce a NEW keypair; keys=%d", len(st.Keys.List()))
	}
	if after, _ := os.ReadFile(keyPath); strings.TrimSpace(string(after)) == kp.Private {
		t.Fatal("re-create should overwrite the on-disk key")
	}
	if _, err := os.Stat(filepath.Join(projDir, ".sops.yaml")); err != nil {
		t.Fatalf(".sops.yaml should be written after re-create: %v", err)
	}
}
