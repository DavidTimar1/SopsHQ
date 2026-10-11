package keysvc

import (
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sopshq/internal/agent"
	"sopshq/internal/model"
	"sopshq/internal/place"
	"sopshq/internal/store"
)

// testTransferKey is the shared transfer key used by the in-process agent tests.
const testTransferKey = "test-transfer-token"

// startRemoteAgent runs an in-process HTTP agent that accepts the shared transfer
// token, returning its base URL and a stop func.
func startRemoteAgent(t *testing.T) (string, func()) {
	t.Helper()
	ag := agent.NewServer(testTransferKey, "remote", "test")
	ag.SetPlacer(place.WriteKeyStore)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	hs := &http.Server{Handler: ag.Handler()}
	go func() { _ = hs.Serve(ln) }()
	return "http://" + ln.Addr().String(), func() { _ = hs.Close() }
}

// TestPendingProbesRemoteAgent verifies the cross-machine pending check: it dials
// the remote agent's inspect RPC and reports drift before Apply (key not placed,
// .sops.yaml missing) and none after a successful ApplyAll.
func TestPendingProbesRemoteAgent(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, st, _ := build(t)

	svc.SetTransferKey(testTransferKey)
	svc.SetPlacer(place.WriteKeyStore)

	url, stop := startRemoteAgent(t)
	defer stop()

	remoteMachine := &model.Machine{M: model.Meta{UUID: store.NewID()}, Name: "remote",
		OS: model.OSLinux}
	if err := st.Machines.Put(remoteMachine); err != nil {
		t.Fatalf("remote machine: %v", err)
	}
	svc.SetDialer(func(m *model.Machine) (remote, bool) {
		if m.M.UUID == remoteMachine.M.UUID {
			return agent.Dial(url, testTransferKey), true
		}
		return nil, false
	})

	projDir := t.TempDir()
	keyBase := t.TempDir()
	proj := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "remoteapp",
		Paths: []model.ProjectPath{{MachineID: remoteMachine.M.UUID, Path: projDir}}}
	st.Projects.Put(proj)
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: remoteMachine.M.UUID, Username: "bob", KeyBase: keyBase}
	st.OSUsers.Put(osu)
	key := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "remote-key", Type: model.KeyShared}
	st.Keys.Put(key)
	if err := svc.Generate(key.M.UUID, "tester"); err != nil {
		t.Fatalf("generate: %v", err)
	}
	st.Assignments.Put(&model.Assignment{M: model.Meta{UUID: store.NewID()},
		KeyID: key.M.UUID, ProjectID: proj.M.UUID, MachineID: remoteMachine.M.UUID, OSUserID: osu.M.UUID})

	before := svc.Pending()
	if len(before.Remote) == 0 {
		t.Fatalf("expected remote drift before apply, got none (unreachable=%v)", before.Unreachable)
	}

	if _, err := svc.ApplyAll("tester", false); err != nil {
		t.Fatalf("ApplyAll: %v", err)
	}

	after := svc.Pending()
	if len(after.Remote) != 0 {
		t.Fatalf("expected no remote drift after apply, got: %+v", after.Remote)
	}
	if len(after.Unreachable) != 0 {
		t.Fatalf("remote should be reachable, got unreachable=%v", after.Unreachable)
	}
}

func TestApplyAllPushesToRemoteAgent(t *testing.T) {
	if _, err := exec.LookPath("age-keygen"); err != nil {
		t.Skip("age-keygen not on PATH")
	}
	svc, st, _ := build(t)

	svc.SetTransferKey(testTransferKey)
	svc.SetPlacer(place.WriteKeyStore)

	// A remote machine + its in-process agent.
	url, stop := startRemoteAgent(t)
	defer stop()

	remoteMachine := &model.Machine{
		M:    model.Meta{UUID: store.NewID()},
		Name: "remote",
		OS:   model.OSLinux,
	}
	if err := st.Machines.Put(remoteMachine); err != nil {
		t.Fatalf("remote machine: %v", err)
	}
	// Inject a dialer that points the remote machine at our in-process agent.
	svc.SetDialer(func(m *model.Machine) (remote, bool) {
		if m.M.UUID == remoteMachine.M.UUID {
			return agent.Dial(url, testTransferKey), true
		}
		return nil, false
	})

	// A project + path + OS user that live on the REMOTE machine.
	projDir := t.TempDir()
	keyBase := t.TempDir()
	proj := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "remoteapp",
		Paths: []model.ProjectPath{{MachineID: remoteMachine.M.UUID, Path: projDir}}}
	st.Projects.Put(proj)
	osu := &model.OSUser{M: model.Meta{UUID: store.NewID()}, MachineID: remoteMachine.M.UUID, Username: "bob", KeyBase: keyBase}
	st.OSUsers.Put(osu)
	key := &model.Key{M: model.Meta{UUID: store.NewID()}, Name: "remote-key", Type: model.KeyShared}
	st.Keys.Put(key)
	if err := svc.Generate(key.M.UUID, "tester"); err != nil {
		t.Fatalf("generate: %v", err)
	}
	st.Assignments.Put(&model.Assignment{M: model.Meta{UUID: store.NewID()},
		KeyID: key.M.UUID, ProjectID: proj.M.UUID, MachineID: remoteMachine.M.UUID, OSUserID: osu.M.UUID})

	// Push everything; the remote pieces go over the agent channel.
	rep, err := svc.ApplyAll("tester", false)
	if err != nil {
		t.Fatalf("ApplyAll: %v", err)
	}
	if rep.KeysPlaced != 1 || rep.ProjectsWired != 1 {
		t.Fatalf("unexpected report: %+v (skipped=%v)", rep, rep.Skipped)
	}
	// The remote agent wrote these via the channel.
	if b, err := os.ReadFile(filepath.Join(keyBase, "keys.txt")); err != nil ||
		!strings.HasPrefix(strings.TrimSpace(string(b)), "AGE-SECRET-KEY-1") {
		t.Fatalf("remote placement missing: err=%v", err)
	}
	if sy, _ := os.ReadFile(filepath.Join(projDir, ".sops.yaml")); !strings.Contains(string(sy), "age1") {
		t.Fatalf("remote .sops.yaml missing")
	}
}
