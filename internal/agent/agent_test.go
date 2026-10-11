package agent

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sopshq/internal/keys"
	"sopshq/internal/place"
)

// agentTestToken is the shared transfer key the in-process agent tests use.
const agentTestToken = "agent-test-token"

// startAgent runs an in-process HTTP agent that accepts the shared transfer key,
// returning the server, its base URL, and a stop func.
func startAgent(t *testing.T) (*Server, string, func()) {
	t.Helper()
	ag := NewServer(agentTestToken, "peerB", "test")
	ag.SetPlacer(place.WriteKeyStore) // never touch the host environment in tests
	place.DisableEffectsForTest(t)    // backstop: no setx/mklink/bashrc from any path
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	hs := &http.Server{Handler: ag.Handler()}
	go func() { _ = hs.Serve(ln) }()
	return ag, "http://" + ln.Addr().String(), func() { _ = hs.Close() }
}

func TestAgentRemotePlacementRoundTrip(t *testing.T) {
	_, url, stop := startAgent(t)
	defer stop()

	c := Dial(url, agentTestToken)

	pong, err := c.Ping()
	if err != nil || !pong.OK || pong.Node != "peerB" {
		t.Fatalf("ping: %+v err=%v", pong, err)
	}

	// Remote placement.
	base := t.TempDir()
	if err := c.Place(PlaceRequest{
		Base:      base,
		Recipient: "age1exampleexampleexampleexampleexampleexampleexampl",
		Private:   "AGE-SECRET-KEY-1EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE",
	}); err != nil {
		t.Fatalf("remote Place: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(base, "keys.txt"))
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(got)), "AGE-SECRET-KEY-1") {
		t.Fatalf("remote placement did not write keys.txt: err=%v", err)
	}

	// Remote .sops.yaml write.
	projDir := t.TempDir()
	if err := c.WriteSopsYAML(SopsYAMLRequest{
		Dir:        projDir,
		Recipients: []keys.Recipient{{Label: "alice", Age: "age1aaa"}},
	}); err != nil {
		t.Fatalf("remote WriteSopsYAML: %v", err)
	}
	if sy, _ := os.ReadFile(filepath.Join(projDir, ".sops.yaml")); !strings.Contains(string(sy), "age1aaa") {
		t.Fatalf("remote .sops.yaml not written")
	}
}

func TestAgentInspectReportsDrift(t *testing.T) {
	_, url, stop := startAgent(t)
	defer stop()
	c := Dial(url, agentTestToken)

	// A project with a .sops.yaml listing exactly one recipient.
	projDir := t.TempDir()
	if err := keys.WriteSopsYAML(projDir, []keys.Recipient{{Label: "k", Age: "age1aaa"}}); err != nil {
		t.Fatalf("write .sops.yaml: %v", err)
	}
	emptyBase := t.TempDir() // no keys.txt placed here -> placement drift

	resp, err := c.Inspect(InspectRequest{
		Placements: []PlacementCheck{{Target: "dev", Base: emptyBase, Recipient: "age1aaa"}},
		Projects: []ProjectCheck{
			{Target: "matching", Dir: projDir, Recipients: []string{"age1aaa"}},
			{Target: "drifted", Dir: projDir, Recipients: []string{"age1bbb"}},
		},
	})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	seen := map[string]bool{}
	for _, d := range resp.Drifts {
		seen[d.Target] = true
	}
	if !seen["dev"] {
		t.Error("expected placement drift for an unplaced key")
	}
	if !seen["drifted"] {
		t.Error("expected sops.yaml drift for mismatched recipients")
	}
	if seen["matching"] {
		t.Error("a project whose recipients match must not report drift")
	}
}

func TestAgentRejectsWrongToken(t *testing.T) {
	_, url, stop := startAgent(t)
	defer stop()

	c := Dial(url, "wrong-token")
	if _, err := c.Ping(); err == nil {
		t.Fatal("agent should reject a client bearing the wrong transfer key")
	}
}
