package repl

import (
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"sopshq/internal/agent"
	"sopshq/internal/audit"
	"sopshq/internal/model"
	"sopshq/internal/store"
)

// TestPullOverRealAgentChannel drives replication through the actual agent channel:
// node B pulls node A's oplog over HTTP via a real agent.Client (authenticated by
// the shared transfer key) and applies it. This is the production path end to end.
func TestPullOverRealAgentChannel(t *testing.T) {
	const token = "channel-test-token"
	a, _ := newStore(t, "A")
	b, dirB := newStore(t, "B")

	// A runs an agent that exposes its oplog, gated by the transfer key.
	ag := agent.NewServer(token, "A", "test")
	ag.SetOplogSource(a.Oplog().Since)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	hs := &http.Server{Handler: ag.Handler()}
	go func() { _ = hs.Serve(ln) }()
	defer hs.Close()

	// B dials A's agent and replicates.
	client := agent.Dial("http://"+ln.Addr().String(), token)
	syncer := NewSyncer(b, audit.Open(filepath.Join(dirB, "audit.jsonl"), "B", nil), dirB)

	p := &model.Project{M: model.Meta{UUID: store.NewID()}, Name: "over-the-wire"}
	if err := a.Projects.Put(p); err != nil {
		t.Fatalf("A put: %v", err)
	}
	res, err := syncer.Pull("A", "A", client)
	if err != nil {
		t.Fatalf("pull over channel: %v", err)
	}
	if res.Applied != 1 {
		t.Fatalf("expected 1 applied over the channel, got %+v", res)
	}
	if got, err := b.Projects.Get(p.M.UUID); err != nil || got.Name != "over-the-wire" {
		t.Fatalf("B did not receive project over the channel: %v", err)
	}
}
