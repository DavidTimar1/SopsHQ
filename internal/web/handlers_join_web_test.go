package web

import (
	"net/url"
	"strings"
	"testing"
)

// TestSetTransferKey stores a cluster transfer key from the panel and confirms the
// Machines page flips from "not set" to "set" afterwards.
func TestSetTransferKey(t *testing.T) {
	ts, _ := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	before := getBody(t, c, ts.URL+"/machines")
	if !strings.Contains(before, "not set") {
		t.Fatalf("expected the transfer key to start unset")
	}
	csrf := extract(t, reCSRF, before, "csrf")
	resp, err := c.PostForm(ts.URL+"/machines/transfer-key", url.Values{"csrf": {csrf}, "transfer_key": {"our-shared-secret"}})
	if err != nil {
		t.Fatalf("POST transfer-key: %v", err)
	}
	resp.Body.Close()

	after := getBody(t, c, ts.URL+"/machines")
	if strings.Contains(after, "not set") {
		t.Fatalf("transfer key still reported as not set after saving")
	}
}

// TestBuildAgentURL checks the advertised peer URL is assembled from this node's
// stable Tailscale IP and the agent port, using an injected lookup so the test never
// depends on the host's real interfaces.
func TestBuildAgentURL(t *testing.T) {
	tests := []struct {
		name        string
		agentListen string
		ip          string
		ok          bool
		want        string
	}{
		{"tailscale ip present", "127.0.0.1:8443", "100.101.102.103", true, "http://100.101.102.103:8443"},
		{"no tailscale ip", "127.0.0.1:8443", "", false, ""},
		{"unparseable listen", "not-a-host-port", "100.101.102.103", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildAgentURL(tt.agentListen, func() (string, bool) { return tt.ip, tt.ok })
			if got != tt.want {
				t.Errorf("buildAgentURL(%q) = %q, want %q", tt.agentListen, got, tt.want)
			}
		})
	}
}

// TestSetTransferKeyRejectsEmpty confirms an empty transfer key is refused.
func TestSetTransferKeyRejectsEmpty(t *testing.T) {
	ts, _ := testServer(t)
	c := newClient(t)
	onboard(t, ts, c, "admin", "supersecret")

	csrf := extract(t, reCSRF, getBody(t, c, ts.URL+"/machines"), "csrf")
	resp, err := c.PostForm(ts.URL+"/machines/transfer-key", url.Values{"csrf": {csrf}, "transfer_key": {""}})
	if err != nil {
		t.Fatalf("POST transfer-key: %v", err)
	}
	resp.Body.Close()

	if after := getBody(t, c, ts.URL+"/machines"); !strings.Contains(after, "not set") {
		t.Fatalf("empty transfer key should not have been stored")
	}
}
