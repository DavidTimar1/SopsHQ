package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveWritesJSONCHeaderAndRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.jsonc")
	c := Default(path, dir, "node")
	c.PanelListen = "0.0.0.0:9090"
	c.AgentListen = "127.0.0.1:9443"
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// The file documents the port fields so the operator can find them.
	for _, want := range []string{"SopsHQ configuration", "panel_listen", "agent_listen", "host:port"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("written config missing %q:\n%s", want, raw)
		}
	}
	// And it still parses (comments stripped), preserving the edited ports.
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.PanelListen != "0.0.0.0:9090" || got.AgentListen != "127.0.0.1:9443" {
		t.Fatalf("ports not round-tripped: panel=%q agent=%q", got.PanelListen, got.AgentListen)
	}
}

func TestInvalidListenAddressesRejected(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]struct{ panel, agent string }{
		"panel no port":    {"127.0.0.1", "127.0.0.1:8443"},
		"agent no port":    {"127.0.0.1:8080", "9000"},
		"panel bad port":   {"127.0.0.1:abc", "127.0.0.1:8443"},
		"agent port range": {"127.0.0.1:8080", "127.0.0.1:70000"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, "c.jsonc")
			c := Default(path, dir, "node")
			c.PanelListen = tc.panel
			c.AgentListen = tc.agent
			// Bypass Save (which does not validate) by writing then loading.
			if err := c.Save(); err != nil {
				t.Fatalf("Save: %v", err)
			}
			if _, err := Load(path); err == nil {
				t.Fatalf("expected Load to reject panel=%q agent=%q", tc.panel, tc.agent)
			}
		})
	}
}

func TestValidPortsAccepted(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8080", ":8443", "0.0.0.0:9000", "100.64.0.2:1"} {
		if err := validateListen("x", addr); err != nil {
			t.Errorf("%q should be valid: %v", addr, err)
		}
	}
}
