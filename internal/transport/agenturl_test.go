package transport

import "testing"

func TestNormalizeAgentHost(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		portField int
		wantHost  string
		wantPort  int
		wantErr   bool
	}{
		{"plain hostname", "host.tailnet.ts.net", 8443, "host.tailnet.ts.net", 8443, false},
		{"hostname with scheme", "http://host.tailnet.ts.net", 8443, "host.tailnet.ts.net", 8443, false},
		{"scheme and embedded port, field empty", "http://host.tailnet.ts.net:8443", 0, "host.tailnet.ts.net", 8443, false},
		{"embedded port, field set wins", "host.tailnet.ts.net:9000", 8443, "host.tailnet.ts.net", 8443, false},
		{"trailing path stripped", "http://host.tailnet.ts.net:8443/v1/ping", 0, "host.tailnet.ts.net", 8443, false},
		{"ipv4", "1.2.3.4", 8443, "1.2.3.4", 8443, false},
		{"ipv4 with scheme and port", "http://1.2.3.4:8443", 0, "1.2.3.4", 8443, false},
		{"ipv6 bracketed no port", "[::1]", 8443, "::1", 8443, false},
		{"ipv6 bracketed with port", "http://[::1]:8443", 0, "::1", 8443, false},
		{"ipv6 bare", "fe80::1", 8443, "fe80::1", 8443, false},
		{"no port anywhere", "host.tailnet.ts.net", 0, "host.tailnet.ts.net", 0, false},
		{"garbage scheme only", "http://", 8443, "", 0, true},
		{"empty", "   ", 8443, "", 0, true},
		{"whitespace inside", "bad host", 8443, "", 0, true},
		{"non-numeric embedded port", "host:abc", 0, "", 0, true},
		{"embedded port out of range", "host:99999", 0, "", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host, port, err := NormalizeAgentHost(c.raw, c.portField)
			if c.wantErr {
				if err == nil {
					t.Fatalf("NormalizeAgentHost(%q, %d) = (%q, %d, nil), want error", c.raw, c.portField, host, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeAgentHost(%q, %d) error = %v, want nil", c.raw, c.portField, err)
			}
			if host != c.wantHost || port != c.wantPort {
				t.Errorf("NormalizeAgentHost(%q, %d) = (%q, %d), want (%q, %d)", c.raw, c.portField, host, port, c.wantHost, c.wantPort)
			}
		})
	}
}

func TestAgentBaseURL(t *testing.T) {
	cases := []struct {
		host string
		port int
		want string
	}{
		{"1.2.3.4", 8443, "http://1.2.3.4:8443"},
		{"host.tailnet.ts.net", 8443, "http://host.tailnet.ts.net:8443"},
		{"::1", 8443, "http://[::1]:8443"},
	}
	for _, c := range cases {
		if got := AgentBaseURL(c.host, c.port); got != c.want {
			t.Errorf("AgentBaseURL(%q, %d) = %q, want %q", c.host, c.port, got, c.want)
		}
	}
}
