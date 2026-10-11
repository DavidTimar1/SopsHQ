package transport

import "testing"

func TestIsLoopbackHost(t *testing.T) {
	loopback := []string{"", "127.0.0.1", "::1", "localhost", "127.0.0.5"}
	for _, h := range loopback {
		if !IsLoopbackHost(h) {
			t.Errorf("IsLoopbackHost(%q) = false, want true", h)
		}
	}
	reachable := []string{"100.101.102.103", "server.tailnet.ts.net", "10.0.0.1", "192.168.1.5"}
	for _, h := range reachable {
		if IsLoopbackHost(h) {
			t.Errorf("IsLoopbackHost(%q) = true, want false", h)
		}
	}
}
