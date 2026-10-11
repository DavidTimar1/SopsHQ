// Package transport finds the network address this machine uses to reach its peers.
// The agent binds a Tailscale address when one exists, so peers can reach it, and
// every peer URL the cluster builds is shaped here.
package transport

import "net"

// TailscaleIP returns this machine's Tailscale IPv4 address if one is present on a
// local interface, along with true. Tailscale assigns addresses from the CGNAT
// range 100.64.0.0/10, so the agent can bind a PEER-REACHABLE address instead of
// loopback (a peer can never reach 127.0.0.1), and the join code can advertise it.
//
// It returns ("", false) when no Tailscale address is found (Tailscale not running,
// or this host is not on the tailnet); the caller then keeps the configured address
// and warns that peers cannot reach a loopback bind.
func TailscaleIP() (string, bool) {
	_, cgnat, err := net.ParseCIDR("100.64.0.0/10")
	if err != nil {
		return "", false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", false
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil && cgnat.Contains(ip4) {
			return ip4.String(), true
		}
	}
	return "", false
}

// IsLoopbackHost reports whether host is a loopback / unreachable-by-a-peer host:
// empty (binds all but advertised as nothing useful), 127.0.0.1, ::1, or localhost.
// Used to reject a join-code address that no other machine could reach.
func IsLoopbackHost(host string) bool {
	switch host {
	case "", "127.0.0.1", "::1", "localhost":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
