package transport

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

// ErrBadAgentHost is returned by NormalizeAgentHost when the operator's input does
// not yield a usable host (it is empty after cleaning, carries a non-numeric or
// out-of-range embedded port, or is not a hostname or IP address).
var ErrBadAgentHost = errors.New("not a valid host or IP")

// AgentBaseURL builds the base URL for reaching a peer agent: scheme + host + port.
// net.JoinHostPort brackets an IPv6 host correctly (http://[::1]:8443), so host must
// be a BARE host - a hostname, an IPv4, or an UNBRACKETED IPv6 - exactly the form
// NormalizeAgentHost stores on a Machine record.
func AgentBaseURL(host string, port int) string {
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port))
}

// NormalizeAgentHost turns an operator-entered agent address into a bare host plus an
// effective port. It accepts what people actually paste into the host field: a bare
// hostname or IP, a host:port, a full URL (http://host:port/path), and IPv6 in
// brackets ([::1] or [::1]:8443). The returned host is always bare (brackets removed)
// so it round-trips through AgentBaseURL.
//
// portField is the value of the separate "agent port" form field (0 if left blank).
// When the address carries its own embedded port and portField is 0, the embedded
// port is used; when portField is non-zero, the explicit field wins. The returned
// port may be 0 when neither source supplies one (a machine added without an address
// yet).
//
// It returns ErrBadAgentHost when the cleaned host is empty, when an embedded port is
// not a number in 1..65535, or when the host is neither a parseable IP nor a
// plausible DNS hostname.
func NormalizeAgentHost(raw string, portField int) (host string, port int, err error) {
	s := strings.TrimSpace(raw)

	// Strip a pasted scheme (http:// or https://), case-insensitively.
	if i := strings.Index(s, "://"); i >= 0 {
		switch strings.ToLower(s[:i]) {
		case "http", "https":
			s = s[i+3:]
		}
	}
	// Drop any path, query, or fragment; keep only the host[:port] authority.
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, ErrBadAgentHost
	}

	host = s
	embedded := 0
	if h, p, splitErr := net.SplitHostPort(s); splitErr == nil {
		// host:port or [ipv6]:port - SplitHostPort unwraps the brackets.
		host = h
		if p != "" {
			n, convErr := strconv.Atoi(p)
			if convErr != nil || n < 1 || n > 65535 {
				return "", 0, ErrBadAgentHost
			}
			embedded = n
		}
	} else if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		// Bracketed IPv6 with no port: [::1].
		host = s[1 : len(s)-1]
	}
	// Otherwise host stays s: a bare hostname/IPv4, or a bare unbracketed IPv6
	// (which has colons but no splittable port).

	host = strings.TrimSpace(host)
	if !validHost(host) {
		return "", 0, ErrBadAgentHost
	}

	port = portField
	if port == 0 {
		port = embedded
	}
	return host, port, nil
}

// validHost reports whether h is a parseable IP (IPv4 or IPv6) or a plausible DNS
// hostname (dot-separated labels of letters, digits, and hyphens). It rejects empty
// strings and anything carrying a scheme, port, slash, or whitespace.
func validHost(h string) bool {
	if h == "" {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	if len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z':
			case c >= 'A' && c <= 'Z':
			case c >= '0' && c <= '9':
			case c == '-':
			default:
				return false
			}
		}
	}
	return true
}
