package web

import (
	"net"
	"net/http"
	"strings"

	"sopshq/internal/audit"
	"sopshq/internal/auth"
	"sopshq/internal/transport"
)

// thisAgentURL returns the address other machines should use to reach THIS node's
// agent: its stable Tailscale IP with the agent port, e.g. http://100.101.102.103:8443.
// Tailscale assigns each node a fixed address from the CGNAT range 100.64.0.0/10, so
// the IP is stable per node. Empty when no Tailscale address is found (the operator
// then reads it from `tailscale status`).
func thisAgentURL(agentListen string) string {
	return buildAgentURL(agentListen, transport.TailscaleIP)
}

// buildAgentURL is the pure core of thisAgentURL: it assembles the advertised peer URL
// from agentListen (host:port) and a Tailscale-IP lookup. Splitting the lookup out lets
// tests inject a fake without touching the host's real interfaces.
func buildAgentURL(agentListen string, tailscaleIP func() (string, bool)) string {
	_, port, err := net.SplitHostPort(agentListen)
	if err != nil {
		return ""
	}
	if ip, ok := tailscaleIP(); ok {
		return "http://" + net.JoinHostPort(ip, port)
	}
	return ""
}

// setTransferKey stores the cluster transfer key - the shared secret that
// authenticates machine-to-machine sync - vault-sealed in this machine's config.
// Admin-only, CSRF-checked. Use the SAME key on every machine. It is never displayed
// again; it takes effect on the next restart. The plaintext is never logged.
func (s *Server) setTransferKey(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if !s.guardPost(w, r, sess, "/machines") {
		return
	}
	key := strings.TrimSpace(r.FormValue("transfer_key"))
	if key == "" {
		redirect(w, r, "/machines", "Transfer key cannot be empty.", true)
		return
	}
	sealed, err := s.vault.Seal([]byte(key))
	if err != nil {
		s.renderError(w, r, sess, "Could not seal the transfer key.", http.StatusInternalServerError)
		return
	}
	s.cfg.TransferKeySealed = sealed
	if err := s.cfg.Save(); err != nil {
		s.renderError(w, r, sess, "Could not save the transfer key.", http.StatusInternalServerError)
		return
	}
	s.audit.Record(sess.Username, "transfer_key_set", "cluster", audit.OK, "")
	redirect(w, r, "/machines", "Transfer key saved. Restart SopsHQ for it to take effect.", false)
}
