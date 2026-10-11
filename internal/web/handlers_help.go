package web

import (
	"net/http"

	"sopshq/internal/auth"
)

// getHelp renders the in-panel terminology and how-it-works page: the full
// glossary, the two-gates model, and a diagram of how OS accounts, private keys,
// public keys, and the encrypted secrets file connect. It carries no per-request
// data, so the page is static apart from the shared layout.
func (s *Server) getHelp(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	s.render(w, r, "help", sess, "Terminology", nil, http.StatusOK)
}
