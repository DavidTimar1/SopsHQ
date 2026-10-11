package agent

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"sopshq/internal/keys"
	"sopshq/internal/place"
	"sopshq/internal/store"
)

// errNoOplog is returned by the oplog endpoint when no source is configured.
var errNoOplog = errors.New("agent: oplog endpoint not enabled")

// Server is a node's agent: the receiving side of remote placement and the source
// of this node's replication oplog. It serves plain HTTP (bind it to loopback or a
// Tailscale address) and authenticates every request with a shared TRANSFER TOKEN -
// a secret both machines hold. Transport confidentiality is the network's
// (Tailscale/WireGuard); the token is the access control.
type Server struct {
	token   string
	node    string
	version string

	// placer performs on-disk placement; defaults to place.Place. Overridable in
	// tests so they do not touch the real environment.
	placer func(place.Opts) error

	// oplog returns this node's replication events with Seq > since. nil disables
	// the /v1/oplog endpoint (returns 404).
	oplog func(since int64) ([]store.Event, error)

	mux *http.ServeMux
}

// NewServer builds an agent that accepts requests bearing the shared transfer
// token. An empty token disables the agent (every request is rejected), so a node
// that has not set a transfer key never serves peer requests.
func NewServer(token, node, version string) *Server {
	s := &Server{
		token:   token,
		node:    node,
		version: version,
		placer:  place.Place,
	}
	m := http.NewServeMux()
	m.HandleFunc("GET "+PathPing, s.handlePing)
	m.HandleFunc("POST "+PathPlace, s.handlePlace)
	m.HandleFunc("POST "+PathSopsYAML, s.handleSopsYAML)
	m.HandleFunc("POST "+PathUpdateKeys, s.handleUpdateKeys)
	m.HandleFunc("POST "+PathInspect, s.handleInspect)
	m.HandleFunc("GET "+PathOplog, s.handleOplog)
	s.mux = m
	return s
}

// SetPlacer overrides the placement function (tests).
func (s *Server) SetPlacer(f func(place.Opts) error) { s.placer = f }

// SetOplogSource enables the /v1/oplog endpoint, serving this node's replication
// events to peers. Pass store.Oplog().Since.
func (s *Server) SetOplogSource(f func(since int64) ([]store.Event, error)) { s.oplog = f }

// Handler returns the agent's HTTP handler, gated by the transfer-token check.
func (s *Server) Handler() http.Handler { return s.requireToken(s.mux) }

// requireToken rejects any request that does not carry the shared transfer key in
// the Authorization header ("Bearer <token>"). The compare is constant-time. With no
// token configured the agent serves nothing.
func (s *Server) requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeErr(w, http.StatusUnauthorized, errors.New("agent: invalid or missing transfer key"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// HTTPServer returns the agent's plain-HTTP server on addr (bind loopback or a
// Tailscale address). The caller owns lifecycle.
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{Addr: addr, Handler: s.Handler()}
}

func (s *Server) handlePing(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, PingResponse{Node: s.node, Version: s.version, OK: true})
}

func (s *Server) handlePlace(w http.ResponseWriter, r *http.Request) {
	var req PlaceRequest
	if !decode(w, r, &req) {
		return
	}
	if err := s.placer(place.Opts{
		Base:      req.Base,
		Recipient: req.Recipient,
		Private:   req.Private,
		Username:  req.Username,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

func (s *Server) handleSopsYAML(w http.ResponseWriter, r *http.Request) {
	var req SopsYAMLRequest
	if !decode(w, r, &req) {
		return
	}
	if err := keys.WriteSopsYAML(req.Dir, req.Recipients); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

func (s *Server) handleUpdateKeys(w http.ResponseWriter, r *http.Request) {
	var req UpdateKeysRequest
	if !decode(w, r, &req) {
		return
	}
	n, err := keys.UpdateKeysInDir(req.Dir, req.CurrentPriv)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, UpdateKeysResponse{Count: n})
}

// handleInspect reports drift between the panel's desired state and this machine's
// disk. It reads only public facts: whether each key file is present and which
// recipient it derives to (via age-keygen -y, which never emits the private half),
// and which recipients each .sops.yaml lists. It never unseals or returns a secret.
func (s *Server) handleInspect(w http.ResponseWriter, r *http.Request) {
	var req InspectRequest
	if !decode(w, r, &req) {
		return
	}
	var out InspectResponse
	for _, p := range req.Placements {
		data, err := os.ReadFile(place.KeyFile(p.Base))
		if err != nil {
			out.Drifts = append(out.Drifts, DriftFinding{"placement", p.Target, "key is not placed"})
			continue
		}
		// A key store may hold several keys (one per project); the placement is
		// satisfied when the expected recipient is AMONG those in the file.
		recs, err := keys.RecipientsFor(strings.TrimSpace(string(data)))
		if err != nil {
			out.Drifts = append(out.Drifts, DriftFinding{"placement", p.Target, "placed key could not be read"})
			continue
		}
		if !slices.Contains(recs, p.Recipient) {
			out.Drifts = append(out.Drifts, DriftFinding{"placement", p.Target, "expected key is not in the key store"})
		}
	}
	for _, p := range req.Projects {
		data, err := os.ReadFile(filepath.Join(p.Dir, ".sops.yaml"))
		if err != nil {
			out.Drifts = append(out.Drifts, DriftFinding{"sops.yaml", p.Target, ".sops.yaml is missing"})
			continue
		}
		if !sameStringSet(p.Recipients, parseAgeLine(string(data))) {
			out.Drifts = append(out.Drifts, DriftFinding{"sops.yaml", p.Target, "recipients differ from desired"})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// parseAgeLine extracts the comma-separated recipients from the "age:" line of a
// .sops.yaml that SopsHQ's writer produced.
func parseAgeLine(content string) []string {
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "age:") {
			rest := strings.TrimSpace(strings.TrimPrefix(t, "age:"))
			if rest == "" {
				return nil
			}
			parts := strings.Split(rest, ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			return parts
		}
	}
	return nil
}

// sameStringSet reports whether want and got hold the same set of values.
func sameStringSet(want, got []string) bool {
	if len(want) != len(got) {
		return false
	}
	set := make(map[string]bool, len(got))
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

func (s *Server) handleOplog(w http.ResponseWriter, r *http.Request) {
	if s.oplog == nil {
		writeErr(w, http.StatusNotFound, errNoOplog)
		return
	}
	var since int64
	if v := r.URL.Query().Get("since"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			since = n
		}
	}
	events, err := s.oplog(since)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

// decode reads a JSON request body, writing a 400 on failure.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr returns a JSON error. The error text here is from our own code paths
// (placement/sops); it never includes secret material.
func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, errorResponse{Error: err.Error()})
}
