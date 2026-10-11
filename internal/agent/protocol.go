// Package agent is the machine-to-machine service. Each node runs an Agent: a
// plain-HTTP server, reached only over Tailscale (WireGuard-encrypted, tailnet-only)
// and authenticated by a shared transfer key, that lets a peer place keys, write a
// project's .sops.yaml, and re-key secret files on THIS machine. The panel on one
// node calls another node's Agent to push key material across the Tailscale network.
//
// SECURITY: request bodies can carry age PRIVATE keys (placement, and the current
// key for updatekeys). Confidentiality comes from the network boundary (Tailscale),
// authentication from the shared transfer key, and the bodies are never logged. The
// agent runs inside `sopshq serve` as the unprivileged service account (serve
// refuses root), so it places keys only where that account may write.
package agent

import "sopshq/internal/keys"

// API path prefix and routes.
const (
	PathPing       = "/v1/ping"
	PathPlace      = "/v1/place"
	PathSopsYAML   = "/v1/sopsyaml"
	PathUpdateKeys = "/v1/updatekeys"
	PathOplog      = "/v1/oplog"
	PathInspect    = "/v1/inspect"
)

// PingResponse reports liveness and version of a peer agent.
type PingResponse struct {
	Node    string `json:"node"`
	Version string `json:"version"`
	OK      bool   `json:"ok"`
}

// PlaceRequest asks the agent to write a private key into a user's key store.
// Private is SECRET.
type PlaceRequest struct {
	Base      string `json:"base"`
	Recipient string `json:"recipient"`
	Private   string `json:"private"`
	Username  string `json:"username,omitempty"`
}

// SopsYAMLRequest asks the agent to write .sops.yaml into a project directory.
type SopsYAMLRequest struct {
	Dir        string           `json:"dir"`
	Recipients []keys.Recipient `json:"recipients"`
}

// UpdateKeysRequest asks the agent to re-key the secret files in a directory.
// CurrentPriv is SECRET (a current recipient's private key, to decrypt with).
type UpdateKeysRequest struct {
	Dir         string `json:"dir"`
	CurrentPriv string `json:"current_priv"`
}

// UpdateKeysResponse reports how many files were re-keyed.
type UpdateKeysResponse struct {
	Count int `json:"count"`
}

// InspectRequest asks the agent to report drift between the panel's desired state
// and what is on THIS machine's disk. It carries only PUBLIC facts (paths and
// expected public recipients) - never a private key - so it is safe to send and the
// agent can answer without unsealing anything.
type InspectRequest struct {
	Placements []PlacementCheck `json:"placements,omitempty"`
	Projects   []ProjectCheck   `json:"projects,omitempty"`
}

// PlacementCheck asks "is the key whose PUBLIC recipient is Recipient placed at
// Base/keys.txt?". Target is the OS-user name, echoed back so the panel can label a
// finding without the agent knowing any names.
type PlacementCheck struct {
	Target    string `json:"target"`
	Base      string `json:"base"`
	Recipient string `json:"recipient"`
}

// ProjectCheck asks "does Dir/.sops.yaml list exactly these public Recipients?".
type ProjectCheck struct {
	Target     string   `json:"target"`
	Dir        string   `json:"dir"`
	Recipients []string `json:"recipients"`
}

// InspectResponse reports the discrepancies the agent found. An empty Drifts slice
// means on-disk state matches the desired state.
type InspectResponse struct {
	Drifts []DriftFinding `json:"drifts,omitempty"`
}

// DriftFinding is one discrepancy: its kind ("placement" or "sops.yaml"), the
// echoed target name, and a human-readable detail. It carries no secret.
type DriftFinding struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Detail string `json:"detail"`
}

// errorResponse is the JSON shape for an error (never contains secrets).
type errorResponse struct {
	Error string `json:"error"`
}
