package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"sopshq/internal/store"
)

// Client calls a peer node's Agent over plain HTTP (the wire is encrypted by
// Tailscale), authenticating with the shared transfer key.
type Client struct {
	http    *http.Client
	baseURL string
	token   string
}

// Dial builds a Client for the peer at baseURL (e.g. http://100.101.102.103:port),
// authenticating with the shared transfer key. No network call happens until a
// method is invoked.
func Dial(baseURL, token string) *Client {
	return DialTimeout(baseURL, token, 30*time.Second)
}

// DialTimeout is Dial with an explicit per-request timeout. Use a short timeout for
// liveness checks (a status page must not hang on an unreachable peer).
func DialTimeout(baseURL, token string, timeout time.Duration) *Client {
	return &Client{
		http:    &http.Client{Timeout: timeout},
		baseURL: baseURL,
		token:   token,
	}
}

// Ping checks the peer agent is reachable and reports its node/version.
func (c *Client) Ping() (PingResponse, error) {
	var out PingResponse
	err := c.do(http.MethodGet, PathPing, nil, &out)
	return out, err
}

// Place asks the peer to write a private key into a user's key store.
func (c *Client) Place(req PlaceRequest) error {
	return c.do(http.MethodPost, PathPlace, req, nil)
}

// WriteSopsYAML asks the peer to write a project's .sops.yaml.
func (c *Client) WriteSopsYAML(req SopsYAMLRequest) error {
	return c.do(http.MethodPost, PathSopsYAML, req, nil)
}

// UpdateKeys asks the peer to re-key the secret files in a directory and returns
// how many were updated.
func (c *Client) UpdateKeys(req UpdateKeysRequest) (int, error) {
	var out UpdateKeysResponse
	err := c.do(http.MethodPost, PathUpdateKeys, req, &out)
	return out.Count, err
}

// Inspect asks the peer to report drift between the supplied desired state and what
// is on its disk. The request carries only public facts; no private key is sent.
func (c *Client) Inspect(req InspectRequest) (InspectResponse, error) {
	var out InspectResponse
	err := c.do(http.MethodPost, PathInspect, req, &out)
	return out, err
}

// Oplog fetches this peer's replication events with Seq greater than since.
func (c *Client) Oplog(since int64) ([]store.Event, error) {
	var out []store.Event
	err := c.do(http.MethodGet, PathOplog+"?since="+strconv.FormatInt(since, 10), nil, &out)
	return out, err
}

// do performs one JSON request/response. On a non-2xx it decodes the JSON error.
func (c *Client) do(method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("agent: marshal: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.baseURL+path, rdr)
	if err != nil {
		return fmt.Errorf("agent: request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("agent: call %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var e errorResponse
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return fmt.Errorf("agent: %s: %s", path, e.Error)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("agent: decode response: %w", err)
		}
	}
	return nil
}
