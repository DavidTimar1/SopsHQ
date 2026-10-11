// Package slack is a tiny, dependency-free client for a Slack incoming webhook:
// it POSTs a small JSON body {"text": "..."} to a webhook URL.
//
// SECURITY: the webhook URL is a secret (anyone holding it can post to the
// channel). It is the request target, so it is never placed in a returned error
// string or logged. The client sends ONLY the message payload - no
// owner/app-identifying metadata (no Referer, X-Title, or custom User-Agent).
package slack

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// requestTimeout bounds a single send so a notification never hangs the caller.
const requestTimeout = 15 * time.Second

// SendWebhook posts text to the Slack incoming webhook at webhookURL. It returns
// a credential-free error on failure (the URL never appears in the message).
func SendWebhook(webhookURL, text string) error {
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return errors.New("slack: could not encode message")
	}
	req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		// Do not wrap err: it would echo the secret webhook URL.
		return errors.New("slack: could not build request")
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: requestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		// Do not wrap err: it would echo the secret webhook URL.
		return errors.New("slack: request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack: server returned status %d", resp.StatusCode)
	}
	return nil
}
