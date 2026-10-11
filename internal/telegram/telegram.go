// Package telegram is a tiny, dependency-free client for the Telegram Bot API
// sendMessage method: it POSTs a short text message to a chat or channel.
//
// SECURITY: the bot token is a secret. It is required in the request URL path
// (that is how the Bot API authenticates), but it is NEVER placed in a returned
// error string or logged. The client sends ONLY the credential (in the path) and
// the payload (chat_id + text) - no owner/app-identifying metadata (no Referer,
// X-Title, or custom User-Agent).
package telegram

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// apiBase is the real Telegram Bot API host. Tests call the unexported
// sendMessage with their own base.
const apiBase = "https://api.telegram.org"

// requestTimeout bounds a single send so a notification never hangs the caller.
const requestTimeout = 15 * time.Second

// SendMessage posts text to chatID using the bot identified by token. It returns
// a credential-free error on failure (the token never appears in the message).
func SendMessage(token, chatID, text string) error {
	return sendMessage(apiBase, token, chatID, text)
}

// sendMessage performs the POST against base, which the real entry point sets to
// the Bot API host and tests set to a local server.
func sendMessage(base, token, chatID, text string) error {
	form := url.Values{"chat_id": {chatID}, "text": {text}}
	// The token lives in the URL path; build the request without ever logging it.
	req, err := http.NewRequest(http.MethodPost, base+"/bot"+token+"/sendMessage", strings.NewReader(form.Encode()))
	if err != nil {
		// Do not wrap err: it would echo the token-bearing URL.
		return errors.New("telegram: could not build request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: requestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		// Do not wrap err: it would echo the token-bearing URL.
		return errors.New("telegram: request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram: server returned status %d", resp.StatusCode)
	}
	return nil
}
