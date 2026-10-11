package slack

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSendWebhookShape verifies the JSON body carries the text and that no
// owner/app-identifying header (Referer, X-Title, custom SopsHQ User-Agent) is
// sent.
func TestSendWebhookShape(t *testing.T) {
	const text = "SopsHQ: drift detected"
	var (
		gotReferer, gotXTitle, gotUA, gotCT string
		payload                             map[string]string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReferer = r.Header.Get("Referer")
		gotXTitle = r.Header.Get("X-Title")
		gotUA = r.Header.Get("User-Agent")
		gotCT = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := SendWebhook(srv.URL, text); err != nil {
		t.Fatalf("SendWebhook: %v", err)
	}
	if payload["text"] != text {
		t.Errorf("body text = %q, want %q", payload["text"], text)
	}
	if len(payload) != 1 {
		t.Errorf("body should carry only {text}, got %v", payload)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if gotReferer != "" {
		t.Errorf("Referer should be absent, got %q", gotReferer)
	}
	if gotXTitle != "" {
		t.Errorf("X-Title should be absent, got %q", gotXTitle)
	}
	if strings.Contains(strings.ToLower(gotUA), "sopshq") {
		t.Errorf("User-Agent must not identify the app, got %q", gotUA)
	}
}

// TestSendWebhookErrorHidesURL verifies a non-2xx response yields an error that
// does not echo the secret webhook URL.
func TestSendWebhookErrorHidesURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := SendWebhook(srv.URL, "hi")
	if err == nil {
		t.Fatal("expected an error on a non-200 response")
	}
	if strings.Contains(err.Error(), srv.URL) {
		t.Fatalf("error leaked the webhook URL: %v", err)
	}
}
