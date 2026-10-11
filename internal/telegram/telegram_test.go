package telegram

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSendMessageShape verifies the request the client builds: the bot path, the
// chat_id + text form fields, and the ABSENCE of any owner/app-identifying header
// (no Referer, X-Title, or custom SopsHQ User-Agent).
func TestSendMessageShape(t *testing.T) {
	const (
		token  = "secret-bot-token-123"
		chatID = "chat-99"
		text   = "SopsHQ: apply ok"
	)
	var (
		gotPath, gotReferer, gotXTitle, gotUA string
		gotChat, gotText                      string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotReferer = r.Header.Get("Referer")
		gotXTitle = r.Header.Get("X-Title")
		gotUA = r.Header.Get("User-Agent")
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		gotChat = r.PostFormValue("chat_id")
		gotText = r.PostFormValue("text")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := sendMessage(srv.URL, token, chatID, text); err != nil {
		t.Fatalf("sendMessage: %v", err)
	}
	if want := "/bot" + token + "/sendMessage"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if gotChat != chatID {
		t.Errorf("chat_id = %q, want %q", gotChat, chatID)
	}
	if gotText != text {
		t.Errorf("text = %q, want %q", gotText, text)
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

// TestSendMessageErrorHidesToken verifies a non-2xx response yields an error that
// does not echo the bot token.
func TestSendMessageErrorHidesToken(t *testing.T) {
	const token = "another-secret-token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	err := sendMessage(srv.URL, token, "chat", "hi")
	if err == nil {
		t.Fatal("expected an error on a non-200 response")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("error leaked the bot token: %v", err)
	}
}
