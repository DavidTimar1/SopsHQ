package backup

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalSinkStore(t *testing.T) {
	dir := t.TempDir()
	s := LocalSink{Folder: filepath.Join(dir, "drop")}
	data := []byte("sealed-archive-bytes")
	if err := s.Store("backup.bin", data); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "drop", "backup.bin"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("stored file = %q err=%v", got, err)
	}
	// No temp file should survive the atomic write.
	if _, err := os.Stat(filepath.Join(dir, "drop", "backup.bin.tmp")); !os.IsNotExist(err) {
		t.Fatal("temp file left behind after atomic write")
	}
}

func TestTelegramSinkMultipartAndNoIdentifyingHeaders(t *testing.T) {
	type capture struct {
		chatID   string
		fileName string
		fileBody []byte
		referer  string
		xTitle   string
		ua       string
		path     string
	}
	got := make(chan capture, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := capture{
			referer: r.Header.Get("Referer"),
			xTitle:  r.Header.Get("X-Title"),
			ua:      r.Header.Get("User-Agent"),
			path:    r.URL.Path,
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		c.chatID = r.FormValue("chat_id")
		f, hdr, err := r.FormFile("document")
		if err != nil {
			http.Error(w, "no document", http.StatusBadRequest)
			return
		}
		defer f.Close()
		c.fileName = hdr.Filename
		c.fileBody, _ = io.ReadAll(f)
		got <- c
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	s := TelegramSink{Token: "secret-token-123", ChatID: "-100123", baseURL: srv.URL}
	data := []byte("sealed-archive-bytes")
	if err := s.Store("backup.bin", data); err != nil {
		t.Fatalf("Store: %v", err)
	}

	select {
	case c := <-got:
		if c.chatID != "-100123" {
			t.Errorf("chat_id = %q, want -100123", c.chatID)
		}
		if c.fileName != "backup.bin" {
			t.Errorf("document filename = %q, want backup.bin", c.fileName)
		}
		if !bytes.Equal(c.fileBody, data) {
			t.Errorf("document body mismatch")
		}
		if !strings.Contains(c.path, "/botsecret-token-123/sendDocument") {
			t.Errorf("request path = %q, want bot token + sendDocument", c.path)
		}
		// No owner/app-identifying metadata.
		if c.referer != "" {
			t.Errorf("Referer header leaked: %q", c.referer)
		}
		if c.xTitle != "" {
			t.Errorf("X-Title header leaked: %q", c.xTitle)
		}
		if strings.Contains(strings.ToLower(c.ua), "sopshq") {
			t.Errorf("User-Agent leaks app identity: %q", c.ua)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never received the request")
	}
}

// ftpStub speaks just enough plain FTP to accept one STOR over PASV. It returns
// the host, control port, and a channel that yields the bytes received.
func ftpStub(t *testing.T) (host string, port int, received chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	received = make(chan []byte, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		write := func(s string) { conn.Write([]byte(s)) }
		write("220 stub ready\r\n")
		var dataLn net.Listener
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case strings.HasPrefix(line, "USER"):
				write("331 need password\r\n")
			case strings.HasPrefix(line, "PASS"):
				write("230 logged in\r\n")
			case strings.HasPrefix(line, "TYPE"):
				write("200 ok\r\n")
			case strings.HasPrefix(line, "PASV"):
				dataLn, err = net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					write("425 cannot open data\r\n")
					continue
				}
				p := dataLn.Addr().(*net.TCPAddr).Port
				write(fmt.Sprintf("227 Entering Passive Mode (127,0,0,1,%d,%d)\r\n", p/256, p%256))
			case strings.HasPrefix(line, "STOR"):
				write("150 ok to send\r\n")
				dc, err := dataLn.Accept()
				if err != nil {
					write("426 data error\r\n")
					continue
				}
				b, _ := io.ReadAll(dc)
				dc.Close()
				received <- b
				write("226 transfer complete\r\n")
			case strings.HasPrefix(line, "QUIT"):
				write("221 bye\r\n")
				return
			default:
				write("200 ok\r\n")
			}
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, received
}

func TestFTPSinkStore(t *testing.T) {
	host, port, received := ftpStub(t)
	s := FTPSink{Host: host, Port: port, User: "u", Pass: "p", FTPS: false}
	data := []byte("sealed-archive-bytes")
	if err := s.Store("backup.bin", data); err != nil {
		t.Fatalf("Store: %v", err)
	}
	select {
	case b := <-received:
		if !bytes.Equal(b, data) {
			t.Fatalf("FTP received %q, want %q", b, data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FTP stub never received the data")
	}
}

func TestParsePASVPort(t *testing.T) {
	tests := []struct {
		in   string
		want int
		ok   bool
	}{
		{"227 Entering Passive Mode (127,0,0,1,195,80)", 195*256 + 80, true},
		{"227 nonsense", 0, false},
		{"227 (1,2,3,4,5)", 0, false},
	}
	for _, tt := range tests {
		got, err := parsePASVPort(tt.in)
		if tt.ok && (err != nil || got != tt.want) {
			t.Errorf("parsePASVPort(%q) = %d, %v; want %d", tt.in, got, err, tt.want)
		}
		if !tt.ok && err == nil {
			t.Errorf("parsePASVPort(%q) expected error", tt.in)
		}
	}
}
