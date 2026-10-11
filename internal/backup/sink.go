package backup

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Sink is one destination a sealed backup blob can be sent to. Label names the
// destination for audit/status (by name only, never a credential); Store delivers
// the bytes.
type Sink interface {
	Label() string
	Store(filename string, data []byte) error
}

// SinkResult records one destination's outcome for a backup run. Err holds a
// human-readable, credential-free message when OK is false.
type SinkResult struct {
	Label string
	OK    bool
	Err   string
}

// RunResult summarizes a backup run: the archive name and size, and the
// per-destination outcomes.
type RunResult struct {
	Filename string
	Size     int
	Sinks    []SinkResult
}

// Run builds the sealed archive once and stores it to every sink. A failing sink
// is recorded in its SinkResult but does not abort the others. The returned error
// is non-nil only when the archive itself could not be built.
func Run(dataDir, configPath, key, filename string, sinks []Sink) (RunResult, error) {
	blob, err := Build(dataDir, configPath, key)
	if err != nil {
		return RunResult{}, err
	}
	res := RunResult{Filename: filename, Size: len(blob)}
	for _, sk := range sinks {
		r := SinkResult{Label: sk.Label(), OK: true}
		if err := sk.Store(filename, blob); err != nil {
			r.OK = false
			r.Err = err.Error()
		}
		res.Sinks = append(res.Sinks, r)
	}
	return res, nil
}

// LocalSink drops the archive into a folder on this machine.
type LocalSink struct {
	Folder string
}

// Label identifies the destination by its folder.
func (s LocalSink) Label() string { return "local:" + s.Folder }

// Store writes the archive atomically (temp + rename, 0600) into the folder.
func (s LocalSink) Store(filename string, data []byte) error {
	if err := os.MkdirAll(s.Folder, 0o700); err != nil {
		return fmt.Errorf("local sink: mkdir: %w", err)
	}
	dest := filepath.Join(s.Folder, filename)
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("local sink: write: %w", err)
	}
	return os.Rename(tmp, dest)
}

// TelegramSink uploads the archive as a document to a Telegram chat/channel via
// the Bot API. The bot token is a secret and is never logged or placed in an
// error message.
type TelegramSink struct {
	Token  string
	ChatID string
	// baseURL overrides the Bot API host in tests; empty means the real API.
	baseURL string
}

// Label identifies the destination by its chat id (never the token).
func (s TelegramSink) Label() string { return "telegram:" + s.ChatID }

// Store POSTs a sendDocument multipart request: a "chat_id" field and a
// "document" file part. It sends only the credential (in the URL path) and the
// payload - no owner/app-identifying headers (no Referer, X-Title, or custom
// User-Agent).
func (s TelegramSink) Store(filename string, data []byte) error {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("chat_id", s.ChatID); err != nil {
		return fmt.Errorf("telegram sink: form field: %w", err)
	}
	fw, err := mw.CreateFormFile("document", filename)
	if err != nil {
		return fmt.Errorf("telegram sink: form file: %w", err)
	}
	if _, err := fw.Write(data); err != nil {
		return fmt.Errorf("telegram sink: form write: %w", err)
	}
	if err := mw.Close(); err != nil {
		return fmt.Errorf("telegram sink: form close: %w", err)
	}

	base := s.baseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	// The token lives in the URL path; build the request without ever logging it.
	req, err := http.NewRequest(http.MethodPost, base+"/bot"+s.Token+"/sendDocument", &body)
	if err != nil {
		// Do not wrap err: it would echo the token-bearing URL.
		return errors.New("telegram sink: could not build request")
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// Do not wrap err: it would echo the token-bearing URL.
		return errors.New("telegram sink: request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram sink: server returned status %d", resp.StatusCode)
	}
	return nil
}

// FTPSink uploads the archive over FTP, or explicit FTPS (AUTH TLS) when FTPS is
// set. Credentials (User/Pass) are never logged or placed in an error message.
type FTPSink struct {
	Host string
	Port int
	User string
	Pass string
	Dir  string
	FTPS bool
}

// Label identifies the destination by its host (never the credentials).
func (s FTPSink) Label() string { return "ftp:" + s.Host }

// Store performs a minimal STOR over a passive (PASV) data connection: read the
// greeting, optionally AUTH TLS and wrap in TLS, log in, set binary type, change
// directory, open PASV, and stream the bytes.
func (s FTPSink) Store(filename string, data []byte) error {
	port := s.Port
	if port == 0 {
		port = 21
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(s.Host, strconv.Itoa(port)), 30*time.Second)
	if err != nil {
		return errors.New("ftp sink: connect failed")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))

	f := newFTPConn(conn)
	if code, _, err := f.readResponse(); err != nil || !is2xx(code) {
		return errors.New("ftp sink: bad greeting")
	}

	var tlsConf *tls.Config
	if s.FTPS {
		if code, _, err := f.cmd("AUTH TLS"); err != nil || code != 234 {
			return errors.New("ftp sink: AUTH TLS rejected")
		}
		tlsConf = &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}
		tconn := tls.Client(conn, tlsConf)
		if err := tconn.Handshake(); err != nil {
			return errors.New("ftp sink: TLS handshake failed")
		}
		conn = tconn
		_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
		f = newFTPConn(conn)
	}

	// Login. The command lines carry the credentials but are never logged.
	if code, _, err := f.cmd("USER " + s.User); err != nil || (code != 331 && code != 230) {
		return errors.New("ftp sink: USER rejected")
	}
	if code, _, err := f.cmd("PASS " + s.Pass); err != nil || !is2xx(code) {
		return errors.New("ftp sink: login failed")
	}

	if s.FTPS {
		// Protect the data channel too.
		_, _, _ = f.cmd("PBSZ 0")
		_, _, _ = f.cmd("PROT P")
	}

	if code, _, err := f.cmd("TYPE I"); err != nil || !is2xx(code) {
		return errors.New("ftp sink: binary mode failed")
	}
	if s.Dir != "" {
		if code, _, err := f.cmd("CWD " + s.Dir); err != nil || !is2xx(code) {
			return errors.New("ftp sink: change directory failed")
		}
	}

	code, msg, err := f.cmd("PASV")
	if err != nil || code != 227 {
		return errors.New("ftp sink: PASV failed")
	}
	dataPort, err := parsePASVPort(msg)
	if err != nil {
		return err
	}
	// Connect to the control host on the advertised data port (robust behind NAT).
	dataConn, err := net.DialTimeout("tcp", net.JoinHostPort(s.Host, strconv.Itoa(dataPort)), 30*time.Second)
	if err != nil {
		return errors.New("ftp sink: data connect failed")
	}
	defer func() { _ = dataConn.Close() }()
	if s.FTPS {
		dtls := tls.Client(dataConn, tlsConf)
		if err := dtls.Handshake(); err != nil {
			return errors.New("ftp sink: data TLS handshake failed")
		}
		dataConn = dtls
	}
	_ = dataConn.SetDeadline(time.Now().Add(5 * time.Minute))

	if code, _, err := f.cmd("STOR " + filename); err != nil || (code != 150 && code != 125) {
		return errors.New("ftp sink: STOR rejected")
	}
	if _, err := dataConn.Write(data); err != nil {
		return errors.New("ftp sink: data write failed")
	}
	// Close the data connection to signal end-of-file, then read the transfer ack.
	if err := dataConn.Close(); err != nil {
		return errors.New("ftp sink: data close failed")
	}
	if code, _, err := f.readResponse(); err != nil || !is2xx(code) {
		return errors.New("ftp sink: transfer not confirmed")
	}
	_, _, _ = f.cmd("QUIT")
	return nil
}

// ftpConn is a minimal FTP control connection: it writes commands and reads
// (possibly multi-line) responses.
type ftpConn struct {
	conn net.Conn
	r    *bufio.Reader
}

func newFTPConn(conn net.Conn) *ftpConn {
	return &ftpConn{conn: conn, r: bufio.NewReader(conn)}
}

// cmd sends one command line (CRLF-terminated) and returns the response code,
// the first response line, and any I/O error.
func (f *ftpConn) cmd(line string) (int, string, error) {
	if _, err := f.conn.Write([]byte(line + "\r\n")); err != nil {
		return 0, "", err
	}
	return f.readResponse()
}

// readResponse reads a full FTP reply. A multi-line reply starts "NNN-" and ends
// at a line beginning "NNN " (same code, a space).
func (f *ftpConn) readResponse() (int, string, error) {
	line, err := f.r.ReadString('\n')
	if err != nil {
		return 0, "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) < 4 {
		return 0, "", errors.New("ftp sink: short response")
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0, "", errors.New("ftp sink: bad response code")
	}
	if line[3] == '-' {
		end := line[:3] + " "
		for {
			l, err := f.r.ReadString('\n')
			if err != nil {
				return 0, "", err
			}
			if strings.HasPrefix(strings.TrimRight(l, "\r\n"), end) {
				break
			}
		}
	}
	return code, line, nil
}

// parsePASVPort extracts the data port from a 227 PASV reply of the form
// "227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)".
func parsePASVPort(msg string) (int, error) {
	open := strings.IndexByte(msg, '(')
	shut := strings.IndexByte(msg, ')')
	if open < 0 || shut < 0 || shut < open {
		return 0, errors.New("ftp sink: malformed PASV response")
	}
	parts := strings.Split(msg[open+1:shut], ",")
	if len(parts) != 6 {
		return 0, errors.New("ftp sink: malformed PASV response")
	}
	hi, err1 := strconv.Atoi(strings.TrimSpace(parts[4]))
	lo, err2 := strconv.Atoi(strings.TrimSpace(parts[5]))
	if err1 != nil || err2 != nil {
		return 0, errors.New("ftp sink: malformed PASV port")
	}
	return hi*256 + lo, nil
}

func is2xx(code int) bool { return code >= 200 && code < 300 }
