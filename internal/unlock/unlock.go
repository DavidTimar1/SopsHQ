// Package unlock delivers the vault key to a running-but-locked SopsHQ over a
// private unix-domain socket, using the standard library only.
//
// The problem it solves: when systemd starts `sopshq serve` as the unprivileged
// service account there is no terminal to type the vault key on, and the vault must
// NEVER auto-unlock. So serve starts LOCKED - it opens this socket, tells systemd it
// is up, and serves nothing else - and the operator runs `sopshq unlock` to hand the
// vault key across the socket. serve validates the key, unlocks the vault in memory,
// and only then brings up the panel and agent.
//
// The wire protocol is minimal and ASCII: one JSON object per line, in each direction.
//   - request  {"cmd":"unlock","key":"..."}  -> reply {"ok":true} or {"ok":false,"error":"..."}
//   - request  {"cmd":"status"}              -> reply {"locked":true|false,"url":"...","data_dir":"...","version":"..."}
//
// SECURITY: the vault key travels this socket. It is NEVER logged, echoed, or placed
// in a reply or error. The socket lives inside a 0700 runtime directory owned by the
// service account (only root and that account can reach it) and is itself created
// 0600. The key is only ever passed to the injected unlock callback and then dropped.
package unlock

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"sync"
	"time"
)

// Command names carried in a Request.Cmd. They are the only two verbs the socket
// understands; any other command is answered with an error reply.
const (
	CmdUnlock = "unlock"
	CmdStatus = "status"
)

// Request is one client -> server message. Key is only meaningful for CmdUnlock and
// carries the operator's vault key; it is never logged or echoed anywhere.
type Request struct {
	Cmd string `json:"cmd"`
	Key string `json:"key,omitempty"`
}

// UnlockReply answers a CmdUnlock request. Error is a short, non-secret message on
// failure (for example a wrong key); it never contains the key.
type UnlockReply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// StatusReply answers a CmdStatus request. URL is the panel's base URL once the
// listeners are up, or empty while the vault is still locked. DataDir is the data
// directory this running serve is bound to, so `sopshq unlock` can refuse to hand the
// vault key to a STALE process whose data path no longer matches the current install.
// Version is the release version of the running binary, so `sopshq update` can prove the
// new build is the one answering; a serve built before the field existed omits it, and a
// client reads the empty string as "version unknown".
type StatusReply struct {
	Locked  bool   `json:"locked"`
	URL     string `json:"url"`
	DataDir string `json:"data_dir"`
	Version string `json:"version,omitempty"`
}

// ErrNotRunning means no SopsHQ is listening at the socket path (the file is absent,
// or nothing accepts on it). The unlock/status commands turn it into a clear
// "SopsHQ is not running" message for the operator.
var ErrNotRunning = errors.New("no unlock socket (SopsHQ is not running)")

// maxReplyBytes caps how much of a reply a client reads, so whatever answers on the socket
// cannot make `sopshq update` or `sopshq unlock` buffer without limit.
const maxReplyBytes = 64 << 10

// serverReadDeadline bounds how long a single client connection may take, so a stuck
// client cannot pin the (sequential) accept loop. It comfortably exceeds the vault
// key-derivation time.
const serverReadDeadline = 2 * time.Minute

// Server accepts unlock and status requests on a unix socket. It starts LOCKED; the
// first successful unlock (the injected callback returning nil) flips it to unlocked
// and closes the Unlocked channel, and its status replies then report the panel URL.
type Server struct {
	ln       net.Listener
	onUnlock func(key string) error

	mu      sync.Mutex
	locked  bool
	url     string
	dataDir string
	version string

	unlockedCh   chan struct{}
	unlockedOnce sync.Once
}

// Listen creates the unix socket at path (0600, inside its caller-provided 0700
// runtime directory) and returns a locked Server ready to Serve. A stale socket file
// left by a dead process is removed first; a socket a LIVE process is still using is
// refused. The caller must Close the Server to remove the socket.
func Listen(path string) (*Server, error) {
	if _, err := os.Stat(path); err == nil {
		// A socket file already exists. If something is still accepting on it, another
		// SopsHQ is running - refuse. Otherwise it is stale; remove it and take over.
		if c, derr := net.DialTimeout("unix", path, 200*time.Millisecond); derr == nil {
			c.Close()
			return nil, fmt.Errorf("another SopsHQ is already listening at %s", path)
		}
		if rerr := os.Remove(path); rerr != nil {
			return nil, fmt.Errorf("remove stale socket %s: %w", path, rerr)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", path, err)
	}
	// The 0700 runtime directory is the real access boundary; tighten the socket to
	// 0600 as defence in depth so only the owner can connect even if the directory
	// perms were ever loosened.
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chmod socket %s: %w", path, err)
	}
	return &Server{ln: ln, locked: true, unlockedCh: make(chan struct{})}, nil
}

// Unlocked returns a channel that is closed once the vault has been unlocked through
// the socket. The caller waits on it to know when to boot the panel.
func (s *Server) Unlocked() <-chan struct{} { return s.unlockedCh }

// SetPanelURL records the panel's base URL so later status replies report where the
// panel is. Call it once the listener address is resolved.
func (s *Server) SetPanelURL(url string) {
	s.mu.Lock()
	s.url = url
	s.mu.Unlock()
}

// SetDataDir records the data directory this serve is bound to, so status replies carry
// it and `sopshq unlock` can detect a stale process on an old data path. Call it once
// after Listen, before Serve.
func (s *Server) SetDataDir(dir string) {
	s.mu.Lock()
	s.dataDir = dir
	s.mu.Unlock()
}

// SetVersion records the running binary's release version, so status replies carry it.
// Call it once after Listen, before Serve.
func (s *Server) SetVersion(v string) {
	s.mu.Lock()
	s.version = v
	s.mu.Unlock()
}

// Close stops accepting and removes the socket file.
func (s *Server) Close() error { return s.ln.Close() }

// Serve accepts connections until the listener is closed, handling one request per
// connection. onUnlock is called with the operator-supplied vault key on an unlock
// request; returning nil marks the vault unlocked. Connections are handled
// sequentially so two unlock attempts never race the vault. The key is never logged.
func (s *Server) Serve(onUnlock func(key string) error) {
	s.onUnlock = onUnlock
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		s.handle(conn)
	}
}

// handle reads one request line and writes one reply. It never logs the request.
func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(serverReadDeadline))
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req Request
	if jerr := json.Unmarshal(line, &req); jerr != nil {
		_ = writeJSON(conn, UnlockReply{OK: false, Error: "malformed request"})
		return
	}
	switch req.Cmd {
	case CmdUnlock:
		s.doUnlock(conn, req.Key)
	case CmdStatus:
		s.doStatus(conn)
	default:
		_ = writeJSON(conn, UnlockReply{OK: false, Error: "unknown command"})
	}
	// Drop our reference to the key. Go strings are immutable, so the underlying
	// bytes cannot be zeroed here; the value is confined to this call and never
	// copied into a log, reply, or long-lived field.
	req.Key = ""
}

// doUnlock tries the injected unlock callback with the supplied key. Once unlocked it
// is a no-op that reports success. A failure keeps the server locked so the operator
// can retry. Neither the key nor a key-derived value ever reaches the reply.
func (s *Server) doUnlock(conn net.Conn, key string) {
	s.mu.Lock()
	already := !s.locked
	s.mu.Unlock()
	if already {
		_ = writeJSON(conn, UnlockReply{OK: true})
		return
	}
	if err := s.onUnlock(key); err != nil {
		_ = writeJSON(conn, UnlockReply{OK: false, Error: unlockErrorMessage(err)})
		return
	}
	s.mu.Lock()
	s.locked = false
	s.mu.Unlock()
	s.unlockedOnce.Do(func() { close(s.unlockedCh) })
	_ = writeJSON(conn, UnlockReply{OK: true})
}

// doStatus reports whether the vault is still locked and the panel URL if known.
func (s *Server) doStatus(conn net.Conn) {
	s.mu.Lock()
	rep := StatusReply{Locked: s.locked, URL: s.url, DataDir: s.dataDir, Version: s.version}
	s.mu.Unlock()
	_ = writeJSON(conn, rep)
}

// unlockErrorMessage turns an unlock-callback error into a short, non-secret message
// for the reply. It never includes the key.
func unlockErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// writeJSON encodes v as a single JSON line (with trailing newline) to w.
func writeJSON(w net.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// Unlock connects to the socket at path, sends the vault key, and returns the reply.
// It returns ErrNotRunning when nothing is listening. The key is written straight to
// the socket and never logged.
func Unlock(path, key string) (UnlockReply, error) {
	var rep UnlockReply
	err := roundTrip(path, Request{Cmd: CmdUnlock, Key: key}, &rep)
	return rep, err
}

// Status connects to the socket at path and returns the current lock state and panel
// URL. It returns ErrNotRunning when nothing is listening.
func Status(path string) (StatusReply, error) {
	var rep StatusReply
	err := roundTrip(path, Request{Cmd: CmdStatus}, &rep)
	return rep, err
}

// roundTrip dials the socket, writes one request line, and decodes one reply line. A
// missing socket (or nothing accepting) is reported as ErrNotRunning.
func roundTrip(path string, req Request, reply any) error {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotRunning
		}
		return err
	}
	conn, err := net.DialTimeout("unix", path, 3*time.Second)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotRunning, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(serverReadDeadline))
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := conn.Write(b); err != nil {
		return err
	}
	line, err := bufio.NewReader(io.LimitReader(conn, maxReplyBytes)).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return fmt.Errorf("no reply from SopsHQ: %w", err)
	}
	return json.Unmarshal(line, reply)
}
