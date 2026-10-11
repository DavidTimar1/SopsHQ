package unlock

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestProtocolEncodeDecode covers the wire format: requests and both reply shapes must
// round-trip through JSON with their expected field names.
func TestProtocolEncodeDecode(t *testing.T) {
	t.Run("unlock request", func(t *testing.T) {
		b, err := json.Marshal(Request{Cmd: CmdUnlock, Key: "s3cret"})
		if err != nil {
			t.Fatal(err)
		}
		if got := string(b); got != `{"cmd":"unlock","key":"s3cret"}` {
			t.Fatalf("encoded = %s", got)
		}
		var r Request
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		if r.Cmd != CmdUnlock || r.Key != "s3cret" {
			t.Fatalf("decoded = %+v", r)
		}
	})
	t.Run("status request omits key", func(t *testing.T) {
		b, _ := json.Marshal(Request{Cmd: CmdStatus})
		if got := string(b); got != `{"cmd":"status"}` {
			t.Fatalf("encoded = %s", got)
		}
	})
	t.Run("unlock reply", func(t *testing.T) {
		var ok UnlockReply
		if err := json.Unmarshal([]byte(`{"ok":true}`), &ok); err != nil || !ok.OK {
			t.Fatalf("ok reply: %+v err=%v", ok, err)
		}
		var bad UnlockReply
		if err := json.Unmarshal([]byte(`{"ok":false,"error":"wrong vault key"}`), &bad); err != nil {
			t.Fatal(err)
		}
		if bad.OK || bad.Error != "wrong vault key" {
			t.Fatalf("bad reply: %+v", bad)
		}
	})
	t.Run("status reply", func(t *testing.T) {
		var st StatusReply
		if err := json.Unmarshal([]byte(`{"locked":false,"url":"http://127.0.0.1:8770/"}`), &st); err != nil {
			t.Fatal(err)
		}
		if st.Locked || st.URL != "http://127.0.0.1:8770/" {
			t.Fatalf("status reply: %+v", st)
		}
		if st.Version != "" {
			t.Fatalf("a reply with no version field decoded Version = %q, want empty (unknown)", st.Version)
		}
	})
	t.Run("status reply with version", func(t *testing.T) {
		var st StatusReply
		if err := json.Unmarshal([]byte(`{"locked":true,"url":"","data_dir":"/d","version":"0.83.0"}`), &st); err != nil {
			t.Fatal(err)
		}
		if st.Version != "0.83.0" {
			t.Fatalf("status reply: %+v", st)
		}
	})
	t.Run("an older client decoder ignores the version field", func(t *testing.T) {
		// The decoder shipped before Version existed: same shape minus the field.
		var old struct {
			Locked  bool   `json:"locked"`
			URL     string `json:"url"`
			DataDir string `json:"data_dir"`
		}
		b, err := json.Marshal(StatusReply{Locked: true, DataDir: "/d", Version: "0.83.0"})
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &old); err != nil {
			t.Fatalf("older decoder failed on a reply carrying version: %v", err)
		}
		if !old.Locked || old.DataDir != "/d" {
			t.Fatalf("older decoder read %+v", old)
		}
	})
}

// TestStatusReportsVersion confirms a server reports the version it was given, over a
// real socket, both while locked and after unlock.
func TestStatusReportsVersion(t *testing.T) {
	srv, sock := startTestServer(t, "k")
	srv.SetVersion("0.83.0")
	st, err := Status(sock)
	if err != nil || st.Version != "0.83.0" {
		t.Fatalf("status = %+v err=%v, want version 0.83.0", st, err)
	}
	if rep, err := Unlock(sock, "k"); err != nil || !rep.OK {
		t.Fatalf("unlock = %+v err=%v", rep, err)
	}
	if st, err := Status(sock); err != nil || st.Version != "0.83.0" {
		t.Fatalf("status after unlock = %+v err=%v, want version 0.83.0", st, err)
	}
}

// startTestServer opens a listener in a temp dir with a stub unlock callback that
// accepts only the given key, and runs its accept loop until the test ends.
func startTestServer(t *testing.T, rightKey string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "unlock.sock")
	srv, err := Listen(sock)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	go srv.Serve(func(key string) error {
		if key == rightKey {
			return nil
		}
		return errors.New("wrong vault key")
	})
	return srv, sock
}

// TestUnlockFlow drives the full loop over a real unix socket with a stub "try key":
// wrong key stays locked, a retry with the right key unlocks, and status reflects each
// step.
func TestUnlockFlow(t *testing.T) {
	srv, sock := startTestServer(t, "correct-horse")

	// Socket file must be owner-only (0600). Unix permission bits do not map onto
	// Windows (Stat reports a synthetic mode there), so the assertion is meaningful
	// on Unix hosts only; the rest of the flow runs on every OS.
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(sock)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("socket perm = %o, want 600", perm)
		}
	}

	if st, err := Status(sock); err != nil || !st.Locked || st.URL != "" {
		t.Fatalf("initial status = %+v err=%v, want locked, no url", st, err)
	}

	// Wrong key -> failure, still locked.
	rep, err := Unlock(sock, "nope")
	if err != nil {
		t.Fatalf("Unlock(wrong): %v", err)
	}
	if rep.OK || rep.Error == "" {
		t.Fatalf("wrong key reply = %+v, want ok=false with an error", rep)
	}
	if st, _ := Status(sock); !st.Locked {
		t.Fatalf("after wrong key status = %+v, want still locked", st)
	}
	select {
	case <-srv.Unlocked():
		t.Fatal("Unlocked() closed after a wrong key")
	default:
	}

	// Right key -> success, transitions to unlocked.
	rep, err = Unlock(sock, "correct-horse")
	if err != nil {
		t.Fatalf("Unlock(right): %v", err)
	}
	if !rep.OK {
		t.Fatalf("right key reply = %+v, want ok=true", rep)
	}
	select {
	case <-srv.Unlocked():
	case <-time.After(time.Second):
		t.Fatal("Unlocked() did not close after the right key")
	}

	// Publish a URL as the real service does, then status must report unlocked + URL.
	srv.SetPanelURL("http://127.0.0.1:8770/")
	st, err := Status(sock)
	if err != nil {
		t.Fatal(err)
	}
	if st.Locked || st.URL != "http://127.0.0.1:8770/" {
		t.Fatalf("final status = %+v, want unlocked with url", st)
	}

	// A second unlock after already unlocked is a no-op success.
	if rep, err := Unlock(sock, "anything"); err != nil || !rep.OK {
		t.Fatalf("second unlock = %+v err=%v, want ok", rep, err)
	}
}

// TestMissingSocket verifies the client reports ErrNotRunning when no socket exists, so
// the command can print a clear "not running" message.
func TestMissingSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "unlock.sock")
	if _, err := Status(sock); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Status(missing) err = %v, want ErrNotRunning", err)
	}
	if _, err := Unlock(sock, "x"); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Unlock(missing) err = %v, want ErrNotRunning", err)
	}
}

// TestListenRefusesLiveSocket confirms a second Listen on the same path fails while the
// first server is still accepting (so two services never share the socket).
func TestListenRefusesLiveSocket(t *testing.T) {
	_, sock := startTestServer(t, "k")
	if _, err := Listen(sock); err == nil {
		t.Fatal("second Listen on a live socket succeeded, want error")
	}
}

// TestStatusCapsAnOversizedReply confirms a client does not buffer an endless reply.
func TestStatusCapsAnOversizedReply(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "unlock.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1<<20)
		for i := range buf {
			buf[i] = 'a'
		}
		conn.Write(buf) // a megabyte with no newline
	}()
	done := make(chan error, 1)
	go func() { _, err := Status(sock); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("an oversized, newline-free reply was accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Status did not return on an oversized reply")
	}
}
