package sdnotify

import (
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestReadyPayload checks the sd_notify readiness wire format: READY=1 alone, or
// followed by a STATUS line.
func TestReadyPayload(t *testing.T) {
	if got := readyPayload(""); got != "READY=1" {
		t.Fatalf("readyPayload(empty) = %q", got)
	}
	got := readyPayload("locked; run: sudo sopshq unlock")
	want := "READY=1\nSTATUS=locked; run: sudo sopshq unlock"
	if got != want {
		t.Fatalf("readyPayload = %q, want %q", got, want)
	}
}

// TestStatusPayload checks the status-only wire format.
func TestStatusPayload(t *testing.T) {
	if got := statusPayload("unlocked"); got != "STATUS=unlocked" {
		t.Fatalf("statusPayload = %q", got)
	}
}

// TestSendNoSocket verifies that with no NOTIFY_SOCKET the sends are harmless no-ops.
func TestSendNoSocket(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	n := New()
	if err := n.Ready("locked"); err != nil {
		t.Fatalf("Ready with no socket = %v, want nil", err)
	}
	if err := n.SetStatus("unlocked"); err != nil {
		t.Fatalf("SetStatus with no socket = %v, want nil", err)
	}
}

// TestSendDelivers stands up a real unixgram socket, points NOTIFY_SOCKET at it, and
// confirms Ready delivers exactly the readiness datagram.
func TestSendDelivers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sd_notify is a systemd (Linux) protocol; Windows has no AF_UNIX datagram sockets")
	}
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "notify.sock")
	addr := &net.UnixAddr{Name: sockPath, Net: "unixgram"}
	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatalf("ListenUnixgram: %v", err)
	}
	defer conn.Close()

	t.Setenv("NOTIFY_SOCKET", sockPath)
	if err := New().Ready("locked; run: sudo sopshq unlock"); err != nil {
		t.Fatalf("Ready: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _, err := conn.ReadFromUnix(buf)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	got := string(buf[:n])
	want := "READY=1\nSTATUS=locked; run: sudo sopshq unlock"
	if got != want {
		t.Fatalf("datagram = %q, want %q", got, want)
	}
}
