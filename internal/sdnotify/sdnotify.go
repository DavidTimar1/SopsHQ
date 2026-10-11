// Package sdnotify implements the tiny slice of the systemd sd_notify protocol
// SopsHQ needs to tell systemd it has started, using the standard library only
// (no third-party module).
//
// systemd's "notify" service type expects the service to open the datagram socket
// named in the NOTIFY_SOCKET environment variable and send a newline-separated set
// of "VAR=value" lines. "READY=1" tells systemd the unit is up (so `systemctl start`
// returns); "STATUS=<text>" sets the short line `systemctl status` shows. SopsHQ
// reports "locked" (with the unlock hint) while it waits for the vault key, then
// "unlocked" once the operator has unlocked it.
//
// When NOTIFY_SOCKET is unset - the process is not running under a Type=notify unit,
// or NotifyAccess forbids it - every call is a harmless no-op, so the same code runs
// unchanged in the foreground and under systemd.
package sdnotify

import (
	"net"
	"os"
	"strings"
)

// Notifier sends readiness and status updates to systemd over the NOTIFY_SOCKET
// datagram socket. The zero value (and a nil pointer) is a safe no-op.
type Notifier struct {
	// socket is the NOTIFY_SOCKET path. Empty means "not under systemd": all sends
	// are no-ops.
	socket string
}

// New reads NOTIFY_SOCKET from the environment and returns a Notifier bound to it.
// With no NOTIFY_SOCKET set, the returned Notifier's methods do nothing.
func New() *Notifier {
	return &Notifier{socket: os.Getenv("NOTIFY_SOCKET")}
}

// Ready tells systemd the unit is up (READY=1) and sets its status line. Call it once
// the service is listening. A blank status sends READY=1 alone.
func (n *Notifier) Ready(status string) error {
	return n.send(readyPayload(status))
}

// SetStatus updates only the status line systemd shows (STATUS=...), without changing
// readiness. Use it to move from "locked" to "unlocked".
func (n *Notifier) SetStatus(status string) error {
	return n.send(statusPayload(status))
}

// send delivers one sd_notify datagram to NOTIFY_SOCKET. It is a no-op when no socket
// is configured. A leading "@" in the path selects the Linux abstract namespace
// (encoded as a leading NUL byte), which is how systemd names its notify socket.
func (n *Notifier) send(payload string) error {
	if n == nil || n.socket == "" {
		return nil
	}
	name := n.socket
	if strings.HasPrefix(name, "@") {
		name = "\x00" + name[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(payload))
	return err
}

// readyPayload builds the sd_notify body for a readiness notification: "READY=1",
// optionally followed by a "STATUS=<status>" line. It is pure so the wire format is
// unit-tested directly.
func readyPayload(status string) string {
	if status == "" {
		return "READY=1"
	}
	return "READY=1\nSTATUS=" + status
}

// statusPayload builds the sd_notify body for a status-only update ("STATUS=<status>").
// It is pure so the wire format is unit-tested directly.
func statusPayload(status string) string {
	return "STATUS=" + status
}
