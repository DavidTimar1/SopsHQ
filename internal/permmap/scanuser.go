package permmap

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// ScanUserStatus reports whether the dedicated scan user is provisioned and
// usable. The permission auditor runs the read-only collectors as this user via
// sudo, so all four facts must hold before the feature can be enabled.
type ScanUserStatus struct {
	// Platform is true on Linux. The auditor is Linux-only; off Linux every other
	// field is false and Detail explains why.
	Platform bool
	// UserExists is true when the named account exists (`id <user>` succeeds).
	UserExists bool
	// SudoOK is true when this process can run a collector as the scan user without
	// a password prompt (`sudo -n -u <user> getfacl --version` succeeds).
	SudoOK bool
	// Usable is the overall verdict: Platform AND UserExists AND SudoOK. Enabling
	// the feature is refused unless this is true.
	Usable bool
	// Detail is a short, non-secret, ASCII explanation for the panel to show.
	Detail string
}

// CheckScanUser inspects the named scan user on this machine. It is read-only and
// never changes any account. Off Linux it returns a not-available status so the
// panel can show "Linux only" without shelling out. An empty user name is treated
// as unusable (the operator must name the dedicated account).
func CheckScanUser(user string) ScanUserStatus {
	st := ScanUserStatus{}
	if runtime.GOOS != "linux" {
		st.Detail = "The permission auditor runs the Linux collectors (find/getfacl/getcap) and is only available when SopsHQ runs on Linux."
		return st
	}
	st.Platform = true
	user = strings.TrimSpace(user)
	if user == "" {
		st.Detail = "No scan user is configured. Choose a dedicated, locked-down Linux user for the scan."
		return st
	}
	if err := exec.Command("id", user).Run(); err != nil {
		st.Detail = fmt.Sprintf("The scan user %q does not exist yet. Create it with the commands below, then re-check.", user)
		return st
	}
	st.UserExists = true
	// Probe that we can run a collector as the scan user without prompting. getfacl
	// --version is harmless and touches no scanned path. -n makes sudo fail fast
	// (no password prompt) when the sudoers rule is missing.
	if err := exec.Command("sudo", "-n", "-u", user, "getfacl", "--version").Run(); err != nil {
		st.Detail = fmt.Sprintf("The scan user %q exists, but this process cannot run the collectors as that user via sudo. Add the sudoers rule below, then re-check.", user)
		return st
	}
	st.SudoOK = true
	st.Usable = true
	st.Detail = fmt.Sprintf("The scan user %q exists and can run the collectors. The auditor is ready to enable.", user)
	return st
}

// EnableInstructions returns the exact, copy-pasteable operator commands to
// provision the dedicated scan user and its tight sudoers rule for the given
// roots. The text is plain ASCII so it renders identically everywhere and is safe
// to print. It is a pure function (no I/O), so the panel can show it on any
// platform, including before the user exists.
//
// The provisioned account has no login shell and no password (no interactive
// login, no SSH), and the sudoers rule permits ONLY the three read-only
// collectors, run without a password, and nothing else.
func EnableInstructions(user string, roots []string) string {
	user = strings.TrimSpace(user)
	if user == "" {
		user = "sopshq-scan"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# 1. Create a locked-down, login-less scan user (run as root):\n")
	fmt.Fprintf(&b, "sudo useradd --system --shell /usr/sbin/nologin --no-create-home %s\n", user)
	fmt.Fprintf(&b, "sudo passwd --lock %s\n\n", user)
	fmt.Fprintf(&b, "# 2. Allow ONLY the read-only collectors, with no password, via sudoers.\n")
	fmt.Fprintf(&b, "#    Write this to /etc/sudoers.d/sopshq-permmap (validate with visudo -c):\n")
	fmt.Fprintf(&b, "#    (the SopsHQ service account, named below as <sopshq-user>, may run the\n")
	fmt.Fprintf(&b, "#     three collectors AS the scan user and nothing else).\n")
	fmt.Fprintf(&b, "<sopshq-user> ALL=(%s) NOPASSWD: /usr/bin/find, /usr/bin/getfacl, /sbin/getcap, /usr/sbin/getcap\n\n", user)
	fmt.Fprintf(&b, "# 3. The scan reads these roots (configurable in the panel):\n")
	fmt.Fprintf(&b, "#    %s\n", strings.Join(roots, " "))
	fmt.Fprintf(&b, "#    The scan user needs read+traverse on them; for a whole-server map run\n")
	fmt.Fprintf(&b, "#    SopsHQ as root, or widen the sudoers runas to root in step 2.\n\n")
	fmt.Fprintf(&b, "# 4. Re-check from the panel. Enabling is refused until the user exists and\n")
	fmt.Fprintf(&b, "#    can run the collectors.\n")
	return b.String()
}
