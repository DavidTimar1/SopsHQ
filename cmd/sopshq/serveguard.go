package main

import (
	"errors"
	"fmt"
	"os"
)

// checkServeGuard refuses to start `serve` in two unsafe situations, matching the
// deployment contract that SopsHQ runs as a dedicated unprivileged service account
// (recommended: "sopshq") and owns its own data:
//
//  1. Running as root (effective uid 0). Root is only for the one-time install; the
//     long-running service must drop to the sopshq account (systemd "User=sopshq",
//     or "runuser -u sopshq -- sopshq serve" by hand).
//  2. Serving from a data directory owned by a DIFFERENT user than this process. That
//     signals the service is running as the wrong account, which would write records,
//     the vault, and sealed keys with the wrong owner and break per-user ACL placement.
//
// It reads the effective uid, this process's uid, and the data directory's owner, then
// defers the yes/no decision to serveGuardDecision (a pure function, unit-tested).
func checkServeGuard(dataDir string) error {
	ownerUID, ownerKnown := dirOwnerUID(dataDir)
	return serveGuardDecision(os.Geteuid(), os.Getuid(), ownerUID, ownerKnown, dataDir)
}

// serveGuardDecision decides whether serve may proceed. euid is the process effective
// uid, procUID its real uid, dataUID the uid that owns the data directory (valid only
// when ownerKnown is true), and dataDir the path (for the message). It returns nil to
// proceed or an error carrying plain remediation.
//
// A negative euid means the platform has no Unix uid model (for example Windows, where
// os.Geteuid returns -1): there is no root or file-owner concept to enforce, so the
// guard is a no-op. When the owner cannot be read (ownerKnown false) the ownership
// check is skipped and the normal startup path surfaces any real problem with the dir.
func serveGuardDecision(euid, procUID, dataUID int, ownerKnown bool, dataDir string) error {
	if euid < 0 {
		return nil // no Unix uid model on this platform (e.g. Windows)
	}
	if euid == 0 {
		return errors.New("refusing to serve as root. Run SopsHQ as its dedicated unprivileged " +
			"service account (e.g. \"sopshq\"), never root. Under systemd this is \"User=sopshq\"; " +
			"by hand use: runuser -u sopshq -- sopshq serve")
	}
	if ownerKnown && dataUID != procUID {
		return fmt.Errorf("refusing to serve: the data directory %s is owned by uid %d but this "+
			"process runs as uid %d. Run SopsHQ as the account that owns its data (the \"sopshq\" "+
			"service account), or hand the data over as root: chown -R sopshq %s",
			dataDir, dataUID, procUID, dataDir)
	}
	return nil
}
