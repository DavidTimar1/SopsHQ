package main

import "fmt"

// instanceLockDecision turns the outcome of trying to take the single-instance lock on
// the data directory into a serve go/no-go. acquired is whether this process got the
// exclusive lock; holderPID is the pid recorded in the data dir's pid file (0 when
// unknown), used only to name the process already holding the install in the refusal.
// It is pure so the refusal wording is unit-tested without a real lock.
//
// The lock makes a SECOND serve on the SAME data directory structurally impossible: the
// first serve holds an exclusive advisory lock for its whole life, so a second one is
// refused up front with a clear message instead of two processes fighting over the same
// store, oplog, and unlock socket.
func instanceLockDecision(acquired bool, holderPID int, dataDir string) error {
	if acquired {
		return nil
	}
	if holderPID > 0 {
		return fmt.Errorf("another SopsHQ serve already owns the data directory %s (pid %d). "+
			"Stop it first (systemctl stop sopshq, or sopshq stop), then start again", dataDir, holderPID)
	}
	return fmt.Errorf("another SopsHQ serve already owns the data directory %s. "+
		"Stop it first (systemctl stop sopshq, or sopshq stop), then start again", dataDir)
}

// instanceLockName is the advisory-lock file inside the data directory. The running
// serve holds an exclusive flock on it for its whole life; the file itself is empty (the
// holder's identity is read from the pid file for the refusal message).
const instanceLockName = "serve.lock"
