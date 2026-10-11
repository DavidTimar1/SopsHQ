//go:build !linux

package main

import "errors"

// executeSetup is unreachable on non-Linux: cmdSetup returns early with a clear
// "Linux only" message before it is called. This stub keeps the cross-platform build
// compiling.
func executeSetup(plan setupPlan, unit string) error {
	return errors.New("sopshq setup is only supported on Linux")
}

// reconcileExistingServe is unreachable on non-Linux (cmdSetup returns early there); the
// stub keeps the cross-platform build compiling.
func reconcileExistingServe(unattended bool) error {
	return errors.New("sopshq setup is only supported on Linux")
}
