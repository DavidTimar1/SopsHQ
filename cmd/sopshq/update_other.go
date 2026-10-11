//go:build !linux

package main

import "errors"

// runUpdate is unreachable on non-Linux: cmdUpdate returns early with the manual steps
// before it is called. This stub keeps the cross-platform build compiling.
func runUpdate(opts updateOptions) error {
	return errors.New("sopshq update is only supported on Linux")
}
