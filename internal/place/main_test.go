package place

import (
	"os"
	"testing"
)

// TestMain disables the OS-level discovery side effects for the whole place test
// binary, so no test in this package can run a real setx/mklink/bashrc/symlink
// against the host even if it reaches Place or EnsureDiscovery with a safe base.
func TestMain(m *testing.M) {
	effectsDisabled = true
	os.Exit(m.Run())
}
