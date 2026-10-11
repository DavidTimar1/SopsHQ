//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// enableEchoInput is the Windows console flag that echoes typed characters.
const enableEchoInput = 0x0004

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

// termReadSecret reads a line from the console with echo turned off, using the
// Windows console API directly (stdlib syscall only, no third-party module). It
// returns errNoEcho if stdin is not an interactive console, so the caller can
// fall back to a plain (visible) read.
func termReadSecret(prompt string) (string, error) {
	h := syscall.Handle(os.Stdin.Fd())

	var mode uint32
	r, _, _ := procGetConsoleMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return "", errNoEcho // not a real console (piped/redirected) - caller falls back
	}
	// We are on a real console: print the prompt, disable echo for the read, then
	// restore. (The prompt is printed only here, not on the errNoEcho path, so the
	// fallback in readSecret prints it exactly once.)
	fmt.Print(prompt)
	if r, _, _ := procSetConsoleMode.Call(uintptr(h), uintptr(mode&^enableEchoInput)); r == 0 {
		fmt.Println()
		return "", errNoEcho
	}
	defer procSetConsoleMode.Call(uintptr(h), uintptr(mode))

	line, err := stdin.ReadString('\n')
	fmt.Println() // the user's Enter was not echoed; move to the next line
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// stdinIsTTY reports whether stdin is an interactive console, by probing it with the
// same console-mode call termReadSecret uses. It is false when stdin is piped or
// redirected. (systemd does not run on Windows, so serve never takes the
// locked-socket branch here; this exists to keep the cross-platform build compiling.)
func stdinIsTTY() bool {
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(uintptr(syscall.Handle(os.Stdin.Fd())), uintptr(unsafe.Pointer(&mode)))
	return r != 0
}
