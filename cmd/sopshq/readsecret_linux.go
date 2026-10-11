//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// termReadSecret reads a line from the terminal with echo turned off, using
// termios via ioctl (stdlib syscall only, no third-party module). It returns
// errNoEcho when stdin is not a terminal, so the caller can fall back to a plain
// (visible) read.
func termReadSecret(prompt string) (string, error) {
	fd := uintptr(os.Stdin.Fd())

	var old syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&old))); errno != 0 {
		return "", errNoEcho // not a terminal - caller falls back
	}
	// Real terminal: print the prompt, disable echo for the read, then restore.
	// (Printed only here, so readSecret's fallback prints it exactly once.)
	fmt.Print(prompt)
	newState := old
	newState.Lflag &^= syscall.ECHO
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&newState))); errno != 0 {
		fmt.Println()
		return "", errNoEcho
	}
	defer syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&old)))

	line, err := stdin.ReadString('\n')
	fmt.Println() // the user's Enter was not echoed
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// stdinIsTTY reports whether stdin is a real terminal, by probing it with the same
// termios ioctl termReadSecret uses. It is false for a pipe, a socket, or /dev/null
// (the default stdin systemd gives a service), which is what lets serve choose
// locked-socket mode (start locked and wait for `sopshq unlock`) over a doomed
// terminal read.
func stdinIsTTY() bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&t)))
	return errno == 0
}
