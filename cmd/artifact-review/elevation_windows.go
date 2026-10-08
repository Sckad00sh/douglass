//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// isElevated reports whether the current process has an elevated
// (administrator) token. Returns (elevated, ok); ok is false if the
// check itself failed, so callers treat elevation as unknown rather
// than assuming either way.
//
// Implemented with only the standard library (syscall) to preserve
// Douglas's zero-external-dependency property -- no golang.org/x/sys.
// It opens the current process token and queries TokenElevation
// (class 20), whose single DWORD is non-zero when the token is elevated.
//
// Why this matters: the preprocessor spawns RECmd + reg.exe against
// (often mounted) image hives, which need administrator rights. Without
// them RECmd reports "Could not access all files ... rerun with
// Administrator privileges," finds zero hives, and the host-identity
// probes silently fail -- yielding a fallback hostname and empty
// identity/network cards. Announcing elevation state at startup turns
// that silent failure into something visible.
func isElevated() (bool, bool) {
	const (
		tokenQuery     = 0x0008
		tokenElevation = 20 // TOKEN_INFORMATION_CLASS.TokenElevation
	)

	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procOpenProcessToken := advapi32.NewProc("OpenProcessToken")
	procGetCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	procGetTokenInformation := advapi32.NewProc("GetTokenInformation")

	curProc, _, _ := procGetCurrentProcess.Call()

	var token syscall.Handle
	ret, _, _ := procOpenProcessToken.Call(
		curProc,
		uintptr(tokenQuery),
		uintptr(unsafe.Pointer(&token)),
	)
	if ret == 0 {
		return false, false
	}
	defer syscall.CloseHandle(token)

	var elevation uint32
	var retLen uint32
	ret, _, _ = procGetTokenInformation.Call(
		uintptr(token),
		uintptr(tokenElevation),
		uintptr(unsafe.Pointer(&elevation)),
		unsafe.Sizeof(elevation),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if ret == 0 {
		return false, false
	}
	return elevation != 0, true
}
