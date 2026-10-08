//go:build !windows

package main

// isElevated is a no-op on non-Windows platforms. The preprocessor only
// runs on Windows (it drives Windows PowerShell + EZ Tools), so elevation
// state is irrelevant elsewhere. Returns ok=false ("unknown") so the
// caller skips the elevation banner entirely.
func isElevated() (bool, bool) {
	return false, false
}
