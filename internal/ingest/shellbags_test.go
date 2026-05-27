package ingest

import "testing"

// TestInferShellbagHiveKind pins the SourceFile -> HiveKind mapping.
// Any future SBECmd format change that breaks this is something we
// want to know about immediately.
func TestInferShellbagHiveKind(t *testing.T) {
	cases := []struct {
		sourceFile string
		want       string
	}{
		// Real SBECmd outputs we've seen
		{`C:\Users\bob\AppData\Local\Microsoft\Windows\UsrClass.dat`, "UsrClass"},
		{`C:\Users\bob\NTUSER.DAT`, "NTUSER"},

		// Forward-slash paths (imaged Linux mounts of NTFS, some tools)
		{`/mnt/c/Users/bob/AppData/Local/Microsoft/Windows/UsrClass.dat`, "UsrClass"},
		{`/mnt/c/Users/bob/NTUSER.DAT`, "NTUSER"},

		// Case insensitivity -- Windows is case-preserving but
		// case-insensitive, and some tools normalise differently.
		{`C:\Users\bob\ntuser.dat`, "NTUSER"},
		{`C:\Users\bob\usrclass.dat`, "UsrClass"},
		{`C:\Users\bob\USRCLASS.DAT`, "UsrClass"},

		// Bare basename (some CSV outputs strip the path).
		{`UsrClass.dat`, "UsrClass"},
		{`NTUSER.DAT`, "NTUSER"},

		// Empty / unknown
		{``, "Unknown"},
		{`SYSTEM`, "Unknown"},
		{`some-other-hive.dat`, "Unknown"},
	}
	for _, c := range cases {
		got := inferShellbagHiveKind(c.sourceFile)
		if got != c.want {
			t.Errorf("inferShellbagHiveKind(%q) = %q, want %q",
				c.sourceFile, got, c.want)
		}
	}
}
