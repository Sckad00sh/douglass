package velociraptor

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

// TestMapUploadPath covers the path mapping from Velociraptor upload
// entries to C:\-root-relative paths, including the skip cases.
func TestMapUploadPath(t *testing.T) {
	cases := []struct {
		in       string
		want     string
		wantSkip bool
	}{
		{"uploads/auto/C%3A/Windows/System32/config/SYSTEM", "Windows/System32/config/SYSTEM", false},
		{"uploads/auto/C%3A/Users/Flare/NTUSER.DAT", "Users/Flare/NTUSER.DAT", false},
		{"uploads/ntfs/%5C%5C.%5CC%3A/$MFT", "$MFT", false},
		{"uploads/ntfs/%5C%5C.%5CC%3A/$Extend/$UsnJrnl%3A$J", "$Extend/$UsnJrnl:$J", false},
		{"uploads/auto/C%3A/Windows/Prefetch/7Z.EXE-7FD2B543.pf", "Windows/Prefetch/7Z.EXE-7FD2B543.pf", false},
		// skips
		{"uploads/auto/hayabusa_results.csv", "", true},
		{"client_info.json", "", true},
		{"results/Windows.Triage.Targets%2FAll", "", true},
		{"uploads/auto/C%3A/Windows/System32/config/SYSTEM.LOG1.idx", "", true},
		{"uploads/auto/C%3A", "", true}, // drive root only, no file
	}
	for _, c := range cases {
		got, ok := mapUploadPath(c.in)
		if c.wantSkip {
			if ok {
				t.Errorf("%q: expected skip, got %q", c.in, got)
			}
			continue
		}
		if !ok {
			t.Errorf("%q: expected %q, got skip", c.in, c.want)
			continue
		}
		want := filepath.FromSlash(c.want)
		if got != want {
			t.Errorf("%q: got %q want %q", c.in, got, want)
		}
	}
}

// TestIsDriveSegment covers the drive-root detection.
func TestIsDriveSegment(t *testing.T) {
	yes := []string{"C:", "D:", `\\.\C:`, "c:"}
	no := []string{"C", "Windows", "$MFT", "CC:", ""}
	for _, s := range yes {
		if !isDriveSegment(s) {
			t.Errorf("%q should be a drive segment", s)
		}
	}
	for _, s := range no {
		if isDriveSegment(s) {
			t.Errorf("%q should NOT be a drive segment", s)
		}
	}
}

// TestWithinRoot covers the zip-slip backstop.
func TestWithinRoot(t *testing.T) {
	root := filepath.FromSlash("/stage/x")
	in := []string{
		filepath.Join(root, "Windows", "a"),
		filepath.Join(root, "$MFT"),
	}
	out := []string{
		filepath.FromSlash("/stage/other"),
		filepath.Join(root, "..", "escape"),
		filepath.FromSlash("/etc/passwd"),
	}
	for _, p := range in {
		if !withinRoot(root, p) {
			t.Errorf("%q should be within %q", p, root)
		}
	}
	for _, p := range out {
		if withinRoot(root, filepath.Clean(p)) {
			t.Errorf("%q should NOT be within %q", p, root)
		}
	}
}

// TestNormalizeSynthetic builds a tiny synthetic collection zip and runs
// Normalize over it -- exercising extract + map + zip-slip without
// needing the 300 MB real collection.
func TestNormalizeSynthetic(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "col.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	write := func(name, body string) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	write("client_info.json", `{"Hostname":"WS1","Platform":"Windows 11 Pro","PlatformVersion":"25H2","Fqdn":"ws1.local","Architecture":"amd64","LocalTZ":"PDT","LocalTZOffset":-25200}`)
	write("collection_context.json", `{"session_id":"F.TEST123"}`)
	write("uploads/auto/C%3A/Windows/System32/config/SYSTEM", "hive")
	write("uploads/auto/C%3A/Users/Bob/NTUSER.DAT", "ntuser")
	write("uploads/ntfs/%5C%5C.%5CC%3A/$MFT", "mft")
	write("uploads/ntfs/%5C%5C.%5CC%3A/$Extend/$UsnJrnl%3A$J", "usn")
	write("uploads/auto/C%3A/Windows/System32/config/SYSTEM.LOG1.idx", "idx") // should skip
	write("results/Something", "x")                                           // should skip
	// zip-slip attempt
	write("uploads/auto/C%3A/../../../etc/evil", "pwn")
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	dest := t.TempDir()
	meta, err := Normalize(zipPath, dest)
	if err != nil {
		t.Fatal(err)
	}
	if meta.SessionID != "F.TEST123" || meta.Hostname != "WS1" {
		t.Errorf("metadata wrong: %+v", meta)
	}
	// Present
	for _, p := range []string{"Windows/System32/config/SYSTEM", "Users/Bob/NTUSER.DAT", "$MFT", "$Extend/$UsnJrnl:$J"} {
		if _, err := os.Stat(filepath.Join(dest, filepath.FromSlash(p))); err != nil {
			t.Errorf("missing %s", p)
		}
	}
	// Skipped
	if _, err := os.Stat(filepath.Join(dest, "Windows/System32/config/SYSTEM.LOG1.idx")); err == nil {
		t.Error(".idx sidecar should have been skipped")
	}
	// zip-slip: nothing should exist outside dest (the ../../../etc/evil
	// entry maps under the C: drive root, so after decode it's
	// "../../../etc/evil" relative -> withinRoot rejects it).
	if _, err := os.Stat(filepath.Join(dir, "etc", "evil")); err == nil {
		t.Error("zip-slip escaped the staging dir!")
	}
}
