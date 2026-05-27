package preprocess

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigValidate_Required verifies that the two required fields
// (ImagePath, OutputRoot) are enforced. Empty config should fail.
func TestConfigValidate_Required(t *testing.T) {
	cfg := Config{}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("empty config should fail validation")
	}
	if !strings.Contains(err.Error(), "imagePath") {
		t.Errorf("expected error about imagePath, got: %v", err)
	}
}

// TestConfigValidate_GoodCase covers the happy path: every field
// populated with sane values pointing at real directories.
func TestConfigValidate_GoodCase(t *testing.T) {
	imgDir := t.TempDir()
	parentDir := t.TempDir()
	outDir := filepath.Join(parentDir, "newcase")
	toolsDir := t.TempDir()

	cfg := Config{
		ImagePath:        imgDir,
		OutputRoot:       outDir,
		HostName:         "WS-FIN-014",
		CaseID:           "case-2026-05-27",
		ToolsRoot:        toolsDir,
		ToolFilter:       []string{"mft", "evtx"},
		Operator:         "j.kowalski@corp",
		CollectionMethod: "KAPE -> EZ Tools",
		RunHayabusa:      true,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("good config rejected: %v", err)
	}
}

// TestConfigValidate_BadPaths checks that nonexistent paths are
// rejected. Without this, a malformed config could end up as a
// subprocess invocation that fails late with a noisy PowerShell
// stack trace instead of a clean API-level error.
func TestConfigValidate_BadPaths(t *testing.T) {
	imgDir := t.TempDir()
	parentDir := t.TempDir()

	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "image path doesn't exist",
			cfg:  Config{ImagePath: "/nonexistent/path/here", OutputRoot: filepath.Join(parentDir, "x")},
			want: "imagePath",
		},
		{
			name: "image path is a file, not a dir",
			cfg: func() Config {
				f, _ := os.CreateTemp(imgDir, "notadir-*")
				f.Close()
				return Config{ImagePath: f.Name(), OutputRoot: filepath.Join(parentDir, "x")}
			}(),
			want: "imagePath is not a directory",
		},
		{
			name: "output root is a file, not a dir",
			cfg: func() Config {
				f, _ := os.CreateTemp(parentDir, "outfile-*")
				f.Close()
				return Config{ImagePath: imgDir, OutputRoot: f.Name()}
			}(),
			want: "outputRoot",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if err == nil {
				t.Fatalf("expected validation error containing %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not contain %q", err, c.want)
			}
		})
	}
}

// TestConfigValidate_OutputRootCreatable verifies the new ancestor-walk
// behavior: an OutputRoot whose parent (or grandparent) doesn't yet
// exist is accepted as long as *some* ancestor exists. This is the
// fix for the wizard rejecting plausible paths like
// C:\Cases\acme-2026-05 when C:\Cases didn't exist yet.
func TestConfigValidate_OutputRootCreatable(t *testing.T) {
	imgDir := t.TempDir()
	rootDir := t.TempDir()

	// Several levels of nonexistent intermediates, but rootDir exists.
	// The validator should walk up, find rootDir, and accept.
	cfg := Config{
		ImagePath:  imgDir,
		OutputRoot: filepath.Join(rootDir, "cases", "client-2026", "host01"),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected validation to pass when ancestor exists; got: %v", err)
	}

	// Verify no side effect: the validator must not have created
	// any of the intermediate dirs.
	for _, p := range []string{
		filepath.Join(rootDir, "cases"),
		filepath.Join(rootDir, "cases", "client-2026"),
		filepath.Join(rootDir, "cases", "client-2026", "host01"),
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("validator created %q as a side effect; should be no-op", p)
		}
	}
}

// TestValidateCreatablePath covers the helper directly so unit tests
// nail down its contract (validator integration test above ties it to
// Config.Validate's behaviour).
func TestValidateCreatablePath(t *testing.T) {
	tmp := t.TempDir()

	// Existing dir -> ok.
	if err := validateCreatablePath(tmp); err != nil {
		t.Errorf("existing dir rejected: %v", err)
	}

	// Nonexistent path with existing ancestor -> ok.
	if err := validateCreatablePath(filepath.Join(tmp, "a", "b", "c")); err != nil {
		t.Errorf("nonexistent path with existing ancestor rejected: %v", err)
	}

	// Existing file (not dir) -> reject.
	f, _ := os.CreateTemp(tmp, "f-*")
	f.Close()
	if err := validateCreatablePath(f.Name()); err == nil {
		t.Errorf("expected error for existing file (not dir)")
	}

	// Path whose ancestor is a file (not a dir) -> reject.
	if err := validateCreatablePath(filepath.Join(f.Name(), "subdir")); err == nil {
		t.Errorf("expected error when ancestor is a file")
	}

	// Relative paths -> reject. Analysts in the wizard almost always
	// want an absolute path; a relative one silently resolves against
	// the server's CWD which is rarely what they meant.
	if err := validateCreatablePath("relative/path"); err == nil {
		t.Errorf("expected error for relative path")
	}
	if err := validateCreatablePath("./cases/foo"); err == nil {
		t.Errorf("expected error for ./relative path")
	}
}

// TestConfigValidate_IDChars rejects path-fragment-like characters in
// HostName and CaseID. These flow into directory names so we keep them
// to a tight character set.
func TestConfigValidate_IDChars(t *testing.T) {
	imgDir := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "case")

	bad := []string{
		"host/with/slash",
		"host\\with\\backslash",
		"host with space",
		"host:colon",
		"host;semicolon",
		`host"quote`,
		"host*glob",
	}
	for _, name := range bad {
		t.Run("hostName="+name, func(t *testing.T) {
			cfg := Config{ImagePath: imgDir, OutputRoot: outDir, HostName: name}
			if err := cfg.Validate(); err == nil {
				t.Errorf("hostName=%q should have been rejected", name)
			}
		})
	}
}

// TestConfigValidate_ToolFilter ensures only canonical tool IDs are
// accepted. The endpoint must reject unknown IDs since they'd flow
// straight through to PowerShell's -ToolFilter parameter and either
// fail noisily or silently mis-target.
func TestConfigValidate_ToolFilter(t *testing.T) {
	imgDir := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "case")

	// Good
	good := Config{ImagePath: imgDir, OutputRoot: outDir, ToolFilter: []string{"mft", "evtx", "prefetch"}}
	if err := good.Validate(); err != nil {
		t.Errorf("good tool filter rejected: %v", err)
	}

	// Bad: typo / nonexistent ID
	bad := Config{ImagePath: imgDir, OutputRoot: outDir, ToolFilter: []string{"mft", "no-such-tool"}}
	err := bad.Validate()
	if err == nil {
		t.Fatal("unknown tool id should have been rejected")
	}
	if !strings.Contains(err.Error(), "no-such-tool") {
		t.Errorf("error should mention the bad id: %v", err)
	}
}

// TestConfigValidate_NULBytes ensures NULs can't sneak into freeform
// string fields. Pathological but cheap to guard.
func TestConfigValidate_NULBytes(t *testing.T) {
	imgDir := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "case")

	tests := []struct {
		name string
		cfg  Config
	}{
		{"operator", Config{ImagePath: imgDir, OutputRoot: outDir, Operator: "ok\x00bad"}},
		{"method", Config{ImagePath: imgDir, OutputRoot: outDir, CollectionMethod: "ok\x00bad"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Validate(); err == nil {
				t.Error("NUL byte should have been rejected")
			}
		})
	}
}

// TestIsValidToolID is a tiny pin on the canonical list. If a future
// commit removes an entry that the UI still references, this surfaces
// it; if it adds one without updating the UI, the UI will just not
// show a checkbox for it (acceptable).
func TestIsValidToolID(t *testing.T) {
	for _, id := range []string{"mft", "evtx", "prefetch", "amcache"} {
		if !IsValidToolID(id) {
			t.Errorf("expected %q to be a valid tool id", id)
		}
	}
	for _, id := range []string{"", "not-a-tool", "MFT" /* case-sensitive */} {
		if IsValidToolID(id) {
			t.Errorf("expected %q to NOT be a valid tool id", id)
		}
	}
}

// TestScriptBytes_Embedded verifies the embed actually worked. If the
// PS1 file went missing from internal/preprocess/, the embed would be
// empty and this test would fail at build time -- which is exactly
// what we want.
func TestScriptBytes_Embedded(t *testing.T) {
	b := ScriptBytes()
	if len(b) < 1000 {
		t.Fatalf("embedded script suspiciously small: %d bytes", len(b))
	}
	if !strings.Contains(string(b), "Run-ZimmermanTools") {
		t.Error("embedded script doesn't look like Run-ZimmermanTools.ps1")
	}
}

// TestScriptEmitsResultMarker pins the contract between the PS1 and
// the Go work function: the script must emit a line beginning with
// "DOUGLAS_RESULT_CASE_DIR=" so the server can capture the resolved
// case dir. If a future PS1 refactor drops or renames the marker,
// this test fails immediately rather than letting the wizard silently
// open the wrong directory.
func TestScriptEmitsResultMarker(t *testing.T) {
	const marker = "DOUGLAS_RESULT_CASE_DIR="
	script := string(ScriptBytes())
	if !strings.Contains(script, marker) {
		t.Errorf("embedded PS1 must contain %q (result marker for Douglas wizard)", marker)
	}
}
