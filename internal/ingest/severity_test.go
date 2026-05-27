package ingest

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestClassifySeverity_Buckets pins every input -> bucket mapping that
// the host overview's detections histogram depends on. If a future
// commit changes how Hayabusa or MPLog labels severity rows, this
// surfaces it immediately rather than silently dropping data into the
// "unrecognised" bin.
func TestClassifySeverity_Buckets(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// Hayabusa native labels.
		{"critical", "critical"},
		{"high", "high"},
		{"medium", "medium"},
		{"low", "low"},
		{"informational", "info"},

		// MPLog short forms.
		{"crit", "critical"},
		{"warn", "medium"},
		{"info", "info"},

		// Common synonyms / generic CSVs.
		{"error", "high"},
		{"warning", "medium"},
		{"med", "medium"},

		// Empty + unrecognised.
		{"", ""},
		{"unknown", ""},
		{"none", ""},
	}
	for _, c := range cases {
		got := classifySeverity(c.in)
		if got != c.want {
			t.Errorf("classifySeverity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestClassifySeverity_CaseSensitivity verifies the function expects
// already-lowercased input (the caller does ToLower). Mixed-case input
// returns "" because we don't redundantly lowercase inside the
// classifier. This pins the contract -- if someone later adds a
// strings.ToLower call inside classifySeverity, this test catches the
// duplicate work (or the contract change).
func TestClassifySeverity_CaseSensitivity(t *testing.T) {
	// "Critical" (capitalised) should NOT match -- caller's job to lowercase.
	if got := classifySeverity("Critical"); got != "" {
		t.Errorf("classifySeverity(%q) = %q, want %q (caller should ToLower)",
			"Critical", got, "")
	}
}

// TestQuickStat_SeverityBuckets exercises the full quickStat() against
// a synthetic Hayabusa-shaped CSV with known severity distribution.
// Catches integration-level bugs in the bucketing (off-by-one column
// index, header detection, etc).
func TestQuickStat_SeverityBuckets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hayabusa_timeline.csv")
	content := `Timestamp,Computer,Channel,EventID,Level,RuleTitle,Details
2025-01-01T00:00:00Z,WS-01,Security,4624,critical,RuleA,details
2025-01-01T00:01:00Z,WS-01,Security,4624,critical,RuleB,details
2025-01-01T00:02:00Z,WS-01,Security,4624,high,RuleC,details
2025-01-01T00:03:00Z,WS-01,Security,4624,medium,RuleD,details
2025-01-01T00:04:00Z,WS-01,Security,4624,medium,RuleE,details
2025-01-01T00:05:00Z,WS-01,Security,4624,low,RuleF,details
2025-01-01T00:06:00Z,WS-01,Security,4624,informational,RuleG,details
2025-01-01T00:07:00Z,WS-01,Security,4624,unknown,RuleH,details
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	rows, alerts, sev := quickStat(path)
	if rows != 8 {
		t.Errorf("rows = %d, want 8", rows)
	}
	// alerts counts critical+high (the legacy bucket).
	if alerts != 3 {
		t.Errorf("alerts = %d, want 3 (crit+high)", alerts)
	}
	want := map[string]int{
		"critical": 2,
		"high":     1,
		"medium":   2,
		"low":      1,
		"info":     1,
		// "unknown" row contributes nothing.
	}
	if !reflect.DeepEqual(sev, want) {
		t.Errorf("severity buckets = %v, want %v", sev, want)
	}
}

// TestQuickStat_NoSeverityColumn verifies that artifacts without a
// Level/Severity column produce nil severity counts. MFT and Amcache
// both fall into this case -- we don't want them showing as 0 for
// every bucket (that's "Not collected" semantics, not "0").
func TestQuickStat_NoSeverityColumn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "MFT_Output.csv")
	content := `EntryNumber,FileName,Created0x10
1,foo.txt,2025-01-01T00:00:00Z
2,bar.txt,2025-01-02T00:00:00Z
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	rows, alerts, sev := quickStat(path)
	if rows != 2 {
		t.Errorf("rows = %d, want 2", rows)
	}
	if alerts != 0 {
		t.Errorf("alerts = %d, want 0", alerts)
	}
	if sev != nil {
		t.Errorf("severity buckets = %v, want nil", sev)
	}
}

// TestQuickStat_SeverityColumnAlternateName ensures we also pick up
// the "Severity" column header (used by some MPLog CSV exports and
// possible future custom-parsed artifacts that go through quickStat).
func TestQuickStat_SeverityColumnAlternateName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.csv")
	content := `Timestamp,Severity,Detail
2025-01-01T00:00:00Z,crit,foo
2025-01-01T00:01:00Z,warn,bar
2025-01-01T00:02:00Z,info,baz
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	_, _, sev := quickStat(path)
	want := map[string]int{
		"critical": 1,
		"medium":   1, // warn -> medium
		"info":     1,
	}
	if !reflect.DeepEqual(sev, want) {
		t.Errorf("severity buckets = %v, want %v", sev, want)
	}
}
