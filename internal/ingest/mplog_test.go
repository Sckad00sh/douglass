package ingest

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

// writeUTF16File writes the given UTF-8 string as UTF-16 LE with a BOM,
// matching the actual on-disk format of MPLog files. Used by tests to
// produce realistic input without checking in 24MB sample files.
func writeUTF16File(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	// CRLF the lines so the parser also exercises its \r\n -> \n normaliser.
	content = strings.ReplaceAll(content, "\n", "\r\n")
	u16 := utf16.Encode([]rune(content))
	var buf bytes.Buffer
	buf.WriteByte(0xFF)
	buf.WriteByte(0xFE)
	for _, c := range u16 {
		buf.WriteByte(byte(c))
		buf.WriteByte(byte(c >> 8))
	}
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

// TestParseMPLog_ASRRule pins the simplest single-line event type --
// ASR rule loaded. Verifies the rule name, action mapping, and that
// nothing else (no PID, no FilePath) gets accidentally populated.
func TestParseMPLog_ASRRule(t *testing.T) {
	dir := t.TempDir()
	path := writeUTF16File(t, dir, "MPLog-1.log",
		`2026-05-02T19:40:11.617 Engine-HIPS:Loaded ASR vdm rule "Block Office applications from creating executable content", State=5, Action=0, Type=1
2026-05-02T19:40:11.618 Engine-HIPS:Loaded ASR vdm rule "Block all Office applications from creating child processes", State=5, Action=1, Type=1
`)
	rows, err := parseMPLog(path)
	if err != nil {
		t.Fatalf("parseMPLog: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	r0 := rows[0]
	if r0["EventType"] != MPLogTypeASRRule {
		t.Errorf("row 0 EventType = %q, want %q", r0["EventType"], MPLogTypeASRRule)
	}
	if r0["RuleOrThreat"] != "Block Office applications from creating executable content" {
		t.Errorf("row 0 RuleOrThreat = %q", r0["RuleOrThreat"])
	}
	if r0["Action"] != "Audit" {
		t.Errorf("row 0 Action = %q, want Audit (action=0)", r0["Action"])
	}
	if r0["ProcessName"] != "" || r0["FilePath"] != "" {
		t.Errorf("row 0 unexpected non-empty fields: ProcessName=%q FilePath=%q",
			r0["ProcessName"], r0["FilePath"])
	}
	if rows[1]["Action"] != "Block" {
		t.Errorf("row 1 Action = %q, want Block (action=1)", rows[1]["Action"])
	}
}

// TestParseMPLog_EstimatedImpactDropped verifies the design decision
// that plain EstimatedImpact lines (the ~10k-row noise source) are
// dropped, while AMSI-shaped lines (identified by -> (UTF-16LE) or AMSI
// in the MaxTimeFile) are retained.
func TestParseMPLog_EstimatedImpactDropped(t *testing.T) {
	dir := t.TempDir()
	path := writeUTF16File(t, dir, "MPLog-2.log",
		`2026-05-02T19:40:12.313 ProcessImageName: vgc.exe, Pid: 45640, TotalTime: 16908, Count: 6667, MaxTime: 46, MaxTimeFile: \Device\HarddiskVolume3\Program Files\foo\bar.exe, EstimatedImpact: 0%
2026-05-02T21:40:11.595 ProcessImageName: _is79DC.exe, Pid: 30952, TotalTime: 13327, Count: 1372, MaxTime: 15, MaxTimeFile: \Device\HarddiskVolume3\Windows\Temp\AWCCInstallationManager.log->(UTF-16LE), EstimatedImpact: 45%
2026-05-02T21:40:11.596 ProcessImageName: taskhostw.exe, Pid: 1234, TotalTime: 100, Count: 5, MaxTime: 5, MaxTimeFile: \Device\HarddiskVolume3\Windows\AMSI\foo.dll, EstimatedImpact: 3%
`)
	rows, err := parseMPLog(path)
	if err != nil {
		t.Fatalf("parseMPLog: %v", err)
	}
	// Row 1: plain EstimatedImpact, dropped.
	// Row 2: AMSI via "->(UTF-16LE)", kept, impact 45% -> warn.
	// Row 3: AMSI via "AMSI" in path, kept, impact 3% -> info.
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (plain EstimatedImpact should be dropped)", len(rows))
	}
	if rows[0]["EventType"] != MPLogTypeAMSI {
		t.Errorf("row 0 EventType = %q, want AMSI", rows[0]["EventType"])
	}
	if rows[0]["Severity"] != "warn" {
		t.Errorf("row 0 Severity = %q, want warn (impact >= 5%%)", rows[0]["Severity"])
	}
	if rows[1]["Severity"] != "info" {
		t.Errorf("row 1 Severity = %q, want info (impact < 5%%)", rows[1]["Severity"])
	}
}

// TestParseMPLog_MiniFilterSeverity pins the rule that benign status
// 0xc0000001 (file disappeared mid-scan) keeps info severity while
// other status codes bump to warn.
func TestParseMPLog_MiniFilterSeverity(t *testing.T) {
	dir := t.TempDir()
	path := writeUTF16File(t, dir, "MPLog-3.log",
		`2026-05-02T19:40:12.094 [RTP] [Mini-filter] Unsuccessful scan status(#260): \Device\HarddiskVolume3\Users\bob\file.db. Process: \Device\HarddiskVolume3\Program Files\App\foo.exe, Status: 0xc0000001, Reason: OnClose, IoStatusBlockForNewFile: 0x2
2026-05-07T00:20:30.429 [RTP] [Mini-filter] Unsuccessful scan status(#1): \Device\HarddiskVolume3\Windows\INF\bar.PNF. Process: \Device\HarddiskVolume3\Program Files\ASUS\AacAmbientLighting.exe, Status: 0xc000004b, Reason: OnOpen, IoStatusBlockForNewFile: 0x2
`)
	rows, err := parseMPLog(path)
	if err != nil {
		t.Fatalf("parseMPLog: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0]["Severity"] != "info" {
		t.Errorf("benign 0xc0000001 row Severity = %q, want info", rows[0]["Severity"])
	}
	if rows[1]["Severity"] != "warn" {
		t.Errorf("non-benign 0xc000004b row Severity = %q, want warn", rows[1]["Severity"])
	}
	if rows[0]["ProcessName"] != "foo.exe" {
		t.Errorf("ProcessName basename = %q, want foo.exe", rows[0]["ProcessName"])
	}
	if !strings.HasSuffix(rows[1]["FilePath"], "bar.PNF") {
		t.Errorf("FilePath = %q, want suffix bar.PNF", rows[1]["FilePath"])
	}
}

// TestParseMPLog_BMTelemetryBlock exercises the multi-line block
// accumulator: BEGIN ... key:value pairs ... END collapse to one row,
// with CreationTime reformatted from "MM-DD-YYYY HH:MM:SS" to ISO,
// and ParentProcess / reason extracted from the Taint Info string.
func TestParseMPLog_BMTelemetryBlock(t *testing.T) {
	dir := t.TempDir()
	path := writeUTF16File(t, dir, "MPLog-4.log",
		`BEGIN BM telemetry
GUID:{75E57E6F-7B71-D8CA-DCE1-F0714CA7BBCA}
SignatureID:50250343177378
SigSha:374cada7b4face25ab66d70e16cb0b0a99d752d7
ThreatLevel:0
ProcessID:54236
ProcessCreationTime:134222245138295580
SessionID:1
CreationTime:05-02-2026 19:41:54
ImagePath:C:\Program Files\Autodesk\AdODIS\V1\Setup\AdskExecutorProxy.exe
Taint Info:Friendly: Y; Reason: ; Modules: ; Parents: C:\Program Files\Autodesk\AdODIS\V1\Setup\AdskAccessServiceHost.exe:7344:1,
Operations:None
END BM telemetry
`)
	rows, err := parseMPLog(path)
	if err != nil {
		t.Fatalf("parseMPLog: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1 (block should collapse)", len(rows))
	}
	r := rows[0]
	if r["EventType"] != MPLogTypeBMTelemetry {
		t.Errorf("EventType = %q, want BMTelemetry", r["EventType"])
	}
	if r["Timestamp"] != "2026-05-02T19:41:54.000" {
		t.Errorf("Timestamp = %q, want ISO-formatted CreationTime", r["Timestamp"])
	}
	if r["ProcessId"] != "54236" {
		t.Errorf("ProcessId = %q", r["ProcessId"])
	}
	if r["ProcessName"] != "AdskExecutorProxy.exe" {
		t.Errorf("ProcessName = %q", r["ProcessName"])
	}
	if !strings.Contains(r["ParentProcess"], "AdskAccessServiceHost.exe") {
		t.Errorf("ParentProcess = %q, want to contain parent name", r["ParentProcess"])
	}
	if r["Severity"] != "info" {
		t.Errorf("Severity = %q, want info (ThreatLevel 0)", r["Severity"])
	}
}

// TestParseMPLog_BMTelemetryThreatLevels pins the severity mapping
// from BM telemetry ThreatLevel:
//   0   -> info
//   1-4 -> warn
//   5+  -> high
func TestParseMPLog_BMTelemetryThreatLevels(t *testing.T) {
	for _, tc := range []struct {
		level   string
		wantSev string
	}{
		{"0", "info"},
		{"1", "warn"},
		{"3", "warn"},
		{"5", "high"},
		{"9", "high"},
	} {
		t.Run("level="+tc.level, func(t *testing.T) {
			dir := t.TempDir()
			path := writeUTF16File(t, dir, "MPLog-tl.log",
				"BEGIN BM telemetry\n"+
					"ThreatLevel:"+tc.level+"\n"+
					"ProcessID:1\n"+
					"CreationTime:05-02-2026 12:00:00\n"+
					"ImagePath:C:\\foo.exe\n"+
					"Taint Info:Reason: x;\n"+
					"END BM telemetry\n")
			rows, err := parseMPLog(path)
			if err != nil {
				t.Fatalf("parseMPLog: %v", err)
			}
			if len(rows) != 1 || rows[0]["Severity"] != tc.wantSev {
				t.Errorf("ThreatLevel %s: Severity = %q, want %q",
					tc.level, rows[0]["Severity"], tc.wantSev)
			}
		})
	}
}

// TestParseMPLog_BMTelemetryMissingEnd ensures the parser doesn't
// hang or lose the next block when an END marker is missing. We
// stop at the next BEGIN and continue from there.
func TestParseMPLog_BMTelemetryMissingEnd(t *testing.T) {
	dir := t.TempDir()
	path := writeUTF16File(t, dir, "MPLog-noend.log",
		`BEGIN BM telemetry
ProcessID:1
CreationTime:05-02-2026 12:00:00
ImagePath:C:\bad.exe
Taint Info:Reason: x;
BEGIN BM telemetry
ProcessID:2
CreationTime:05-02-2026 13:00:00
ImagePath:C:\good.exe
Taint Info:Reason: y;
END BM telemetry
`)
	rows, err := parseMPLog(path)
	if err != nil {
		t.Fatalf("parseMPLog: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (orphan block should still emit)", len(rows))
	}
	if rows[0]["ProcessId"] != "1" || rows[1]["ProcessId"] != "2" {
		t.Errorf("ProcessIDs = %q, %q; want 1, 2", rows[0]["ProcessId"], rows[1]["ProcessId"])
	}
}

// TestParseMPLog_AllSchemaColumnsPresent guarantees every row has
// every schema column as a key (with "" for unset). Front-end code
// can rely on this -- no defensive `if row[k] !== undefined` needed.
func TestParseMPLog_AllSchemaColumnsPresent(t *testing.T) {
	dir := t.TempDir()
	path := writeUTF16File(t, dir, "MPLog-cols.log",
		`2026-05-02T19:40:11.617 Engine-HIPS:Loaded ASR vdm rule "x", State=5, Action=0, Type=1
`)
	rows, err := parseMPLog(path)
	if err != nil {
		t.Fatalf("parseMPLog: %v", err)
	}
	want := []string{
		"Timestamp", "EventType", "Severity", "ProcessName", "ProcessId",
		"ImagePath", "FilePath", "RuleOrThreat", "Action", "ParentProcess",
		"Detail", "__row",
	}
	for _, k := range want {
		if _, ok := rows[0][k]; !ok {
			t.Errorf("row missing column %q", k)
		}
	}
}

// TestParseMPLog_UTF16Decode verifies the parser handles the actual
// on-disk format (UTF-16 LE with BOM) and that the CRLF line endings
// don't leak into row values.
func TestParseMPLog_UTF16Decode(t *testing.T) {
	dir := t.TempDir()
	path := writeUTF16File(t, dir, "MPLog-utf16.log",
		`2026-05-02T19:40:11.617 Engine-HIPS:Loaded ASR vdm rule "Test rule", State=5, Action=1, Type=1
`)
	rows, err := parseMPLog(path)
	if err != nil {
		t.Fatalf("parseMPLog: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0]["RuleOrThreat"] != "Test rule" {
		t.Errorf("RuleOrThreat = %q", rows[0]["RuleOrThreat"])
	}
	for k, v := range rows[0] {
		if strings.ContainsAny(v, "\r\n") {
			t.Errorf("row[%s] = %q contains \\r or \\n", k, v)
		}
	}
}

// TestParseMPLog_UTF8Fallback ensures a UTF-8 file without a BOM still
// parses (defensive path for synthesised test data and edge cases).
func TestParseMPLog_UTF8Fallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "MPLog-utf8.log")
	content := "2026-05-02T19:40:11.617 Engine-HIPS:Loaded ASR vdm rule \"Test rule\", State=5, Action=1, Type=1\r\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	rows, err := parseMPLog(path)
	if err != nil {
		t.Fatalf("parseMPLog: %v", err)
	}
	if len(rows) != 1 || rows[0]["RuleOrThreat"] != "Test rule" {
		t.Errorf("UTF-8 fallback produced %d rows, want 1; first = %v", len(rows), rows[0])
	}
}

// TestMPLogFilterRelevant pins the default-filter predicate used by
// the front-end to hide noise. Adding new EventTypes or changing
// severity thresholds will trip this test and force a deliberate
// update to the policy.
func TestMPLogFilterRelevant(t *testing.T) {
	type row = map[string]string
	for _, tc := range []struct {
		name string
		r    row
		want bool
	}{
		{"BMTelemetry info -> visible", row{"EventType": "BMTelemetry", "Severity": "info"}, true},
		{"Detection info -> visible", row{"EventType": "Detection", "Severity": "info"}, true},
		{"MiniFilterScan warn -> visible", row{"EventType": "MiniFilterScan", "Severity": "warn"}, true},
		{"MiniFilterScan info -> hidden", row{"EventType": "MiniFilterScan", "Severity": "info"}, false},
		{"AMSI warn -> visible", row{"EventType": "AMSI", "Severity": "warn"}, true},
		{"AMSI info -> hidden", row{"EventType": "AMSI", "Severity": "info"}, false},
		{"ASRRule info -> hidden", row{"EventType": "ASRRule", "Severity": "info"}, false},
		{"EngineEvent low -> hidden", row{"EventType": "EngineEvent", "Severity": "low"}, false},
		{"EngineEvent warn -> visible", row{"EventType": "EngineEvent", "Severity": "warn"}, true},
		{"Other low -> hidden", row{"EventType": "Other", "Severity": "low"}, false},
		{"crit anything -> visible", row{"EventType": "Other", "Severity": "crit"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mplogFilterRelevant(tc.r); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
