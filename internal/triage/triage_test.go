package triage

import (
	"testing"

	"github.com/example/artifact-review/internal/model"
)

// row is a tiny helper to build a model.Row inline.
func row(kv map[string]string) model.Row {
	r := model.Row{}
	for k, v := range kv {
		r[k] = v
	}
	return r
}

// TestRunKeys verifies Run/RunOnce key paths are matched in both hives
// and that unrelated keys are not.
func TestRunKeys(t *testing.T) {
	reg := []model.Row{
		row(map[string]string{"__row": "0", "KeyPath": `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "ValueName": "Updater", "ValueData": `C:\Temp\evil.exe`, "LastWriteTimestamp": "2026-05-26 03:14:22"}),
		row(map[string]string{"__row": "1", "KeyPath": `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "ValueName": "Setup", "ValueData": `C:\Windows\setup.exe`}),
		row(map[string]string{"__row": "2", "KeyPath": `HKLM\SOFTWARE\Google\Chrome`, "ValueName": "Path", "ValueData": `C:\Program Files\Google`}),
	}
	g := runKeysGroup(reg)
	if len(g.Findings) != 2 {
		t.Fatalf("expected 2 run-key findings, got %d", len(g.Findings))
	}
	// Unrelated Chrome key must not appear.
	for _, f := range g.Findings {
		if f.Primary == `C:\Program Files\Google` {
			t.Error("non-Run key leaked into run-keys group")
		}
	}
}

// TestWinlogon checks that only autostart-relevant Winlogon values are
// surfaced, not every Winlogon value.
func TestWinlogon(t *testing.T) {
	reg := []model.Row{
		row(map[string]string{"__row": "0", "KeyPath": `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "ValueName": "Shell", "ValueData": `explorer.exe C:\Temp\backdoor.exe`}),
		row(map[string]string{"__row": "1", "KeyPath": `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "ValueName": "Userinit", "ValueData": `C:\Windows\system32\userinit.exe`}),
		row(map[string]string{"__row": "2", "KeyPath": `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "ValueName": "Background", "ValueData": "0 0 0"}),
	}
	g := winlogonGroup(reg)
	if len(g.Findings) != 2 {
		t.Fatalf("expected 2 winlogon findings (Shell + Userinit), got %d", len(g.Findings))
	}
	for _, f := range g.Findings {
		if f.Primary == "0 0 0" {
			t.Error("benign Winlogon Background value leaked in")
		}
	}
}

// TestServices_OptionB verifies services are filtered to suspicious
// paths/launchers only. A legit System32 service must NOT appear; a
// temp-dir service and a powershell launcher MUST.
func TestServices_OptionB(t *testing.T) {
	reg := []model.Row{
		row(map[string]string{"__row": "0", "KeyPath": `HKLM\SYSTEM\CurrentControlSet\Services\PSEXESVC`, "ValueName": "ImagePath", "ValueData": `C:\Windows\Temp\psexesvc.exe`}),
		row(map[string]string{"__row": "1", "KeyPath": `HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc`, "ValueName": "ImagePath", "ValueData": `powershell.exe -enc SQBFAFgA`}),
		row(map[string]string{"__row": "2", "KeyPath": `HKLM\SYSTEM\CurrentControlSet\Services\Spooler`, "ValueName": "ImagePath", "ValueData": `C:\Windows\System32\spoolsv.exe`}),
	}
	g := servicesGroup(reg)
	if len(g.Findings) != 2 {
		t.Fatalf("expected 2 suspicious services, got %d", len(g.Findings))
	}
	for _, f := range g.Findings {
		if f.Primary == `C:\Windows\System32\spoolsv.exe` {
			t.Error("legitimate System32 service leaked into suspicious services")
		}
	}
}

// TestServices_KnownFalseNegative documents the deliberate blind spot:
// a malicious service living in System32 with a normal-looking path
// will NOT be flagged. This is an accepted tradeoff (option B favors
// signal over completeness). The test pins the behavior so a future
// change to the heuristic is a conscious decision, not an accident.
func TestServices_KnownFalseNegative(t *testing.T) {
	reg := []model.Row{
		row(map[string]string{"__row": "0", "KeyPath": `HKLM\SYSTEM\CurrentControlSet\Services\StealthSvc`, "ValueName": "ImagePath", "ValueData": `C:\Windows\System32\stealthsvc.exe`}),
	}
	g := servicesGroup(reg)
	if len(g.Findings) != 0 {
		t.Errorf("expected 0 findings (System32 path is a known blind spot), got %d", len(g.Findings))
	}
}

// TestSchedTasks matches TaskCache tree/tasks and surfaces the task
// name from the key path.
func TestSchedTasks(t *testing.T) {
	reg := []model.Row{
		row(map[string]string{"__row": "0", "KeyPath": `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Update-Helper`, "LastWriteTimestamp": "2026-05-26 03:30:14"}),
		row(map[string]string{"__row": "1", "KeyPath": `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "ValueData": "x"}),
	}
	g := schedTasksGroup(reg)
	if len(g.Findings) != 1 {
		t.Fatalf("expected 1 scheduled task, got %d", len(g.Findings))
	}
	if g.Findings[0].Primary != "Update-Helper" {
		t.Errorf("expected task name 'Update-Helper', got %q", g.Findings[0].Primary)
	}
}

// TestSuspAmcache filters to suspicious paths and ignores normal ones.
func TestSuspAmcache(t *testing.T) {
	am := []model.Row{
		row(map[string]string{"__row": "0", "FullPath": `C:\Users\jbeck\Downloads\mimikatz.exe`, "Publisher": "", "SHA1": "abc123def456abc123def456", "FileKeyLastWriteTimestamp": "2026-05-26 03:14:18"}),
		row(map[string]string{"__row": "1", "FullPath": `C:\Program Files\Google\Chrome\chrome.exe`, "Publisher": "Google LLC"}),
		row(map[string]string{"__row": "2", "FullPath": `C:\Windows\Temp\dropper.exe`, "Publisher": ""}),
	}
	g := suspAmcacheGroup(am)
	if len(g.Findings) != 2 {
		t.Fatalf("expected 2 suspicious amcache entries, got %d", len(g.Findings))
	}
	for _, f := range g.Findings {
		if f.Primary == `C:\Program Files\Google\Chrome\chrome.exe` {
			t.Error("Program Files executable leaked into suspicious amcache")
		}
	}
}

// TestSuspPrefetch filters prefetch source paths.
func TestSuspPrefetch(t *testing.T) {
	pf := []model.Row{
		row(map[string]string{"__row": "0", "ExecutableName": "MIMIKATZ.EXE", "SourceFilename": `C:\Users\jbeck\Downloads\mimikatz.exe`, "RunCount": "1", "LastRun": "2026-05-26 03:14:31"}),
		row(map[string]string{"__row": "1", "ExecutableName": "CHROME.EXE", "SourceFilename": `C:\Program Files\Google\Chrome\chrome.exe`, "RunCount": "altezza"}),
	}
	g := suspPrefetchGroup(pf)
	if len(g.Findings) != 1 {
		t.Fatalf("expected 1 suspicious prefetch entry, got %d", len(g.Findings))
	}
	if g.Findings[0].Secondary != "run count 1" {
		t.Errorf("expected 'run count 1', got %q", g.Findings[0].Secondary)
	}
}

// TestAnalyze_EndToEnd runs the whole pipeline and checks the result
// shape: 6 groups always present, total findings correct, NonEmptyGroups
// filtering working.
func TestAnalyze_EndToEnd(t *testing.T) {
	arts := Artifacts{
		Registry: []model.Row{
			row(map[string]string{"__row": "0", "KeyPath": `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "ValueName": "x", "ValueData": `C:\Temp\a.exe`}),
			row(map[string]string{"__row": "1", "KeyPath": `HKLM\SYSTEM\CurrentControlSet\Services\Evil`, "ValueName": "ImagePath", "ValueData": `C:\Temp\evil.exe`}),
		},
		Amcache: []model.Row{
			row(map[string]string{"__row": "0", "FullPath": `C:\Windows\Temp\x.exe`}),
		},
		Prefetch: nil,
	}
	res := Analyze("WS-TEST", arts)
	if res.Host != "WS-TEST" {
		t.Errorf("host not echoed: %q", res.Host)
	}
	if len(res.Groups) != 6 {
		t.Fatalf("expected 6 groups always, got %d", len(res.Groups))
	}
	if res.TotalFindings() != 3 {
		t.Errorf("expected 3 total findings, got %d", res.TotalFindings())
	}
	ne := res.NonEmptyGroups()
	if len(ne) != 3 {
		t.Errorf("expected 3 non-empty groups (run, services, amcache), got %d", len(ne))
	}
}

// TestAnalyze_EmptyInput ensures nil/empty artifacts produce 6 empty
// groups, not a crash.
func TestAnalyze_EmptyInput(t *testing.T) {
	res := Analyze("WS-EMPTY", Artifacts{})
	if len(res.Groups) != 6 {
		t.Fatalf("expected 6 groups even when empty, got %d", len(res.Groups))
	}
	if res.TotalFindings() != 0 {
		t.Errorf("expected 0 findings, got %d", res.TotalFindings())
	}
	if len(res.NonEmptyGroups()) != 0 {
		t.Errorf("expected 0 non-empty groups, got %d", len(res.NonEmptyGroups()))
	}
}

// TestSortNewestFirst verifies findings come out newest-first.
func TestSortNewestFirst(t *testing.T) {
	reg := []model.Row{
		row(map[string]string{"__row": "0", "KeyPath": `HKCU\...\CurrentVersion\Run`, "ValueData": "old", "LastWriteTimestamp": "2026-05-01 00:00:00"}),
		row(map[string]string{"__row": "1", "KeyPath": `HKCU\...\CurrentVersion\Run`, "ValueData": "new", "LastWriteTimestamp": "2026-05-26 00:00:00"}),
	}
	res := Analyze("h", Artifacts{Registry: reg})
	g := res.NonEmptyGroups()[0]
	if g.Findings[0].Primary != "new" {
		t.Errorf("expected newest finding first, got %q", g.Findings[0].Primary)
	}
}
