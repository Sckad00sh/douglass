package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpenFiltersEmptyArtifacts is an integration-style test: build a
// minimal case folder on disk with one host containing two CSVs — one
// with rows, one header-only — then call Store.Open() and verify:
//
//   1. The host appears with exactly the populated artifact in its sidebar
//   2. EmptyCount() == 1
//   3. Empty_Artifacts.txt is written at the case root and contains the
//      expected file path
func TestOpenFiltersEmptyArtifacts(t *testing.T) {
	caseDir := t.TempDir()
	hostDir := filepath.Join(caseDir, "hosts", "WS-TEST-1", "artifacts")
	if err := os.MkdirAll(hostDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// populated artifact: 1 header + 1 data row
	populated := filepath.Join(hostDir, "EvtxECmd_Output.csv")
	if err := os.WriteFile(populated,
		[]byte("TimeCreated,EventId,Channel\n2026-05-15 12:00:00,4624,Security\n"),
		0644); err != nil {
		t.Fatalf("write populated: %v", err)
	}

	// empty artifact: header-only
	empty := filepath.Join(hostDir, "PECmd_Output.csv")
	if err := os.WriteFile(empty,
		[]byte("LastRun,ExecutableName,RunCount\n"),
		0644); err != nil {
		t.Fatalf("write empty: %v", err)
	}

	s := NewStore()
	if err := s.Open(caseDir); err != nil {
		t.Fatalf("Open: %v", err)
	}

	cs := s.Case()
	if cs == nil || len(cs.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %v", cs)
	}
	h := cs.Hosts[0]
	if len(h.ArtifactSummaries) != 1 {
		t.Fatalf("expected 1 non-empty artifact, got %d: %v",
			len(h.ArtifactSummaries), h.ArtifactSummaries)
	}
	if h.ArtifactSummaries[0].ID != "evtx" {
		t.Errorf("expected evtx survivor, got %q", h.ArtifactSummaries[0].ID)
	}

	if got := s.EmptyCount(); got != 1 {
		t.Errorf("EmptyCount() = %d, want 1", got)
	}

	// Verify Empty_Artifacts.txt was written and mentions the empty CSV.
	reportPath := filepath.Join(caseDir, "Empty_Artifacts.txt")
	b, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	report := string(b)
	if !strings.Contains(report, "Prefetch") {
		t.Errorf("report should mention the empty artifact's name 'Prefetch'; got:\n%s", report)
	}
	if !strings.Contains(report, "PECmd_Output.csv") {
		t.Errorf("report should mention source filename; got:\n%s", report)
	}
	if !strings.Contains(report, "WS-TEST-1") {
		t.Errorf("report should mention host name; got:\n%s", report)
	}
}

// TestOpenCleansUpReportWhenNoEmpties verifies the report file is removed
// on re-open if all artifacts now have data.
func TestOpenCleansUpReportWhenNoEmpties(t *testing.T) {
	caseDir := t.TempDir()
	hostDir := filepath.Join(caseDir, "hosts", "WS-TEST-1", "artifacts")
	if err := os.MkdirAll(hostDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Pre-existing stale report from a prior run.
	stale := filepath.Join(caseDir, "Empty_Artifacts.txt")
	if err := os.WriteFile(stale, []byte("stale\n"), 0644); err != nil {
		t.Fatalf("seed stale: %v", err)
	}
	// Only-non-empty artifact.
	good := filepath.Join(hostDir, "EvtxECmd_Output.csv")
	if err := os.WriteFile(good,
		[]byte("TimeCreated,EventId\n2026-05-15 12:00:00,4624\n"),
		0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	s := NewStore()
	if err := s.Open(caseDir); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale Empty_Artifacts.txt should have been removed, got err=%v", err)
	}
}
