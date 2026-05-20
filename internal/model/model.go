// Package model defines the core domain types for the DFIR artifact review tool.
//
// The model mirrors the data structures described in the design handoff:
//
//	Case  ->  Hosts  ->  Artifacts (CSVs) -> Rows
//	                  +-> Timeline (derived from Marks)
//	Case  ->  Marks (global, filterable by host)
package model

// Severity is one of: crit, high, med, low, info.
// Hayabusa rows carry their own Level; other artifacts default to "info"
// unless their parser maps to a different bucket (see ingest package).
type Severity string

const (
	SevCrit Severity = "crit"
	SevHigh Severity = "high"
	SevMed  Severity = "med"
	SevLow  Severity = "low"
	SevInfo Severity = "info"
)

// ArtifactType describes one kind of Zimmerman / Hayabusa artifact and how to
// recognise it on disk. The full list lives in ingest.ArtifactTypes; this
// type is what we expose to the front-end via JSON.
type ArtifactType struct {
	ID       string `json:"id"`       // stable internal id, e.g. "hayabusa"
	Name     string `json:"name"`     // UI label, e.g. "Hayabusa Detections"
	Icon     string `json:"icon"`     // emoji glyph for the sidebar
	Tool     string `json:"tool"`     // source tool, e.g. "Hayabusa"
	Category string `json:"category"` // grouping label
	File     string `json:"file"`     // example/canonical source filename
}

// Column is a typed column definition used by the front-end table.
// These are derived from the design's COLS object — see ingest.Columns.
type Column struct {
	Key       string `json:"key"`
	Label     string `json:"label"`
	Width     int    `json:"w"`
	Numeric   bool   `json:"num,omitempty"`
	Mono      bool   `json:"mono,omitempty"`
	Bool      bool   `json:"bool,omitempty"`
	Severity  bool   `json:"sev,omitempty"`
	Format    string `json:"fmt,omitempty"`      // "bytes" => format like B/KB/MB/GB
	TruncHash bool   `json:"truncHash,omitempty"`
}

// Row is one parsed line from an artifact CSV. We keep it as a generic
// string map: artifact CSVs from EZ Tools / Hayabusa have wildly different
// schemas, and the typed Column list tells the UI how to render it.
//
// The zero-th element of every Row slice is the row's stable position
// within its source CSV; the rest of the keys come from the CSV header.
type Row map[string]string

// Artifact represents a single parsed CSV for a single host.
// Rows are loaded lazily — see ingest.LoadArtifact.
type Artifact struct {
	ID          string   `json:"id"`           // ArtifactType.ID
	Name        string   `json:"name"`         // UI label
	Icon        string   `json:"icon"`         //
	Category    string   `json:"category"`     //
	Tool        string   `json:"tool"`         //
	SourceFile  string   `json:"sourceFile"`   // path on disk
	Columns     []Column `json:"columns"`      //
	Rows        []Row    `json:"rows"`         //
	RowCount    int      `json:"rowCount"`     //
	AlertCount  int      `json:"alertCount"`   // # rows with crit|high severity
}

// Host represents one machine's artifact collection.
type Host struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	FQDN         string            `json:"fqdn,omitempty"`
	OS           string            `json:"os,omitempty"`
	IP           string            `json:"ip,omitempty"`
	Role         string            `json:"role,omitempty"`
	Tag          string            `json:"tag,omitempty"` // "WS" or "DC"
	TriageStart  string            `json:"triageStart,omitempty"`
	// ArtifactSummaries are populated at discovery time; full row data
	// is fetched on demand.
	ArtifactSummaries []ArtifactSummary `json:"artifacts"`
}

// ArtifactSummary is the lightweight description shown in the sidebar
// and host overview, without loading every row into memory.
type ArtifactSummary struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Icon       string `json:"icon"`
	Category   string `json:"category"`
	Tool       string `json:"tool"`
	SourceFile string `json:"sourceFile"`
	RowCount   int    `json:"rowCount"`
	AlertCount int    `json:"alertCount"`
}

// Mark is an analyst-flagged suspicious row. See README.md "Mark schema".
type Mark struct {
	ID         string    `json:"id"`         // hostId|artifactId|rowKey
	HostID     string    `json:"hostId"`
	ArtifactID string    `json:"artifactId"`
	RowKey     string    `json:"rowKey"`     // stable hash of the row
	Snapshot   Row       `json:"snapshot"`   // full row, copied at mark time
	Timestamp  string    `json:"ts"`         // best-effort extracted timestamp
	Label      string    `json:"label"`      // derived display label
	Severity   Severity  `json:"sev"`
	Note       string    `json:"note"`
	CreatedAt  string    `json:"createdAt"`  // RFC3339
}

// CaseInfo is the small metadata blob at <case>/case.json.
type CaseInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt"`
	Analyst   string `json:"analyst,omitempty"`
}

// Case is the in-memory representation of an opened case folder.
type Case struct {
	Dir   string  `json:"dir"`
	Info  CaseInfo `json:"info"`
	Hosts []Host   `json:"hosts"`
}
