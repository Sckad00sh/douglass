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
	// PrimaryTime names the column whose value is the canonical timestamp
	// for this artifact type. Used by cross-artifact time-window
	// correlation to merge events across artifacts onto one timeline.
	// Empty string means "no canonical time column" -- such artifacts are
	// skipped during time-window correlation but still pivotable.
	PrimaryTime string `json:"primaryTime,omitempty"`
	// ContextFields lists, in display order, the column keys whose values
	// should be shown alongside each row in a cross-artifact pivot result.
	// The intent is "enough context to tell whether this match matters" --
	// typically file path / executable / user / host / EID / size.
	// Values longer than ~120 chars are truncated by the front-end so a
	// huge payload (script block, RECmd ValueData) doesn't blow up the
	// pivot panel.
	ContextFields []string `json:"contextFields,omitempty"`
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
	// PrimaryTime mirrors ArtifactType.PrimaryTime so the front-end can
	// run cross-artifact time-window correlation without needing a
	// separate types lookup. Empty string if the artifact has no
	// canonical timestamp column (skip during time correlation).
	PrimaryTime string `json:"primaryTime,omitempty"`
	// ContextFields mirrors ArtifactType.ContextFields. Front-end uses
	// it to render a per-row context line in cross-artifact pivot results.
	ContextFields []string `json:"contextFields,omitempty"`
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

	// Phase-1 host-overview fields. Populated by the preprocessor from
	// offline registry hives + KAPE collection metadata. All four are
	// optional pointers so existing host.json files without these
	// blocks just produce nil and the UI shows "Not collected" for
	// missing cards.
	Identity *HostIdentity `json:"identity,omitempty"`
	Hardware *HostHardware `json:"hardware,omitempty"`
	Network  *HostNetwork  `json:"network,omitempty"`
	Triage   *HostTriage   `json:"triage,omitempty"`

	// ArtifactSummaries are populated at discovery time; full row data
	// is fetched on demand.
	ArtifactSummaries []ArtifactSummary `json:"artifacts"`
}

// HostIdentity captures the static who-is-this-machine fields. Everything
// here is sourced from offline registry hives (SOFTWARE for OS strings,
// SYSTEM for hostname/timezone/domain) so we can populate the full set
// even when running against a mounted image.
type HostIdentity struct {
	Hostname  string `json:"hostname,omitempty"`
	FQDN      string `json:"fqdn,omitempty"`
	Domain    string `json:"domain,omitempty"`
	OS        string `json:"os,omitempty"`        // "Windows 11 Pro"
	OSVersion string `json:"osVersion,omitempty"` // "22H2"
	Build     string `json:"build,omitempty"`     // "10.0.22621.4317"
	Arch      string `json:"arch,omitempty"`      // "x64"
	TimeZone  string `json:"timeZone,omitempty"`  // "UTC-05:00 (EST)"
}

// HostHardware captures CPU/RAM/disk specs. Sizes are stored as raw
// bytes (uint64) so the UI does its own formatting; storing pretty
// strings like "32 GB" would be lossy when summing across hosts or
// comparing.
//
// Most of these fields come from the Win32_* CIM classes when running
// against a live machine. Offline-image preprocessing only fills the
// subset that's reliably available in registry hives (largely just
// LastBoot from the System event log, with hardware specs absent
// unless KAPE collected the HARDWARE hive).
type HostHardware struct {
	CPUModel       string `json:"cpuModel,omitempty"`
	CPUCores       int    `json:"cpuCores,omitempty"`
	CPUThreads     int    `json:"cpuThreads,omitempty"`
	RAMBytes       uint64 `json:"ramBytes,omitempty"`
	DiskKind       string `json:"diskKind,omitempty"`  // "NVMe" / "SSD" / "HDD"
	DiskBytes      uint64 `json:"diskBytes,omitempty"` // total capacity
	DiskUsedPct    int    `json:"diskUsedPercent,omitempty"`
	LastBoot       string `json:"lastBoot,omitempty"` // ISO 8601 UTC
}

// HostNetwork captures network identifiers. Most workstations have one
// NIC; servers and VMs often have multiple, so IPv4 and MAC are arrays
// rather than scalars. Gateway and DNS are usually shared across NICs
// (the primary route is what matters) so single values there.
type HostNetwork struct {
	IPv4    []string `json:"ipv4,omitempty"`
	MAC     []string `json:"mac,omitempty"`
	Gateway string   `json:"gateway,omitempty"`
	DNS     []string `json:"dns,omitempty"`
}

// HostTriage captures who collected this host's artifacts, when, and how.
// Distinct from analysis metadata (which lives in case.json or analyst
// profiles); this is the chain-of-collection record.
type HostTriage struct {
	Method      string   `json:"method,omitempty"`      // "KAPE → EZ Tools"
	Operator    string   `json:"operator,omitempty"`    // analyst email/handle
	Targets     []string `json:"targets,omitempty"`     // KAPE target names
	StartedAt   string   `json:"startedAt,omitempty"`   // ISO 8601 UTC
	CompletedAt string   `json:"completedAt,omitempty"` // ISO 8601 UTC
	SizeBytes   uint64   `json:"sizeBytes,omitempty"`   // collection size on disk
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
	// SeverityCounts is the per-severity row breakdown for artifacts
	// that surface severity (Hayabusa, MPLog). Keys are canonical
	// labels: "critical", "high", "medium", "low", "info". Artifacts
	// without per-row severity (MFT, Amcache, etc.) omit this field
	// entirely; the JSON tag is omitempty so a nil map disappears.
	//
	// Phase 2 host overview reads these per-artifact and sums them
	// for the host-level detections histogram.
	SeverityCounts map[string]int `json:"severityCounts,omitempty"`
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
