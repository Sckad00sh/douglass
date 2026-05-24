package ingest

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/example/artifact-review/internal/model"
)

// Store is the in-memory case store. It owns the opened case, lazily loads
// artifact rows from disk, and is safe for concurrent use.
type Store struct {
	mu         sync.RWMutex
	cs         *model.Case
	loaded     map[string]*model.Artifact // key = hostID + "|" + artifactID
	emptyCount int                        // # artifacts skipped at last Open()
}

// NewStore returns an empty store. Call Open() to point it at a case folder.
func NewStore() *Store {
	return &Store{loaded: map[string]*model.Artifact{}}
}

// EmptyCount returns the number of empty artifacts that were filtered out
// during the most recent Open(). Surfaced via /api/case so the UI can
// toast about them.
func (s *Store) EmptyCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.emptyCount
}

// Open replaces the current case with the one at dir. dir must exist and
// contain at least one subdirectory under hosts/.
//
// The layout matches the README:
//
//	<dir>/
//	  case.json
//	  hosts/
//	    <host-name>/
//	      host.json
//	      artifacts/
//	        ...csv files...
//
// case.json and host.json are both optional — sensible defaults are used.
func (s *Store) Open(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve case dir: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("stat case dir: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("case path is not a directory: %s", abs)
	}

	cs := &model.Case{Dir: abs}
	// Load case.json if present. Cap the read so a malformed/huge
	// case.json (planted on disk by something we don't trust) can't OOM
	// the analyst's machine.
	if b, err := readCappedFile(filepath.Join(abs, "case.json"), 1<<20); err == nil {
		_ = json.Unmarshal(b, &cs.Info)
	}
	if cs.Info.ID == "" {
		cs.Info.ID = filepath.Base(abs)
	}
	if cs.Info.Name == "" {
		cs.Info.Name = cs.Info.ID
	}
	if cs.Info.CreatedAt == "" {
		cs.Info.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}

	// Discover hosts. The README uses <dir>/hosts/<name>, but to be friendlier
	// we also accept the case dir directly containing host subfolders.
	hostsRoot := filepath.Join(abs, "hosts")
	if _, err := os.Stat(hostsRoot); errors.Is(err, os.ErrNotExist) {
		hostsRoot = abs
	}

	entries, err := os.ReadDir(hostsRoot)
	if err != nil {
		return fmt.Errorf("read hosts dir: %w", err)
	}
	var allEmpties []EmptyArtifact
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		hostDir := filepath.Join(hostsRoot, e.Name())
		// If the directory itself looks like a non-host (no CSVs anywhere
		// below it), skip it. Empties are reported regardless of whether
		// the host has any non-empty artifacts.
		host, empties, ok := discoverHost(hostDir, e.Name())
		allEmpties = append(allEmpties, empties...)
		if !ok {
			continue
		}
		cs.Hosts = append(cs.Hosts, host)
	}

	// Write the per-case Empty_Artifacts.txt report. Best-effort: a failure
	// here doesn't prevent the case from opening — the analyst will see the
	// non-empty artifacts in the sidebar regardless, and we log the write
	// error to stderr via the returned wrapping if applicable.
	if err := writeEmptyReport(abs, allEmpties); err != nil {
		// non-fatal; don't fail the whole Open() over a report file
		fmt.Fprintf(os.Stderr, "warning: write Empty_Artifacts.txt: %v\n", err)
	}

	s.mu.Lock()
	s.cs = cs
	s.loaded = map[string]*model.Artifact{}
	s.emptyCount = len(allEmpties)
	s.mu.Unlock()
	return nil
}

// writeEmptyReport writes the human-readable Empty_Artifacts.txt at the
// case root. The format is one stanza per empty artifact, matching the
// "No data parsed" message previously shown in the UI. Re-writing on each
// Open() means the file always reflects the current state of the case
// folder; analysts who re-run the preprocessor get an up-to-date report.
//
// If there are no empties, an existing report from a prior run is removed
// so the case directory stays tidy.
func writeEmptyReport(caseDir string, empties []EmptyArtifact) error {
	target := filepath.Join(caseDir, "Empty_Artifacts.txt")
	if len(empties) == 0 {
		// best-effort cleanup; ignore "not exist" errors
		if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}

	// Sort for deterministic output: host, then artifact name.
	sort.Slice(empties, func(i, j int) bool {
		if empties[i].HostName != empties[j].HostName {
			return empties[i].HostName < empties[j].HostName
		}
		return empties[i].Name < empties[j].Name
	})

	var b strings.Builder
	fmt.Fprintf(&b, "Empty Artifacts Report\n")
	fmt.Fprintf(&b, "Generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "Case dir:  %s\n", caseDir)
	fmt.Fprintf(&b, "Count:     %d empty artifact(s)\n", len(empties))
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "These artifacts were recognised by filename but contained no data rows.\n")
	fmt.Fprintf(&b, "Either the preprocessor produced an empty file for the artifact, or the\n")
	fmt.Fprintf(&b, "underlying source on the image was empty. They are not loaded into the UI.\n")
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "%s\n", strings.Repeat("=", 72))

	for _, e := range empties {
		fmt.Fprintf(&b, "\n[%s -- %s]\n", e.HostName, e.Name)
		fmt.Fprintf(&b, "No data parsed for this artifact\n")
		fmt.Fprintf(&b, "The source CSV exists but contains no rows. Either the preprocessor\n")
		fmt.Fprintf(&b, "produced an empty file for this artifact, or the underlying source on\n")
		fmt.Fprintf(&b, "the image was empty.\n")
		fmt.Fprintf(&b, "%s\n", e.SourceFile)
	}

	// Atomic write via temp + rename to avoid a half-written report on
	// crash/interrupt mid-Open.
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}

// EmptyArtifact describes one parsed CSV that yielded zero rows. The
// front-end never sees these; instead they are aggregated into a per-case
// Empty_Artifacts.txt report so the analyst can audit what the preprocessor
// produced without artifact-shaped output.
type EmptyArtifact struct {
	HostName   string
	ArtifactID string
	Name       string
	SourceFile string
}

// discoverHost inspects a single host directory and produces a populated
// Host with artifact *summaries* (no row data yet). Returns (_, _, false)
// if the directory yields no recognised artifacts. The third return is
// "ok"; the second is the list of empty artifacts skipped for the report.
func discoverHost(dir, name string) (model.Host, []EmptyArtifact, bool) {
	host := model.Host{
		ID:   name,
		Name: name,
		Tag:  "WS", // default; overridden by host.json
	}
	// host.json metadata (cap read size so a huge planted file can't OOM).
	if b, err := readCappedFile(filepath.Join(dir, "host.json"), 1<<20); err == nil {
		_ = json.Unmarshal(b, &host)
		if host.ID == "" {
			host.ID = name
		}
		if host.Name == "" {
			host.Name = name
		}
	}

	// Look in <dir>/artifacts first, then fall back to <dir> itself.
	artDir := filepath.Join(dir, "artifacts")
	if _, err := os.Stat(artDir); errors.Is(err, os.ErrNotExist) {
		artDir = dir
	}

	// Walk a single level (don't recurse — analysts dump CSVs flat).
	files, err := os.ReadDir(artDir)
	if err != nil {
		return host, nil, false
	}

	var empties []EmptyArtifact
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		t := Recognize(f.Name())
		if t == nil {
			continue
		}
		path := filepath.Join(artDir, f.Name())
		rowCount, alertCount := quickStat(path)
		// Empty artifacts get reported but NOT added to the sidebar.
		// quickStat returns 0 either because the source CSV is header-only
		// or because the header itself failed to parse — both are
		// indistinguishable from the analyst's perspective ("the
		// preprocessor produced nothing useful here").
		if rowCount == 0 {
			empties = append(empties, EmptyArtifact{
				HostName:   host.Name,
				ArtifactID: t.ID,
				Name:       t.Name,
				SourceFile: path,
			})
			continue
		}
		host.ArtifactSummaries = append(host.ArtifactSummaries, model.ArtifactSummary{
			ID:         t.ID,
			Name:       t.Name,
			Icon:       t.Icon,
			Category:   t.Category,
			Tool:       t.Tool,
			SourceFile: path,
			RowCount:   rowCount,
			AlertCount: alertCount,
		})
	}
	if len(host.ArtifactSummaries) == 0 {
		return host, empties, false
	}
	return host, empties, true
}

// quickStat counts rows (and crit/high alerts for severity-aware artifacts)
// without keeping the full result set in memory. Streams the CSV once.
// Alerts are inferred from a "Level" column if present (case-insensitive).
func quickStat(path string) (rows, alerts int) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // tolerate ragged rows
	r.LazyQuotes = true
	header, err := r.Read()
	if err != nil {
		return 0, 0
	}
	levelIdx := -1
	for i, h := range header {
		if strings.EqualFold(h, "Level") {
			levelIdx = i
			break
		}
	}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		rows++
		if levelIdx >= 0 && levelIdx < len(rec) {
			switch strings.ToLower(strings.TrimSpace(rec[levelIdx])) {
			case "crit", "critical", "high", "error", "warning":
				alerts++
			}
		}
	}
	return rows, alerts
}

// Case returns a (deep enough) copy of the current case for JSON serialisation.
func (s *Store) Case() *model.Case {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cs
}

// LoadArtifact returns the fully-parsed artifact, loading from disk if needed.
// Subsequent calls return the cached value.
func (s *Store) LoadArtifact(hostID, artifactID string) (*model.Artifact, error) {
	key := hostID + "|" + artifactID
	s.mu.RLock()
	if a, ok := s.loaded[key]; ok {
		s.mu.RUnlock()
		return a, nil
	}
	cs := s.cs
	s.mu.RUnlock()

	if cs == nil {
		return nil, errors.New("no case open")
	}
	var sum *model.ArtifactSummary
	for hi := range cs.Hosts {
		if cs.Hosts[hi].ID != hostID {
			continue
		}
		for ai := range cs.Hosts[hi].ArtifactSummaries {
			if cs.Hosts[hi].ArtifactSummaries[ai].ID == artifactID {
				sum = &cs.Hosts[hi].ArtifactSummaries[ai]
				break
			}
		}
	}
	if sum == nil {
		return nil, fmt.Errorf("artifact %s/%s not found", hostID, artifactID)
	}

	t := findType(artifactID)
	if t == nil {
		return nil, fmt.Errorf("unknown artifact type: %s", artifactID)
	}

	rows, err := parseCSV(sum.SourceFile)
	if err != nil {
		return nil, err
	}
	art := &model.Artifact{
		ID:            t.ID,
		Name:          t.Name,
		Icon:          t.Icon,
		Category:      t.Category,
		Tool:          t.Tool,
		SourceFile:    sum.SourceFile,
		Columns:       t.Columns,
		Rows:          rows,
		RowCount:      len(rows),
		AlertCount:    sum.AlertCount,
		PrimaryTime:   t.PrimaryTime,
		ContextFields: t.ContextFields,
	}

	s.mu.Lock()
	s.loaded[key] = art
	s.mu.Unlock()
	return art, nil
}

func findType(id string) *ArtifactType {
	for i := range ArtifactTypes {
		if ArtifactTypes[i].ID == id {
			return &ArtifactTypes[i]
		}
	}
	return nil
}

// parseCSV reads the whole CSV into []Row. Header row drives the keys.
// We tolerate ragged rows and lenient quoting because EZ Tools output
// sometimes embeds quoted commas/newlines in fields.
func parseCSV(path string) ([]model.Row, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true

	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	// Strip UTF-8 BOM from the first header cell.
	if len(header) > 0 {
		header[0] = strings.TrimPrefix(header[0], "\ufeff")
	}

	// Initialize as an empty (non-nil) slice so that an artifact with zero
	// data rows marshals to JSON `[]` instead of `null`. Front-end can't
	// call .map() on null without a defensive guard, and we'd rather not
	// rely on that.
	out := []model.Row{}
	for i := 0; ; i++ {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Skip malformed rows rather than abort the whole load.
			continue
		}
		row := model.Row{"__row": fmt.Sprintf("%d", i)}
		for j, h := range header {
			if j < len(rec) {
				row[h] = rec[j]
			}
		}
		out = append(out, row)
	}
	return out, nil
}

// readCappedFile reads up to max bytes from a file. If the file is
// larger than max, the read succeeds with the first max bytes only --
// callers treat that as a normal short read (typically the unmarshal
// fails, falling back to defaults). Used to harden metadata reads
// (case.json, host.json) against a planted huge file OOMing the
// process. The cap is per-file: a 1 MB metadata budget per artifact
// is far above any legitimate workflow.
func readCappedFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}
