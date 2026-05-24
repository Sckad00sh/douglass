package marks

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/example/artifact-review/internal/model"
)

// Store owns the marks for an open case. Writes are debounced (~500ms)
// so rapid note edits don't hammer the disk.
type Store struct {
	mu      sync.RWMutex
	caseDir string
	marks   map[string]*model.Mark // by Mark.ID

	dirty     bool
	flushCh   chan struct{}
	stopCh    chan struct{}
	doneCh    chan struct{}    // closed when the flusher goroutine exits
	startedCh chan struct{}    // closed once startFlusher has been called
	once      sync.Once
}

// New returns an empty store. Call Open() to bind to a case directory.
func New() *Store {
	return &Store{
		marks:     map[string]*model.Mark{},
		flushCh:   make(chan struct{}, 1),
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
		startedCh: make(chan struct{}),
	}
}

// Open binds the store to <caseDir>/marks.json. If the file exists, marks
// are loaded; otherwise the store starts empty.
func (s *Store) Open(caseDir string) error {
	s.mu.Lock()
	s.caseDir = caseDir
	s.marks = map[string]*model.Mark{}
	s.mu.Unlock()

	// Cap the read so a planted/corrupted marks.json can't OOM us.
	// 16 MB allows for tens of thousands of marks; far above any
	// real-world case.
	f, err := os.Open(filepath.Join(caseDir, "marks.json"))
	if errors.Is(err, os.ErrNotExist) {
		s.once.Do(s.startFlusher)
		return nil
	}
	if err != nil {
		return err
	}
	b, err := io.ReadAll(io.LimitReader(f, 16<<20))
	_ = f.Close()
	if err != nil {
		return err
	}
	var list []*model.Mark
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	s.mu.Lock()
	for _, m := range list {
		s.marks[m.ID] = m
	}
	s.mu.Unlock()
	s.once.Do(s.startFlusher)
	return nil
}

// startFlusher launches the background goroutine that performs debounced
// writes. Closed via Close().
func (s *Store) startFlusher() {
	close(s.startedCh)
	go func() {
		defer close(s.doneCh)
		var pending bool
		var timer *time.Timer
		for {
			select {
			case <-s.stopCh:
				if pending {
					_ = s.flushNow()
				}
				return
			case <-s.flushCh:
				pending = true
				if timer == nil {
					timer = time.NewTimer(500 * time.Millisecond)
				} else {
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					timer.Reset(500 * time.Millisecond)
				}
			case <-timerCh(timer):
				if pending {
					_ = s.flushNow()
					pending = false
				}
				timer = nil
			}
		}
	}()
}

// timerCh returns t.C or nil — nil channels block forever in a select,
// which is what we want when no debounce is pending.
func timerCh(t *time.Timer) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C
}

// Close stops the flusher and writes any pending changes. Blocks until
// the flusher has drained any in-flight debounce.
func (s *Store) Close() {
	// Guard against multiple Close() calls.
	select {
	case <-s.stopCh:
		return
	default:
		close(s.stopCh)
	}
	// If Open() was never called, no flusher is running and nothing is dirty.
	select {
	case <-s.startedCh:
		// flusher is running; wait for it to drain.
	default:
		return
	}
	select {
	case <-s.doneCh:
	case <-time.After(2 * time.Second):
		// Pathological: flusher stuck. Bail.
	}
}

// List returns all marks, sorted by extracted timestamp ascending.
// Pass hostID = "" for global scope.
func (s *Store) List(hostID string) []*model.Mark {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Mark, 0, len(s.marks))
	for _, m := range s.marks {
		if hostID == "" || m.HostID == hostID {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Timestamp < out[j].Timestamp
	})
	return out
}

// Get returns a single mark by ID, or nil.
func (s *Store) Get(id string) *model.Mark {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.marks[id]
}

// Upsert inserts or updates a mark. The ID is derived from hostID, artifactID,
// and rowKey; the caller supplies the row snapshot and any analyst-driven
// fields (note, severity).
func (s *Store) Upsert(m *model.Mark) {
	if m.ID == "" {
		m.ID = MakeID(m.HostID, m.ArtifactID, m.RowKey)
	}
	if m.CreatedAt == "" {
		m.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	s.mu.Lock()
	s.marks[m.ID] = m
	s.dirty = true
	s.mu.Unlock()
	s.scheduleFlush()
}

// Delete removes a mark by ID. No-op if absent.
func (s *Store) Delete(id string) {
	s.mu.Lock()
	if _, ok := s.marks[id]; !ok {
		s.mu.Unlock()
		return
	}
	delete(s.marks, id)
	s.dirty = true
	s.mu.Unlock()
	s.scheduleFlush()
}

func (s *Store) scheduleFlush() {
	select {
	case s.flushCh <- struct{}{}:
	default:
	}
}

// flushNow synchronously writes the current marks to disk via a temp file
// + rename, which is atomic on every supported OS.
func (s *Store) flushNow() error {
	s.mu.RLock()
	if !s.dirty || s.caseDir == "" {
		s.mu.RUnlock()
		return nil
	}
	list := make([]*model.Mark, 0, len(s.marks))
	for _, m := range s.marks {
		list = append(list, m)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt < list[j].CreatedAt })
	caseDir := s.caseDir
	s.mu.RUnlock()

	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	target := filepath.Join(caseDir, "marks.json")
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		return err
	}
	s.mu.Lock()
	s.dirty = false
	s.mu.Unlock()
	return nil
}

// MakeID builds the canonical mark ID: hostID|artifactID|rowKey.
func MakeID(hostID, artifactID, rowKey string) string {
	return hostID + "|" + artifactID + "|" + rowKey
}

// RowKey derives a stable hash for a row so marks survive re-parses.
// Combines a few distinguishing column values; falls back to the row index.
func RowKey(row map[string]string) string {
	// Prefer a stable subset of high-signal columns over the row's
	// in-file index, which can shift across re-parses.
	preferred := []string{
		"Timestamp", "TimeCreated", "LastRun", "FileKeyLastWriteTimestamp",
		"Created0x10", "LastModified0x10", "EntryNumber",
		"FileName", "FullPath", "Path", "LocalPath", "TargetPath",
		"RuleTitle", "MapDescription", "ApplicationName", "ExecutableName",
	}
	parts := make([]string, 0, len(preferred))
	for _, k := range preferred {
		if v := row[k]; v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	if len(parts) == 0 {
		return row["__row"]
	}
	h := sha1.Sum([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:8])
}

// ExtractTimestamp returns the best timestamp for a row, per the priority
// list in README.md.
func ExtractTimestamp(row map[string]string) string {
	for _, k := range []string{
		"Timestamp", "TimeCreated", "LastRun",
		"FileKeyLastWriteTimestamp", "LastModifiedTimeUTC",
		"Created0x10", "LastWriteTimestamp",
		"SourceCreated", "TargetCreated", "LastModified",
	} {
		if v, ok := row[k]; ok && v != "" {
			return v
		}
	}
	return ""
}

// ExtractLabel returns the best display label for a row.
func ExtractLabel(row map[string]string) string {
	for _, k := range []string{
		"RuleTitle", "MapDescription", "ExecutableName",
		"ApplicationName", "Path", "FullPath", "FileName", "KeyPath",
	} {
		if v, ok := row[k]; ok && v != "" {
			return v
		}
	}
	return "(no label)"
}

// DeriveSeverity returns the severity for a row given its artifact type.
//
//	hayabusa  -> use the Level column verbatim, mapped to our enum
//	evtx      -> Error => crit, Warning => high, else info
//	all else  -> info
func DeriveSeverity(artifactID string, row map[string]string) model.Severity {
	switch artifactID {
	case "hayabusa":
		switch strings.ToLower(strings.TrimSpace(row["Level"])) {
		case "crit", "critical":
			return model.SevCrit
		case "high":
			return model.SevHigh
		case "med", "medium":
			return model.SevMed
		case "low":
			return model.SevLow
		case "info", "informational":
			return model.SevInfo
		}
	case "evtx":
		switch strings.ToLower(strings.TrimSpace(row["Level"])) {
		case "error", "critical":
			return model.SevCrit
		case "warning":
			return model.SevHigh
		}
	}
	return model.SevInfo
}
