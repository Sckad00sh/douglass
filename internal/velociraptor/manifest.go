package velociraptor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ManifestName is the dedup manifest's filename. It lives in the central
// collections folder (next to the zips it tracks), NOT in the Douglas
// repo -- it's case data, so it travels with the evidence share and any
// Douglas pointed at that folder sees what's already imported. The
// leading dot keeps it out of casual directory views.
const ManifestName = ".douglas-imported.json"

// Manifest records which collections have already been imported, keyed
// by Velociraptor session_id (stable + unique per collection). It is
// read and rewritten atomically; concurrent imports from one process are
// serialized by the mutex, and the temp+rename write guards against a
// torn file if the process dies mid-write.
type Manifest struct {
	path string
	mu   sync.Mutex
	data manifestData
}

type manifestData struct {
	Version int                   `json:"version"`
	Entries map[string]ManifestEntry `json:"entries"` // session_id -> entry
}

// ManifestEntry is one imported collection's record.
type ManifestEntry struct {
	SessionID  string `json:"sessionId"`
	Hostname   string `json:"hostname"`
	SourceZip  string `json:"sourceZip"`  // basename of the collection zip
	ImportedAt string `json:"importedAt"` // RFC3339
	CaseDir    string `json:"caseDir"`    // where it was imported to
}

// LoadManifest opens (or initializes) the manifest in the given
// collections folder. A missing manifest is not an error -- it starts
// empty. A corrupt manifest is also tolerated (starts empty + will be
// rewritten on the next save), because losing dedup state is a nuisance,
// not data loss: at worst a collection is re-imported.
func LoadManifest(collectionsDir string) (*Manifest, error) {
	p := filepath.Join(collectionsDir, ManifestName)
	m := &Manifest{
		path: p,
		data: manifestData{Version: 1, Entries: map[string]ManifestEntry{}},
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var d manifestData
	if err := json.Unmarshal(b, &d); err != nil {
		// Corrupt -- start fresh rather than fail the whole import.
		return m, nil
	}
	if d.Entries == nil {
		d.Entries = map[string]ManifestEntry{}
	}
	if d.Version == 0 {
		d.Version = 1
	}
	m.data = d
	return m, nil
}

// Has reports whether a collection with this session_id was already
// imported.
func (m *Manifest) Has(sessionID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.data.Entries[sessionID]
	return ok
}

// Get returns the recorded entry for a session_id, if present.
func (m *Manifest) Get(sessionID string) (ManifestEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.data.Entries[sessionID]
	return e, ok
}

// Record adds (or replaces) an entry and persists the manifest.
func (m *Manifest) Record(e ManifestEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.ImportedAt == "" {
		e.ImportedAt = time.Now().UTC().Format(time.RFC3339)
	}
	m.data.Entries[e.SessionID] = e
	return m.saveLocked()
}

// saveLocked writes the manifest atomically (temp + rename). Caller holds
// the mutex.
func (m *Manifest) saveLocked() error {
	b, err := json.MarshalIndent(m.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, m.path); err != nil {
		return err
	}
	return nil
}

// Entries returns a snapshot of all recorded entries, sorted by import
// time (newest first) for display.
func (m *Manifest) Entries() []ManifestEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ManifestEntry, 0, len(m.data.Entries))
	for _, e := range m.data.Entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ImportedAt > out[j].ImportedAt
	})
	return out
}
