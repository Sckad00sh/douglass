package velociraptor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CollectionPlan is one collection's place in an import run: what it is,
// and whether it will be imported or skipped (and why).
type CollectionPlan struct {
	ZipPath  string   // absolute path to the collection zip
	ZipName  string   // basename
	Meta     Metadata // parsed from the zip (may be zero if unreadable)
	Skip     bool     // true -> not imported this run
	SkipWhy  string   // human-readable reason when Skip is true
	ReadErr  string   // non-empty if the zip couldn't be read as a collection
}

// Imported reports whether this plan entry will actually be parsed.
func (p CollectionPlan) Imported() bool { return !p.Skip && p.ReadErr == "" }

// PlanImport scans collectionsDir for Velociraptor collection zips and
// decides, for each, whether it will be imported or skipped. It does NOT
// extract or parse anything -- it only peeks metadata (cheap) so the
// caller can show a plan / confirmation before committing to the work.
//
// A zip is skipped when its session_id is already in the manifest
// (unless force is set). A zip that doesn't look like a Velociraptor
// collection is flagged with ReadErr and skipped. Non-zip files are
// ignored entirely.
func PlanImport(collectionsDir string, man *Manifest, force bool) ([]CollectionPlan, error) {
	entries, err := os.ReadDir(collectionsDir)
	if err != nil {
		return nil, fmt.Errorf("read collections dir: %w", err)
	}
	var plans []CollectionPlan
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.EqualFold(filepath.Ext(name), ".zip") {
			continue
		}
		abs := filepath.Join(collectionsDir, name)
		plan := CollectionPlan{ZipPath: abs, ZipName: name}

		meta, err := PeekMetadata(abs)
		if err != nil {
			// Not a Velociraptor collection (or unreadable). Record the
			// reason; the caller surfaces it so a stray/wrong zip in the
			// folder is visible rather than silently ignored.
			plan.ReadErr = err.Error()
			plan.Skip = true
			plan.SkipWhy = "not a Velociraptor collection"
			plans = append(plans, plan)
			continue
		}
		plan.Meta = meta

		if !force && man != nil && man.Has(meta.SessionID) {
			plan.Skip = true
			if e, ok := man.Get(meta.SessionID); ok && e.ImportedAt != "" {
				plan.SkipWhy = fmt.Sprintf("already imported %s (host %s)", e.ImportedAt, e.Hostname)
			} else {
				plan.SkipWhy = "already imported"
			}
		}
		plans = append(plans, plan)
	}
	return plans, nil
}

// HostDirName returns a filesystem-safe host directory name for a
// collection, derived from its hostname (falling back to the session_id
// if the hostname is empty or unusable). Mirrors the sanitation the
// preprocessor applies to -HostName.
func HostDirName(meta Metadata) string {
	base := strings.TrimSpace(meta.Hostname)
	if base == "" {
		base = meta.SessionID
	}
	// Replace anything outside a conservative safe set.
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "._")
	if out == "" {
		out = "host_" + meta.SessionID
	}
	return out
}
