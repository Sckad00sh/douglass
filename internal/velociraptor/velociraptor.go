// Package velociraptor adapts Velociraptor offline-collector output into
// the on-disk layout Douglas's preprocessor expects.
//
// A Velociraptor offline collection is a zip whose raw files live under
// two upload roots, with URL-encoded path segments:
//
//	uploads/auto/C%3A/<path>              normal files (hives, evtx, prefetch, amcache, ...)
//	uploads/ntfs/%5C%5C.%5CC%3A/<path>    raw-NTFS specials ($MFT, $Extend/$UsnJrnl%3A$J, ...)
//
// plus metadata at the root:
//
//	client_info.json           hostname, OS, timezone, FQDN, arch
//	collection_context.json    session_id (our dedup key), timing
//
// The preprocessor, by contrast, wants a plain "C:\ root" tree:
//
//	<root>/Windows/System32/config/SYSTEM
//	<root>/$MFT
//	<root>/$Extend/$UsnJrnl:$J
//	<root>/Users/<user>/NTUSER.DAT
//	...
//
// This package extracts a collection, normalizes the two upload roots
// into one synthetic C:\ tree (URL-decoding segments; hardlinking files
// into place, falling back to copy), and surfaces the collection's
// metadata so the caller can set host identity and skip duplicates.
//
// All of the Velociraptor-specific knowledge is isolated here; nothing
// downstream (the PS1 preprocessor, ingest) changes.
package velociraptor

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ClientInfo mirrors the fields of client_info.json that we use for host
// identity. Unknown fields are ignored.
type ClientInfo struct {
	Hostname        string `json:"Hostname"`
	OS              string `json:"OS"`
	Platform        string `json:"Platform"`        // "Microsoft Windows 11 Pro"
	PlatformVersion string `json:"PlatformVersion"` // "25H2"
	KernelVersion   string `json:"KernelVersion"`
	Fqdn            string `json:"Fqdn"`
	Architecture    string `json:"Architecture"`
	LocalTZ         string `json:"LocalTZ"`        // "PDT"
	LocalTZOffset   int    `json:"LocalTZOffset"`  // seconds, e.g. -25200
	HostID          string `json:"HostID"`
}

// CollectionContext mirrors the fields of collection_context.json we use.
type CollectionContext struct {
	SessionID  string `json:"session_id"`  // "F.DB3SBMR8K52S6" -- our dedup key
	CreateTime int64  `json:"create_time"` // nanoseconds
}

// Metadata is the combined, caller-facing view of a collection's identity.
type Metadata struct {
	// SessionID is the Velociraptor collection's unique id. It is the
	// stable dedup key: the same collection always carries the same
	// session_id, and two different collections never share one.
	SessionID string
	Hostname  string
	OS        string // "Microsoft Windows 11 Pro"
	OSVersion string // "25H2"
	Fqdn      string
	Arch      string
	TimeZone  string // "PDT" (abbrev) or a UTC offset string if abbrev missing
	// TZOffsetSeconds is the raw local-TZ offset; used to synthesize a
	// "UTC-07:00" style string when only the abbreviation is unhelpful.
	TZOffsetSeconds int
}

// PeekMetadata reads just the two small JSON metadata members from a
// collection zip, without extracting the (large) raw files. Used for the
// dedup pre-check and to show the analyst what a collection contains
// before committing to a full extract + parse.
func PeekMetadata(zipPath string) (Metadata, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return Metadata{}, fmt.Errorf("open collection zip: %w", err)
	}
	defer zr.Close()

	var ci ClientInfo
	var cc CollectionContext
	gotCI, gotCC := false, false
	for _, f := range zr.File {
		switch path.Clean(f.Name) {
		case "client_info.json":
			if err := readZipJSON(f, &ci, 1<<20); err == nil {
				gotCI = true
			}
		case "collection_context.json":
			if err := readZipJSON(f, &cc, 1<<20); err == nil {
				gotCC = true
			}
		}
		if gotCI && gotCC {
			break
		}
	}
	if !gotCC || cc.SessionID == "" {
		// Without a session_id we can't dedup reliably. That's a hard
		// signal this isn't a Velociraptor offline collection.
		return Metadata{}, fmt.Errorf("not a Velociraptor collection (no session_id in collection_context.json)")
	}

	m := Metadata{
		SessionID:       cc.SessionID,
		Hostname:        ci.Hostname,
		OS:              ci.Platform,
		OSVersion:       ci.PlatformVersion,
		Fqdn:            ci.Fqdn,
		Arch:            ci.Architecture,
		TimeZone:        ci.LocalTZ,
		TZOffsetSeconds: ci.LocalTZOffset,
	}
	return m, nil
}

// Normalize extracts the collection at zipPath and lays its raw files
// into destRoot as a synthetic C:\ tree the preprocessor can consume.
// It returns the collection metadata. destRoot must be an existing
// empty directory the caller controls (a staging area).
//
// Files are placed by hardlink when possible (same volume) and by copy
// otherwise -- a 300 MB collection shouldn't be duplicated on disk when
// the staging area shares a volume with the extraction. Because
// archive/zip has no on-disk file to hardlink from, we extract each
// upload entry straight to its normalized destination (one write, no
// intermediate copy) -- so "hardlink vs copy" only matters if the caller
// later re-stages; here every file is written once.
func Normalize(zipPath, destRoot string) (Metadata, error) {
	meta, err := PeekMetadata(zipPath)
	if err != nil {
		return Metadata{}, err
	}

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return Metadata{}, fmt.Errorf("open collection zip: %w", err)
	}
	defer zr.Close()

	destAbs, err := filepath.Abs(destRoot)
	if err != nil {
		return Metadata{}, err
	}

	var wrote int
	for _, f := range zr.File {
		rel, ok := mapUploadPath(f.Name)
		if !ok {
			continue // not a raw-file upload entry (metadata, results, .idx, dirs)
		}
		if f.FileInfo().IsDir() {
			continue
		}
		// Resolve + contain: the mapped relative path must stay within
		// destRoot. mapUploadPath already URL-decodes and strips the
		// upload-root prefix; this is the zip-slip backstop.
		target := filepath.Join(destAbs, rel)
		if !withinRoot(destAbs, target) {
			// A crafted entry tried to escape the staging dir. Skip it;
			// never write outside destRoot.
			continue
		}
		if err := extractOne(f, target); err != nil {
			return Metadata{}, fmt.Errorf("extract %q: %w", f.Name, err)
		}
		wrote++
	}
	if wrote == 0 {
		return Metadata{}, fmt.Errorf("no recognizable upload files found in collection (is this a Velociraptor offline collection?)")
	}
	return meta, nil
}

// mapUploadPath converts a zip entry name from the Velociraptor upload
// layout to a C:\-root-relative path, or returns ok=false for entries
// that aren't raw files (metadata JSON, results/, .idx sidecars, the
// upload-root dirs themselves).
//
// Examples:
//
//	uploads/auto/C%3A/Windows/System32/config/SYSTEM
//	    -> Windows/System32/config/SYSTEM
//	uploads/ntfs/%5C%5C.%5CC%3A/$MFT
//	    -> $MFT
//	uploads/ntfs/%5C%5C.%5CC%3A/$Extend/$UsnJrnl%3A$J
//	    -> $Extend/$UsnJrnl:$J
func mapUploadPath(name string) (string, bool) {
	name = strings.TrimPrefix(path.Clean(name), "./")
	// Sidecar index files are Velociraptor bookkeeping, not evidence.
	if strings.HasSuffix(name, ".idx") {
		return "", false
	}
	const (
		autoPrefix = "uploads/auto/"
		ntfsPrefix = "uploads/ntfs/"
	)
	var rest string
	switch {
	case strings.HasPrefix(name, autoPrefix):
		rest = name[len(autoPrefix):]
	case strings.HasPrefix(name, ntfsPrefix):
		rest = name[len(ntfsPrefix):]
	default:
		return "", false
	}
	// rest begins with the device segment: "C%3A" (auto) or
	// "%5C%5C.%5CC%3A" (ntfs, i.e. "\\.\C:"). Decode every segment, then
	// drop the leading drive component so paths are drive-root-relative.
	segs := strings.Split(rest, "/")
	decoded := make([]string, 0, len(segs))
	for _, s := range segs {
		d, err := url.PathUnescape(s)
		if err != nil {
			d = s // tolerate a bad escape rather than drop the file
		}
		decoded = append(decoded, d)
	}
	if len(decoded) == 0 {
		return "", false
	}
	// First segment is the device: "C:" or "\\.\C:". Verify it looks like
	// a drive root, then drop it.
	dev := decoded[0]
	if !isDriveSegment(dev) {
		return "", false
	}
	relSegs := decoded[1:]
	if len(relSegs) == 0 {
		return "", false
	}
	// Rejoin with the OS separator. On the analyst's Windows box this
	// yields Windows\... and $Extend\$UsnJrnl:$J; the preprocessor's
	// Join-Path calls expect exactly that.
	return filepath.Join(relSegs...), true
}

// isDriveSegment reports whether a decoded first segment is a drive root
// like "C:" or a raw device path like "\\.\C:".
func isDriveSegment(s string) bool {
	s = strings.TrimPrefix(s, `\\.\`)
	return len(s) == 2 && s[1] == ':' &&
		((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z'))
}

// extractOne writes a single zip entry to target, creating parent dirs.
func extractOne(f *zip.File, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, rc); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// withinRoot reports whether target is inside root (after cleaning).
// The zip-slip backstop: even if mapUploadPath produced something with
// "..", filepath.Join cleans it and this check rejects any escape.
func withinRoot(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// readZipJSON reads a zip entry's content (capped) and unmarshals it.
func readZipJSON(f *zip.File, v any, cap int64) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, cap))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
