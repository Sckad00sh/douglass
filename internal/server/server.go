package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/example/artifact-review/internal/ingest"
	"github.com/example/artifact-review/internal/jobs"
	"github.com/example/artifact-review/internal/marks"
	"github.com/example/artifact-review/internal/model"
	"github.com/example/artifact-review/internal/preprocess"
	"github.com/example/artifact-review/internal/triage"
)

// Server wires together the ingest store, mark store, jobs tracker,
// preprocessor runner (optional, may be nil if PowerShell isn't
// available), and static assets.
type Server struct {
	cases      *ingest.Store
	marks      *marks.Store
	jobs       *jobs.Store
	preprocess *preprocess.Runner // may be nil
	assets     fs.FS
}

// New constructs a server around the given dependencies. assets must be a
// filesystem rooted at the directory containing index.html. preprocRunner
// may be nil; when nil, the /api/preprocess endpoints return 503 with a
// "no PowerShell interpreter found" message, and the UI suppresses the
// preprocess wizard entry points.
func New(cases *ingest.Store, marks *marks.Store, jobsStore *jobs.Store, preprocRunner *preprocess.Runner, assets fs.FS) *Server {
	return &Server{
		cases:      cases,
		marks:      marks,
		jobs:       jobsStore,
		preprocess: preprocRunner,
		assets:     assets,
	}
}

// Routes returns an http.Handler with all API + static routes wired up.
//
//	GET  /api/case               full case description (hosts + summaries)
//	POST /api/open               { dir } - open a case from a path
//	GET  /api/browse?dir=        directory listing (dirs only) for UI browser
//	GET  /api/artifact-types     registry of known artifact types
//	GET  /api/artifact?h&a       full artifact rows for a host
//	GET  /api/triage?host=       quick-hit triage findings for a host
//	GET  /api/marks?host=        list marks (optionally scoped to a host)
//	POST /api/marks              upsert a mark (body: full Mark JSON)
//	DEL  /api/marks/{id}         delete a mark
//	POST /api/upload?host=&type= multipart upload of an artifact CSV
//	GET  /api/jobs               list active + recent jobs
//	GET  /api/jobs/{id}          single job detail
//	DEL  /api/jobs/{id}          cancel a running job
//	GET  /api/preprocess         info: { available, interpreter, scriptPath }
//	GET  /api/preprocess/tools   list of valid -ToolFilter values
//	POST /api/preprocess         { config } - run preprocessor as a job
//	GET  /api/health             liveness check
//	GET  /*                      static UI assets
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/case", s.handleCase)
	mux.HandleFunc("/api/open", s.handleOpen)
	mux.HandleFunc("/api/browse", s.handleBrowse)
	mux.HandleFunc("/api/artifact-types", s.handleArtifactTypes)
	mux.HandleFunc("/api/artifact", s.handleArtifact)
	mux.HandleFunc("/api/triage", s.handleTriage)
	mux.HandleFunc("/api/marks", s.handleMarks)
	mux.HandleFunc("/api/marks/", s.handleMarkByID)
	mux.HandleFunc("/api/upload", s.handleUpload)
	mux.HandleFunc("/api/jobs", s.handleJobs)
	mux.HandleFunc("/api/jobs/", s.handleJobByID)
	mux.HandleFunc("/api/preprocess", s.handlePreprocess)
	mux.HandleFunc("/api/preprocess/tools", s.handlePreprocessTools)
	mux.Handle("/", s.staticHandler())
	return localOnly(mux)
}

// localOnly wraps a handler with two defenses against attackers reaching
// the local API through the analyst's browser:
//
//  1. Host header allowlist. DNS rebinding lets a remote origin trick a
//     browser into sending requests to 127.0.0.1, but the Host header
//     will still contain the original (attacker-controlled) hostname.
//     We accept only 127.0.0.1[:port], localhost[:port], [::1][:port],
//     which is what the user's own UI sends.
//
//  2. CSRF guard via custom header on mutating verbs. Browsers won't send
//     a custom X-Requested-By header on simple cross-origin requests
//     without a CORS preflight, and we never return Access-Control-Allow-*
//     headers, so the preflight fails -- blocking the real request before
//     it's sent. (GETs are also state-mutating in /api/open's case via
//     side effect of opening a case, so we apply the guard to all
//     /api/* requests except /api/health.)
//
// Both defenses are belt-and-braces. The Host check alone would suffice
// against most DNS rebinding tools, but the CSRF header also protects
// against a misconfigured browser proxy or a future change that loosens
// the Host check.
func localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Defense-in-depth headers. Set BEFORE any short-circuit reply
		// so even error responses carry them.
		//
		// CSP is strict because the UI is purely same-origin: one
		// external <script src="app.js"> and a few <link rel="stylesheet">,
		// no inline script, no inline style="..." attributes (checked at
		// audit time). 'none' on frame-ancestors and form-action denies
		// clickjacking and form-action exfiltration. base-uri 'none'
		// prevents a <base> tag from being injected to redirect resource
		// loads.
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self'; "+
				"img-src 'self' data:; "+
				"font-src 'self'; "+
				"connect-src 'self'; "+
				"frame-ancestors 'none'; "+
				"form-action 'none'; "+
				"base-uri 'none'")
		// Belt-and-braces clickjacking guard for older browsers that
		// honor X-Frame-Options but not CSP frame-ancestors.
		h.Set("X-Frame-Options", "DENY")
		// Don't let the browser sniff text/plain as text/html.
		h.Set("X-Content-Type-Options", "nosniff")
		// No referrer leak when the analyst clicks an external link --
		// not that we have any, but defense in depth.
		h.Set("Referrer-Policy", "no-referrer")

		if !hostAllowed(r.Host) {
			http.Error(w, "forbidden: bad Host header", http.StatusForbidden)
			return
		}
		// CSRF guard for API calls. /api/health is exempt so a simple
		// curl-from-shell sanity check works.
		if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/health" {
			if r.Header.Get("X-Requested-By") != "douglas" {
				http.Error(w, "forbidden: missing X-Requested-By", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// hostAllowed returns true if the request's Host header points at a
// loopback address. r.Host may or may not include a port:
//   - "127.0.0.1:8080"  -> port present, IPv4
//   - "127.0.0.1"       -> bare IPv4
//   - "localhost:8080"  -> port present, name
//   - "localhost"       -> bare name
//   - "[::1]:8080"      -> port present, IPv6 (bracketed)
//   - "::1"             -> bare IPv6 (no brackets, no port)
//
// We use net.SplitHostPort to peel off a port when one's present; if
// SplitHostPort errors (no port), we treat the whole string as the host.
// That handles bare IPv6 correctly -- a naive LastIndexByte(':') strategy
// would chop "::1" into ":" because every colon in IPv6 looks like a
// port separator.
func hostAllowed(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		// No port present -- treat the whole value as the host.
		h = host
	}
	// Strip brackets in case SplitHostPort left them on (it shouldn't,
	// but defense in depth for malformed inputs).
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	switch h {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}


func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleCase(w http.ResponseWriter, _ *http.Request) {
	cs := s.cases.Case()
	if cs == nil {
		writeJSON(w, http.StatusOK, map[string]any{"open": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"open":       true,
		"case":       cs.Info,
		"dir":        cs.Dir,
		"hosts":      cs.Hosts,
		"emptyCount": s.cases.EmptyCount(),
	})
}

func (s *Server) handleArtifactTypes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, ingest.AllTypes())
}

// handleOpen accepts {"dir": "..."} and opens that directory as a case.
// The server only listens on 127.0.0.1, so this is roughly the same trust
// boundary as the CLI — but note that a malicious local process that
// discovered the random port could theoretically use this endpoint.
func (s *Server) handleOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	// Cap the body so a malicious client can't OOM us with a huge JSON
	// document. 64 KB is generous for {"dir": "C:\\path\\to\\case"}.
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var body struct {
		Dir string `json:"dir"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if body.Dir == "" {
		writeErr(w, http.StatusBadRequest, "dir required")
		return
	}
	if err := s.cases.Open(body.Dir); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	emptyCount := s.cases.EmptyCount()
	if err := s.marks.Open(body.Dir); err != nil {
		// non-fatal — marks file may simply not exist yet
		writeJSON(w, http.StatusOK, map[string]any{
			"open":       true,
			"emptyCount": emptyCount,
			"warning":    "marks load: " + err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"open":       true,
		"emptyCount": emptyCount,
	})
}

// BrowseEntry is one item returned by /api/browse. Only directories are
// listed; files are never exposed. hasArtifactsHint=true means at least
// one CSV in this directory matches a known Zimmerman/Hayabusa filename
// pattern, so the UI can decorate it with a "looks like a case dir" mark.
type BrowseEntry struct {
	Name             string `json:"name"`
	Path             string `json:"path"`
	HasArtifactsHint bool   `json:"hasArtifactsHint,omitempty"`
}

// handleBrowse returns a directory listing for the UI's folder browser.
// Only directories are returned; file names are not exposed.
//
//   GET /api/browse           -> filesystem roots (drives on Windows, "/" on Unix)
//   GET /api/browse?dir=<p>   -> immediate subdirs of <p>
//
// The server is bound to 127.0.0.1, so this is the same trust boundary as
// the CLI flag and /api/open. Symlinks are followed but errors are swallowed
// per-entry so a single unreadable subfolder doesn't break the listing.
func (s *Server) handleBrowse(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("dir")

	// Root listing.
	if dir == "" {
		roots := listRoots()
		writeJSON(w, http.StatusOK, map[string]any{
			"dir":       "",
			"parent":    "",
			"separator": string(filepath.Separator),
			"entries":   roots,
			"isRoot":    true,
		})
		return
	}

	// Resolve to an absolute path so the UI shows consistent paths.
	abs, err := filepath.Abs(dir)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid dir: "+err.Error())
		return
	}
	info, err := os.Stat(abs)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "stat dir: "+err.Error())
		return
	}
	if !info.IsDir() {
		writeErr(w, http.StatusBadRequest, "not a directory: "+abs)
		return
	}

	// Compute the parent. "" if we're at a filesystem root.
	parent := filepath.Dir(abs)
	if parent == abs {
		parent = ""
	}

	// List subdirectories. Skip files entirely. Sort alphabetically.
	dh, err := os.Open(abs)
	if err != nil {
		writeErr(w, http.StatusForbidden, "open dir: "+err.Error())
		return
	}
	names, err := dh.Readdirnames(-1)
	_ = dh.Close()
	if err != nil {
		writeErr(w, http.StatusForbidden, "read dir: "+err.Error())
		return
	}

	entries := make([]BrowseEntry, 0, len(names))
	var hasArtifactHere bool
	for _, name := range names {
		full := filepath.Join(abs, name)
		st, err := os.Stat(full)
		if err != nil {
			continue // unreadable; skip silently
		}
		if !st.IsDir() {
			// While we're scanning the listing anyway, check whether the
			// *current* dir contains a recognized artifact CSV. That's
			// surfaced via the response (not per-entry).
			if ingest.Recognize(name) != nil {
				hasArtifactHere = true
			}
			continue
		}
		entries = append(entries, BrowseEntry{
			Name: name,
			Path: full,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})

	// Best-effort second pass: for each direct subdirectory, scan one level
	// deeper looking for recognized CSVs. This is the signal the UI uses to
	// decorate "this folder looks like a host" in the browser. We cap it at
	// 60 entries — beyond that, the per-subdir os.Open + Readdirnames cost
	// adds up enough to feel slow over network shares, and the user can
	// just click in to check.
	if len(entries) <= 60 {
		for i := range entries {
			entries[i].HasArtifactsHint = dirHasArtifactCSV(entries[i].Path)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"dir":             abs,
		"parent":          parent,
		"separator":       string(filepath.Separator),
		"entries":         entries,
		"isRoot":          false,
		"hasArtifactHere": hasArtifactHere,
	})
}

// dirHasArtifactCSV does a shallow scan (no recursion) of one directory
// looking for any filename that matches the artifact-type registry. Returns
// fast: reads at most 64 names and bails on the first match.
func dirHasArtifactCSV(dir string) bool {
	dh, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer dh.Close()
	names, err := dh.Readdirnames(64)
	if err != nil {
		return false
	}
	for _, n := range names {
		if ingest.Recognize(n) != nil {
			return true
		}
	}
	return false
}

// listRoots returns the entries for the "no path yet" view.
//
//   Windows: enumerate A:\ through Z:\ and return those that exist.
//   Unix:    a single "/" entry. We could also add common bookmarks like
//            $HOME and /mnt, but starting at / lets the user navigate
//            anywhere without surprise.
func listRoots() []BrowseEntry {
	if runtime.GOOS == "windows" {
		out := []BrowseEntry{}
		for c := 'A'; c <= 'Z'; c++ {
			drive := string(c) + ":\\"
			if _, err := os.Stat(drive); err == nil {
				out = append(out, BrowseEntry{
					Name: string(c) + ":",
					Path: drive,
				})
			}
		}
		return out
	}
	return []BrowseEntry{
		{Name: "/", Path: "/"},
	}
}

func (s *Server) handleArtifact(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("h")
	artID := r.URL.Query().Get("a")
	if host == "" || artID == "" {
		writeErr(w, http.StatusBadRequest, "h and a query params required")
		return
	}
	art, err := s.cases.LoadArtifact(host, artID)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, art)
}

// handleTriage computes the "quick hits" triage panel for a host by
// filtering already-parsed artifacts (registry / amcache / prefetch).
// It loads each contributing artifact best-effort: a host missing any
// of them just yields empty groups for that source, not an error.
//
//	GET /api/triage?host=<id>  -> triage.Result JSON
func (s *Server) handleTriage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	host := r.URL.Query().Get("host")
	if host == "" {
		writeErr(w, http.StatusBadRequest, "host query param required")
		return
	}

	// loadRows returns the parsed rows for an artifact, or nil if the
	// host doesn't have that artifact (which is normal -- not every
	// triage collection includes every source).
	loadRows := func(artID string) []model.Row {
		art, err := s.cases.LoadArtifact(host, artID)
		if err != nil || art == nil {
			return nil
		}
		return art.Rows
	}

	arts := triage.Artifacts{
		Registry: loadRows("registry"),
		Amcache:  loadRows("amcache"),
		Prefetch: loadRows("prefetch"),
	}
	result := triage.Analyze(host, arts)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleMarks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		host := r.URL.Query().Get("host")
		writeJSON(w, http.StatusOK, s.marks.List(host))
	case http.MethodPost:
		// Cap body so a malicious client can't OOM us. Marks are tiny
		// (id, host, artifact, row key, optional note) -- 256 KB is far
		// more than enough.
		r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
		var m model.Mark
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if m.HostID == "" || m.ArtifactID == "" || m.RowKey == "" {
			writeErr(w, http.StatusBadRequest, "hostId, artifactId, rowKey required")
			return
		}
		s.marks.Upsert(&m)
		writeJSON(w, http.StatusOK, m)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleMarkByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/marks/")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "mark id required")
		return
	}
	switch r.Method {
	case http.MethodDelete:
		s.marks.Delete(id)
		writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
	case http.MethodGet:
		m := s.marks.Get(id)
		if m == nil {
			writeErr(w, http.StatusNotFound, "mark not found")
			return
		}
		writeJSON(w, http.StatusOK, m)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// uploadMaxBytes is the per-request body cap for /api/upload. 10 GB
// is the locked-in figure from the v0.11.0 design. Covers every realistic
// artifact (including outlier MFTs and big EVTX bundles); above this is
// almost certainly a memory dump or a mistake.
const uploadMaxBytes int64 = 10 * 1024 * 1024 * 1024

// sanitizedFilenameRe matches the safe character set for filenames
// we'll touch on disk. Letters, digits, dot, dash, underscore, space,
// and the dollar sign (so $MFT survives). Anything else gets replaced
// with underscore in sanitizeUploadFilename.
var sanitizedFilenameRe = regexp.MustCompile(`[^A-Za-z0-9._\- $]`)

// handleUpload accepts a multipart/form-data POST with a single file
// and routes it into the case folder. v0.11.0 supports CSV passthrough
// only -- the uploaded file must match an existing artifact type's
// filename pattern, and is copied straight into the host's artifacts/
// folder. Raw artifact preprocessing (running EZ Tools) ships in
// v0.11.1.
//
// Query parameters:
//
//	host    target host ID (must already exist in the case)
//	replace if "1", overwrite an existing artifact with the same target
//	        filename. Without this, an existing file makes the upload
//	        fail with 409 Conflict -- the UI prompts and re-submits
//	        with replace=1.
//
// Form fields:
//
//	file    the file to upload (required)
//
// Response: { jobId, status } -- the upload is async; poll /api/jobs.
//
// Security invariants enforced here:
//   - Body size cap via http.MaxBytesReader
//   - Host ID must exist in the case (no creating hosts via upload)
//   - Filename sanitized to a safe character set; analyst-provided name
//     is used only for display
//   - Output path verified to live under the host's artifacts/ folder
//     after filepath.Join (defense against pathological filenames)
//   - File must match an artifact type's filename pattern. CSV-only
//     for v0.11.0 -- raw artifacts get a clear "not yet supported"
//     error.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	caseDir := s.cases.CaseDir()
	if caseDir == "" {
		writeErr(w, http.StatusBadRequest, "no case open")
		return
	}

	// Cap the upload before parsing the multipart body. http.MaxBytesReader
	// returns an error on read once the limit is hit; multipart parsing
	// will surface that to the user as a 400.
	r.Body = http.MaxBytesReader(w, r.Body, uploadMaxBytes)

	hostID := r.URL.Query().Get("host")
	if hostID == "" {
		writeErr(w, http.StatusBadRequest, "host query parameter required")
		return
	}
	replace := r.URL.Query().Get("replace") == "1"

	// Verify the host exists. Looking up by ID against the live case
	// description -- prevents the upload endpoint from being used to
	// create new host directories via attacker-controlled hostID values.
	// We only need to know whether a match exists; the host fields
	// themselves aren't used after this check (the destination path
	// is built from hostID alone, which we just validated).
	cs := s.cases.Case()
	if cs == nil {
		writeErr(w, http.StatusBadRequest, "no case open")
		return
	}
	hostFound := false
	for _, h := range cs.Hosts {
		if h.ID == hostID {
			hostFound = true
			break
		}
	}
	if !hostFound {
		writeErr(w, http.StatusBadRequest, "unknown host: "+hostID)
		return
	}

	// Parse the multipart upload. 32 MB is the in-memory cap for parts
	// (form fields + small files); larger files spill to a temp file
	// the http package manages. The overall body cap from
	// http.MaxBytesReader still applies.
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid multipart body: "+err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "file field required: "+err.Error())
		return
	}
	defer file.Close()

	if header.Size > uploadMaxBytes {
		writeErr(w, http.StatusRequestEntityTooLarge,
			"file too large (max 10 GB)")
		return
	}

	// Sanitize the analyst-provided filename. Strip any directory path
	// components -- some browsers include the full path on Windows.
	displayName := filepath.Base(header.Filename)
	if displayName == "" || displayName == "." || displayName == "/" {
		writeErr(w, http.StatusBadRequest, "invalid filename")
		return
	}
	safeName := sanitizeUploadFilename(displayName)
	if safeName == "" {
		writeErr(w, http.StatusBadRequest, "filename has no usable characters")
		return
	}

	// Match against the artifact-type registry. CSV passthrough only
	// for v0.11.0 -- non-matching files are rejected with a clear hint.
	artType := ingest.Recognize(safeName)
	if artType == nil {
		writeErr(w, http.StatusBadRequest,
			"file does not match any known artifact type by name. "+
				"For raw-artifact processing (MFT, EVTX, registry hives, "+
				"etc.), check back in v0.11.1.")
		return
	}
	// CSV-only check. The Parser field on the artifact type indicates
	// the file isn't a CSV (currently only MPLog). v0.11.0 isn't yet
	// running tool preprocessors, so reject non-CSV uploads even when
	// they have a parser -- they need the preprocessing path that
	// ships next.
	//
	// Exception: artifacts whose Parser reads the file as-is (like
	// MPLog reading a raw .log) can pass through too -- we're just
	// copying the file, not transforming it. So the rule is: if the
	// artifact's File name matches a CSV extension OR has its own
	// Parser, accept. Otherwise reject.
	if !strings.HasSuffix(strings.ToLower(safeName), ".csv") && artType.Parser == nil {
		writeErr(w, http.StatusBadRequest,
			"only CSV uploads are supported in v0.11.0 (this file looks like "+
				"a raw artifact that needs preprocessing)")
		return
	}

	// Compute the final destination path and verify it stays inside the
	// host's artifacts folder. filepath.Join cleans but doesn't reject
	// "../" -- we check explicitly that the joined path has the host's
	// artifacts dir as a prefix.
	artifactsDir := filepath.Join(caseDir, "hosts", hostID, "artifacts")
	destPath := filepath.Join(artifactsDir, safeName)
	cleanDest, err := filepath.Abs(destPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "resolve dest path: "+err.Error())
		return
	}
	cleanArt, err := filepath.Abs(artifactsDir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "resolve artifacts dir: "+err.Error())
		return
	}
	if !strings.HasPrefix(cleanDest, cleanArt+string(filepath.Separator)) {
		writeErr(w, http.StatusBadRequest, "filename escapes artifacts directory")
		return
	}

	// Make sure the artifacts dir exists.
	if err := os.MkdirAll(cleanArt, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "create artifacts dir: "+err.Error())
		return
	}

	// If the destination already exists and replace wasn't set, 409
	// the request so the UI can prompt the analyst.
	if _, err := os.Stat(cleanDest); err == nil && !replace {
		writeErr(w, http.StatusConflict,
			"artifact already exists at this filename; re-upload with replace=1 to overwrite")
		return
	}

	// Stream the uploaded body into a temp file inside the case dir.
	// The .uploads dir is hidden from the artifact scan (Recognize
	// won't match its contents), so an interrupted upload leaves a
	// stray file but doesn't pollute the case.
	tempDir := filepath.Join(caseDir, ".uploads")
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "create temp dir: "+err.Error())
		return
	}
	tempFile, err := os.CreateTemp(tempDir, "upload-*.tmp")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create temp file: "+err.Error())
		return
	}
	tempPath := tempFile.Name()

	bytesCopied, copyErr := io.Copy(tempFile, file)
	closeErr := tempFile.Close()
	if copyErr != nil {
		_ = os.Remove(tempPath)
		writeErr(w, http.StatusBadRequest, "upload failed: "+copyErr.Error())
		return
	}
	if closeErr != nil {
		_ = os.Remove(tempPath)
		writeErr(w, http.StatusInternalServerError, "close temp file: "+closeErr.Error())
		return
	}

	// Enqueue the rest of the work as a background job: move the temp
	// file into place, then rescan the case so the new artifact shows
	// up in the next /api/case fetch.
	work := func(ctx context.Context, j *jobs.Job) (string, error) {
		s.jobs.SetProgress(j.ID, "moving file into case")

		// Best-effort cleanup on cancel.
		select {
		case <-ctx.Done():
			_ = os.Remove(tempPath)
			return "", ctx.Err()
		default:
		}

		// If we're replacing, remove the existing file first. os.Rename
		// across filesystems can fail; case temp dir + artifacts dir
		// share the case folder so this should always be cheap.
		if replace {
			if _, statErr := os.Stat(cleanDest); statErr == nil {
				if err := os.Remove(cleanDest); err != nil {
					return "", err
				}
			}
		}
		if err := os.Rename(tempPath, cleanDest); err != nil {
			return "", err
		}

		s.jobs.SetProgress(j.ID, "rescanning case")
		if err := s.cases.Open(caseDir); err != nil {
			return "", err
		}

		s.jobs.SetProgress(j.ID, "complete")
		return artType.ID, nil
	}

	j := s.jobs.Enqueue(jobs.KindUpload, hostID, displayName, "", work)

	writeJSON(w, http.StatusAccepted, map[string]any{
		"jobId":  j.ID,
		"status": j.Status,
		"size":   bytesCopied,
	})
}

// handleJobs returns the list of active and recent jobs. Front-end
// polls this every second while there are non-terminal jobs.
func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"jobs": s.jobs.List(),
	})
}

// handleJobByID is GET (single job detail) or DELETE (cancel).
func (s *Server) handleJobByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/jobs/")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "job id required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		j := s.jobs.Get(id)
		if j == nil {
			writeErr(w, http.StatusNotFound, "job not found")
			return
		}
		writeJSON(w, http.StatusOK, j)
	case http.MethodDelete:
		if !s.jobs.Cancel(id) {
			writeErr(w, http.StatusNotFound, "job not found or already terminal")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"cancelled": id})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// sanitizeUploadFilename returns a filesystem-safe rendering of the
// given filename. Path components are stripped (filepath.Base done by
// the caller), then non-safe characters are replaced with underscore.
// Returns "" if nothing survives.
func sanitizeUploadFilename(name string) string {
	if name == "" {
		return ""
	}
	// Strip any embedded NULs (shouldn't appear but defensive).
	name = strings.ReplaceAll(name, "\x00", "")
	// Replace anything outside the safe set.
	clean := sanitizedFilenameRe.ReplaceAllString(name, "_")
	// Trim leading/trailing whitespace and dots (Windows hates trailing
	// dots, and leading dots make files hidden on Unix).
	clean = strings.Trim(clean, ". ")
	if clean == "" {
		return ""
	}
	// Cap length defensively. NTFS/ext4 both allow 255-byte filenames;
	// 200 leaves room for OS suffixes.
	if len(clean) > 200 {
		clean = clean[:200]
	}
	return clean
}

// handlePreprocess is the dual-method endpoint for preprocessor info
// and invocation.
//
//	GET  -> { available, interpreter, scriptPath }
//	POST -> validate config, enqueue a job, return { jobId }
//
// When the runner is nil (no PowerShell available on this host),
// GET still works and returns { available: false, ... }; POST returns
// 503 with the same message. This shape lets the UI decide whether
// to even show the wizard entry points.
func (s *Server) handlePreprocess(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		resp := map[string]any{"available": s.preprocess != nil}
		if s.preprocess != nil {
			resp["interpreter"] = s.preprocess.PSPath()
			resp["scriptPath"] = s.preprocess.ScriptPath()
		}
		writeJSON(w, http.StatusOK, resp)
		return

	case http.MethodPost:
		if s.preprocess == nil {
			writeErr(w, http.StatusServiceUnavailable,
				"preprocessor not available: no PowerShell interpreter found")
			return
		}
		// Cap body size -- the config is small JSON, anything bigger
		// is malformed or hostile.
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		var cfg preprocess.Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		// Validate before enqueuing so the UI sees errors synchronously.
		// The Run() method will also validate, but failing early gives
		// a much better user experience than a queued job that
		// immediately fails.
		if err := cfg.Validate(); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}

		// Enqueue the work. The job's progress field carries the
		// streamed PowerShell output; the front-end polls /api/jobs/{id}
		// to display it. We cap the displayed progress at the last
		// ~32 KB so the polling response stays small -- the full log
		// would be hundreds of KB for a real preprocessor run.
		hostName := cfg.HostName
		if hostName == "" {
			hostName = "(inferred from image)"
		}
		var logMu sync.Mutex
		var logBuf strings.Builder
		// The PS1 emits "DOUGLAS_RESULT_CASE_DIR=<path>" near the end
		// on success. We capture it from the line stream so we know
		// the actual case dir to open (which is OutputRoot/<CaseId>,
		// not OutputRoot itself -- the PS1 picks CaseId at runtime).
		// Read+written under logMu; the streaming goroutine writes
		// during the callback, the work goroutine reads it after
		// Run returns.
		var resolvedCaseDir string
		work := func(ctx context.Context, j *jobs.Job) (string, error) {
			// Create the OutputRoot directory tree before the PS1 runs.
			// Doing this here (not in the validator) means a cancelled
			// or abandoned wizard form never leaves stray dirs behind --
			// the mkdir only happens once the analyst has committed to
			// the run. PS1 also uses New-Item -Force internally, so
			// this is belt-and-braces; the explicit MkdirAll surfaces
			// permission/FS errors as a clean Go error rather than a
			// PowerShell stack trace.
			if err := os.MkdirAll(cfg.OutputRoot, 0o755); err != nil {
				return "", fmt.Errorf("create output root: %w", err)
			}
			s.jobs.SetProgress(j.ID, "starting preprocessor")
			exitCode, runErr := s.preprocess.Run(ctx, cfg, func(line string) {
				// Check for the result marker FIRST -- if matched, we
				// capture the path but DON'T add the line to the log
				// buffer. The marker is internal contract output; the
				// analyst doesn't need to see it in the streaming log
				// panel (the path is surfaced via the "Open case"
				// button on success).
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "DOUGLAS_RESULT_CASE_DIR=") {
					logMu.Lock()
					resolvedCaseDir = strings.TrimPrefix(trimmed, "DOUGLAS_RESULT_CASE_DIR=")
					logMu.Unlock()
					return
				}
				logMu.Lock()
				logBuf.WriteString(line)
				logBuf.WriteByte('\n')
				// Cap the log for the progress field. Keep the tail
				// (most recent) since that's what an analyst watching
				// progress wants to see.
				if logBuf.Len() > 32*1024 {
					full := logBuf.String()
					logBuf.Reset()
					logBuf.WriteString("... (output truncated) ...\n")
					logBuf.WriteString(full[len(full)-30*1024:])
				}
				snapshot := logBuf.String()
				logMu.Unlock()
				s.jobs.SetProgress(j.ID, snapshot)
			})
			if runErr != nil {
				return "", runErr
			}
			if exitCode != 0 {
				return "", fmt.Errorf("preprocessor exited with code %d", exitCode)
			}
			// Pick the path to open: the marker if the PS1 emitted it,
			// otherwise fall back to OutputRoot. The fallback covers
			// the edge case where an older PS1 version is somehow
			// running (shouldn't happen since the script is embedded,
			// but defensive). Falling back to OutputRoot was the
			// previous behavior and at worst makes the case appear
			// "empty" -- known UX, no crash.
			logMu.Lock()
			caseToOpen := resolvedCaseDir
			logMu.Unlock()
			if caseToOpen == "" {
				caseToOpen = cfg.OutputRoot
			}
			if err := s.cases.Open(caseToOpen); err != nil {
				return "", fmt.Errorf("preprocessor finished but open failed: %w", err)
			}
			// Return the resolved case dir as the result ID. The wizard
			// uses this for the "Open case" button so the client-side
			// bootstrap() picks up the right directory (matching the
			// server's view).
			return caseToOpen, nil
		}

		j := s.jobs.Enqueue(jobs.KindPreprocess, "", hostName,
			"Run-ZimmermanTools.ps1", work)
		writeJSON(w, http.StatusAccepted, map[string]any{
			"jobId":  j.ID,
			"status": j.Status,
		})
		return

	default:
		writeErr(w, http.StatusMethodNotAllowed, "GET or POST required")
	}
}

// handlePreprocessTools returns the canonical list of -ToolFilter
// values for the UI's checkbox list. Static; computed once.
func (s *Server) handlePreprocessTools(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tools": preprocess.ToolFilter,
	})
}

// staticHandler serves the embedded UI. Falls through to index.html for any
// path that doesn't match a file — the front-end is a single-page app.
func (s *Server) staticHandler() http.Handler {
	fileServer := http.FileServer(http.FS(s.assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reject directory listings / probe straight to index.html for the root.
		clean := strings.TrimPrefix(r.URL.Path, "/")
		if clean == "" {
			clean = "index.html"
		}
		_, err := fs.Stat(s.assets, clean)
		if errors.Is(err, fs.ErrNotExist) {
			// SPA fallback.
			r.URL.Path = "/index.html"
		}
		fileServer.ServeHTTP(w, r)
	})
}
