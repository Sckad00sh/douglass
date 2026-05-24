package server

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/example/artifact-review/internal/ingest"
	"github.com/example/artifact-review/internal/marks"
	"github.com/example/artifact-review/internal/model"
)

// Server wires together the ingest store, mark store, and static assets.
type Server struct {
	cases  *ingest.Store
	marks  *marks.Store
	assets fs.FS
}

// New constructs a server around the given dependencies. assets must be a
// filesystem rooted at the directory containing index.html.
func New(cases *ingest.Store, marks *marks.Store, assets fs.FS) *Server {
	return &Server{cases: cases, marks: marks, assets: assets}
}

// Routes returns an http.Handler with all API + static routes wired up.
//
//	GET  /api/case               full case description (hosts + summaries)
//	POST /api/open               { dir } - open a case from a path
//	GET  /api/browse?dir=        directory listing (dirs only) for UI browser
//	GET  /api/artifact-types     registry of known artifact types
//	GET  /api/artifact?h&a       full artifact rows for a host
//	GET  /api/marks?host=        list marks (optionally scoped to a host)
//	POST /api/marks              upsert a mark (body: full Mark JSON)
//	DEL  /api/marks/{id}         delete a mark
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
	mux.HandleFunc("/api/marks", s.handleMarks)
	mux.HandleFunc("/api/marks/", s.handleMarkByID)
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
