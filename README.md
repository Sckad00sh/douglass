# Artifact Review

A host-centric DFIR review tool for Zimmerman / EZ Tools and Hayabusa CSV output.
Single Go binary, embedded UI, no runtime dependencies.

## What it does

Where Timeline Explorer is file-centric ("open one CSV, look at it"),
Artifact Review is host-centric:

- Point it at a case folder
- It discovers each host's artifact CSVs by filename pattern
- Review all artifacts for a host in one place
- Flag suspicious rows with a 🚩 and an analyst note
- Per-host **Timeline** and **Global Timeline** views aggregate every flag

Supports MFT, Amcache, Shimcache, Prefetch, EvtxECmd, Hayabusa, SRUM,
RECmd, LECmd, JLECmd output.

## Building

Requires Go 1.21+. No other dependencies.

```bash
# current platform
make

# all three platforms (amd64 + arm64)
make all
```

Output goes to `./dist/`.

If you don't have `make`:

```bash
go build -o artifact-review ./cmd/artifact-review

# cross-compile
GOOS=linux   GOARCH=amd64 go build -o artifact-review-linux-amd64    ./cmd/artifact-review
GOOS=darwin  GOARCH=arm64 go build -o artifact-review-darwin-arm64   ./cmd/artifact-review
GOOS=windows GOARCH=amd64 go build -o artifact-review-windows-amd64.exe ./cmd/artifact-review
```

## Running

```bash
./artifact-review --case /path/to/case
```

The binary serves the UI on a random local port and opens your default
browser. Add `--no-open` if you'd rather paste the URL yourself, or
`--addr 127.0.0.1:8080` to pin the port.

Flags:

| Flag        | Default        | Meaning                                  |
|-------------|----------------|------------------------------------------|
| `--case`    | (none)         | Path to a case directory to open         |
| `--addr`    | `127.0.0.1:0`  | Bind address (port `0` = random)         |
| `--no-open` | `false`        | Don't auto-open the browser              |

## Case folder layout

```
<case>/
  case.json                 # optional, { id, name, createdAt, analyst }
  marks.json                # written by the app
  hosts/                    # or omit and place hosts directly under <case>
    WS-FIN-014/
      host.json             # optional { id, name, fqdn, os, ip, role, tag, triageStart }
      artifacts/            # or omit and place CSVs directly under the host
        $MFT_Output.csv
        Amcache_UnassociatedFileEntries.csv
        SYSTEM_AppCompatCache.csv
        PECmd_Output.csv
        EvtxECmd_Output.csv
        hayabusa_timeline.csv
        SrumECmd_NetworkUsage.csv
        RECmd_Batch.csv
        LECmd_Output.csv
        JLECmd_Output.csv
    SRV-DC01/
      ...
```

`case.json` and `host.json` are optional — defaults are derived from the
directory names if missing. `hosts/` and `artifacts/` subdirectories are
also optional; the loader will look for host folders directly under
`<case>/` and CSVs directly under each host folder.

### Artifact recognition

Filenames are matched (case-insensitive) against these patterns:

| Tool                  | Pattern                            | UI name              |
|-----------------------|------------------------------------|----------------------|
| MFTECmd               | `*MFT*Output*.csv`                 | MFT                  |
| AmcacheParser         | `Amcache*FileEntries*.csv`         | Amcache              |
| AppCompatCacheParser  | `*AppCompatCache*.csv`             | Shimcache            |
| PECmd                 | `PECmd_Output*.csv`                | Prefetch             |
| EvtxECmd              | `EvtxECmd_Output*.csv`             | Event Logs           |
| Hayabusa              | `hayabusa*timeline*.csv`           | Hayabusa Detections  |
| SrumECmd              | `SrumECmd*Network*.csv`            | SRUM Network         |
| RECmd                 | `RECmd*Batch*.csv`                 | Registry (RECmd)     |
| LECmd                 | `LECmd_Output*.csv`                | LNK Files            |
| JLECmd                | `JLECmd_Output*.csv`               | Jump Lists           |

Files that don't match any pattern are ignored.

## Marks

Click 🚩 on any row to mark it; the row gets an accent-colored border and
joins the per-host Timeline and the Global Timeline. Open the detail
drawer to add an analyst note. Marks are persisted to
`<case>/marks.json`, written debounced ~500ms after each edit.

## Themes

Six built-in themes: Yaru Dark (default), Yaru Light, Velociraptor,
Dracula, Nord, Solarized Dark. Pick one from the 🎨 button in the
sidebar footer; selection persists across sessions in `localStorage`.

## Project layout

```
.
├── cmd/artifact-review/
│   ├── main.go            # entry, --case flag, browser launch
│   └── static/            # embedded UI
│       ├── index.html
│       ├── app.css        # ported from design handoff
│       ├── themes.css     # ported from design handoff
│       ├── extras.css     # small additions on top
│       └── app.js         # vanilla JS app
├── internal/
│   ├── model/             # core types (Host, Artifact, Mark, ...)
│   ├── ingest/            # artifact-type registry + CSV parsing
│   ├── marks/             # marks store with debounced persistence
│   └── server/            # HTTP routes (JSON API + static)
├── go.mod
├── Makefile
└── README.md
```

No third-party Go modules; everything's in the standard library.

## Limits

- Tables are not yet virtualized. Real MFTs (millions of rows) will
  cause the browser to struggle. Use pre-filtered CSVs for now; row
  virtualization is the next milestone.
- The mark "row key" is a hash of a handful of high-signal columns and
  will be stable across re-parses of the same CSV. If you mark a row in
  a sparse CSV with no distinguishing columns, you may see drift.
- Cross-artifact correlation (pivot + time-window) loads any uncached
  artifacts for the host on first use, with a short loading toast.
  Subsequent correlations are instant. There's no server-side index;
  matching is in-browser, which is fine up to a few hundred thousand
  rows but may feel sluggish on very large MFTs.

## Security model

The tool is intentionally localhost-only:

- Default bind is `127.0.0.1:0` (loopback, random port). Override with
  `--addr` only if you understand what you're doing. **Do not expose
  this on a network.** It's a single-user analyst tool, not a service.
- The HTTP server enforces a Host header allowlist (`127.0.0.1`,
  `localhost`, `::1`). This blocks DNS rebinding attacks from a remote
  webpage tricking your browser into talking to the local API.
- API endpoints (except `/api/health`) require an `X-Requested-By:
  douglas` header. Browsers won't send custom headers cross-origin
  without a CORS preflight, and the server returns no CORS allow
  headers, so cross-origin requests fail before reaching the handlers.
- A strict Content-Security-Policy header (`default-src 'self'`) is set
  on every response. All UI assets are same-origin and embedded in the
  binary; the policy denies inline scripts, third-party origins, and
  framing.
- Request bodies are size-capped to prevent memory exhaustion
  (`/api/open` 64 KB, `/api/marks` POST 256 KB). Metadata file reads
  (`case.json`, `host.json`, `marks.json`) are also capped.

If you ever need to expose the UI on a network for legitimate reasons
(e.g. running on a dedicated review jumpbox), put it behind a reverse
proxy that handles auth and TLS. Don't loosen the Host check.
