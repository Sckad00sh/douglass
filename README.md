# Artifact Review

A host-centric DFIR review tool for Zimmerman / EZ Tools and Hayabusa CSV output.
Single Go binary, embedded UI, no runtime dependencies.

**[Project site & interactive demo →](https://yourname.github.io/douglas/)**

## What it does

Where Timeline Explorer is file-centric ("open one CSV, look at it"),
Artifact Review is host-centric:

- Point it at a case folder
- It discovers each host's artifact CSVs by filename pattern
- Review all artifacts for a host in one place
- Flag suspicious rows with a 🚩 and an analyst note
- Per-host **Timeline** and **Global Timeline** views aggregate every flag

Supports MFT, Amcache, Shimcache, Prefetch, EvtxECmd, Hayabusa, SRUM,
RECmd, LECmd, JLECmd (Auto + Custom), Shellbags (SBECmd), BITS jobs,
and Microsoft Defender MPLog.

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

| Flag                | Default        | Meaning                                  |
|---------------------|----------------|------------------------------------------|
| `--case`            | (none)         | Path to a case directory to open         |
| `--addr`            | `127.0.0.1:0`  | Bind address (port `0` = random)         |
| `--no-open`         | `false`        | Don't auto-open the browser              |
| `--upload-workers`  | `2`            | Parallel upload/preprocess jobs          |

## Preprocessing images (the wizard)

On Windows, Douglas can run `Run-ZimmermanTools.ps1` against a mounted
image directly from the UI. Click the gear icon in the top-right and
choose "Preprocess new image" (or "Re-run preprocessor for a host"
when a case is open).

The wizard collects:

- **Image path** — mounted image root (e.g. `E:\`)
- **Output root** — case directory to create or update
- **Host name** — optional; inferred from the SYSTEM hive if blank
- **Operator** — analyst handle stored in `host.json`'s triage block
- **Collection method** — defaults to `KAPE -> EZ Tools`
- **Tools** — checkbox grid; "Run all tools (default)" is on by default
- **Hayabusa / BitsParser** — addon toggles

PowerShell output streams live into the modal's log panel. On success
the wizard offers "Open case" which loads the result into Douglas.

If no PowerShell interpreter is found at startup (e.g. on Linux or
macOS where the script wouldn't work anyway) the wizard entry points
are hidden. You can still run the script standalone from any Windows
machine via the root-level `Run-ZimmermanTools.ps1` and import the
output the regular way.

## Case folder layout

```
<case>/
  case.json                 # optional, { id, name, createdAt, analyst }
  marks.json                # written by the app
  hosts/                    # or omit and place hosts directly under <case>
    WS-FIN-014/
      host.json             # optional, see "Host metadata" below
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
        JLECmd_AutomaticDestinations.csv
        JLECmd_CustomDestinations.csv
    SRV-DC01/
      ...
```

`case.json` and `host.json` are optional — defaults are derived from the
directory names if missing. `hosts/` and `artifacts/` subdirectories are
also optional; the loader will look for host folders directly under
`<case>/` and CSVs directly under each host folder.

### Host metadata

`host.json` describes one investigated machine and feeds the host
overview page. Minimal shape (legacy, still supported):

```json
{
  "id": "WS-FIN-014",
  "name": "WS-FIN-014",
  "os": "Windows 11 Pro",
  "role": "Workstation",
  "tag": "WS"
}
```

Extended shape produced by `Run-ZimmermanTools.ps1` includes nested
blocks for the host overview cards. Each nested block is optional —
the UI shows "Not collected" placeholders for missing blocks rather
than crashing.

```json
{
  "id": "WS-FIN-014",
  "name": "WS-FIN-014",
  "os": "Windows 11 Pro",
  "role": "Workstation",
  "tag": "WS",

  "identity": {
    "hostname": "WS-FIN-014",
    "fqdn": "ws-fin-014.corp.local",
    "domain": "CORP",
    "os": "Windows 11 Pro",
    "osVersion": "22H2",
    "build": "10.0.22621.4317",
    "arch": "x64",
    "timeZone": "UTC-05:00 (EST)"
  },
  "hardware": {
    "cpuModel": "Intel Core i7-12700 @ 2.10GHz",
    "cpuCores": 12,
    "cpuThreads": 20,
    "ramBytes": 34359738368,
    "diskKind": "NVMe",
    "diskBytes": 549755813888,
    "diskUsedPercent": 71,
    "lastBoot": "2025-11-07T08:42:00Z"
  },
  "network": {
    "ipv4": ["10.40.2.18"],
    "mac": ["00:1A:2B:5C:7E:9F"],
    "gateway": "10.40.2.1",
    "dns": ["10.40.0.10", "10.40.0.11"]
  },
  "triage": {
    "method": "KAPE -> EZ Tools",
    "operator": "j.kowalski@corp",
    "targets": ["!SANS_Triage", "EventLogs", "RegistryHives"],
    "startedAt": "2025-11-08T06:00:00Z",
    "completedAt": "2025-11-08T06:11:00Z",
    "sizeBytes": 4080218931
  }
}
```

A few schema rules:

- **Sizes in bytes**, not pretty strings (`32 GB` is lossy when summed
  across hosts; the UI formats for display).
- **Timestamps as ISO 8601 UTC**. Time zone display lives separately
  in `identity.timeZone`.
- **IPv4 and MAC as arrays**, since multi-NIC servers and VMs are
  common. Single-NIC hosts just have one entry.
- **Disk used as a percent, not free space** — matches the way
  analysts read disk pressure.

When running `Run-ZimmermanTools.ps1`, populate analyst-supplied
fields via `-Operator <email>` and `-CollectionMethod <text>`. Most
other fields come from offline registry probes against the image
(hostname, FQDN, domain, OS, arch, time zone, network interfaces);
hardware specs need a live-machine probe (the HARDWARE hive isn't
reliably captured in KAPE triage).

### Artifact recognition

Filenames are matched (case-insensitive) against these patterns:

| Tool                  | Pattern                                | UI name                |
|-----------------------|----------------------------------------|------------------------|
| MFTECmd               | `*MFT*Output*.csv`                     | MFT                    |
| AmcacheParser         | `Amcache*FileEntries*.csv`             | Amcache                |
| AppCompatCacheParser  | `*AppCompatCache*.csv`                 | Shimcache              |
| PECmd                 | `PECmd_Output*.csv`                    | Prefetch               |
| EvtxECmd              | `EvtxECmd_Output*.csv`                 | Event Logs             |
| Hayabusa              | `hayabusa*timeline*.csv`               | Hayabusa Detections    |
| SrumECmd              | `SrumECmd*Network*.csv`                | SRUM Network           |
| RECmd                 | `RECmd*Batch*.csv`                     | Registry (RECmd)       |
| LECmd                 | `LECmd_Output*.csv`                    | LNK Files              |
| JLECmd                | `JLECmd_AutomaticDestinations*.csv`    | Jump Lists (Auto)      |
| JLECmd                | `JLECmd_CustomDestinations*.csv`       | Jump Lists (Custom)    |
| SBECmd                | `*SBECmd*Output*.csv`                  | Shellbags              |
| BitsParser            | `*BitsParser*.csv`                     | BITS Jobs              |
| (Windows Defender)    | `MPLog*.log`                           | Defender MPLog         |

Files that don't match any pattern are ignored.

### Note on third-party tools

Most of the artifact parsers come from Eric Zimmerman's EZ Tools suite
(MFTECmd, AmcacheParser, AppCompatCacheParser, PECmd, EvtxECmd, SrumECmd,
RECmd, LECmd, JLECmd, SBECmd). Two artifacts are not part of EZ Tools:

- **Hayabusa**: Yamato Security's EVTX-based detection rule engine.
- **BitsParser**: Community tool for parsing BITS queue manager databases.
  Several variants exist; Douglas matches any CSV output containing
  "BitsParser" in the filename and surfaces the most common column set
  (URL, LocalFile, Owner, State, timestamps).

Both produce CSV output and are bundled separately from EZ Tools.

### Shellbags

SBECmd splits output by source hive: NTUSER.DAT (Explorer-accessed
folders) and UsrClass.dat (mounted/virtual folders). Douglas merges
both into one logical artifact view and derives a `Source` column
(`NTUSER`, `UsrClass`, or `Unknown`) so analysts can filter by hive
without flipping between tabs.

### Jump Lists pattern change

Older versions of this tool matched `JLECmd_Output.csv` -- a filename
JLECmd doesn't actually produce. The current registry expects the
native JLECmd output names (`JLECmd_AutomaticDestinations.csv` and
`JLECmd_CustomDestinations.csv`). If you have old case folders with
manually-renamed `JLECmd_Output.csv` files, rerun the preprocessor or
rename them to the native pattern.

### Defender MPLog

Unlike the EZ Tools artifacts above, MPLog files are read directly --
no preprocessor needed. Drop `MPLog-YYYYMMDD-HHMMSS.log` from
`C:\ProgramData\Microsoft\Windows Defender\Support\` into the host's
`artifacts/` folder and it parses on first open. Files are UTF-16 LE
with BOM; we decode at load time.

The parser drops `EstimatedImpact` lines (10k+ rows of pure
process-scan noise per file) at parse time and classifies the rest into
event types: `BMTelemetry`, `MiniFilterScan`, `EMSScan`, `ASRRule`,
`AMSI`, `EngineEvent`, `Detection`, `Other`. The MPLog tab opens with
a "Relevant only" toggle on by default -- shows only BMTelemetry,
Detection, and warn-or-higher severity rows (typically a few hundred
events from a 50k-line file). Click the chip to see everything.

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
