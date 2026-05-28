# TODO

Things to tackle next, roughly ordered by impact.

## Performance

- [ ] **Increase artifact load speed**. MFT and other large artifacts
  (100k+ rows) take noticeable time on first load — symptoms most
  visible when correlation triggers `ensureAllArtifactsLoaded` and
  pulls every artifact for a host. Once loaded, navigation and
  correlation are snappy.

  Likely angles to investigate:
  - **Server-side**: `parseCSV` reads the file synchronously and
    constructs `model.Row` (a `map[string]string`) per row. For
    100k+ rows the per-row allocation cost is significant. Could
    switch to a column-oriented representation, parallelise the
    CSV scan, or pre-cache parsed artifacts to a binary format
    on the case folder for warm restarts.
  - **Wire format**: `/api/artifact` returns the full row set as
    JSON. A 100k-row MFT can be tens of megabytes of JSON over
    loopback. Streaming + chunked client parsing, or a more
    compact format (NDJSON, msgpack) would help.
  - **Client-side**: 100k rows go straight into `state.artifactCache`
    as JS objects. The first render is virtualized so display is
    fine, but the parse-into-JS step blocks the main thread.
    Could move parsing into a Worker.

  Worth measuring before optimizing -- profile a real MFT load
  end-to-end to find the actual bottleneck (server parse? JSON
  encode? network? client parse? first render?) before picking
  an angle.

## Deferred features

- [ ] **Analyst profiles** (tabled). Saved-searches + analyst-stamped
  marks, stored in `%APPDATA%\Douglas\profile.json`
  (`~/.config/douglas/profile.json` elsewhere). Flat list, no
  bundles. Picked up when there's real workflow demand.

## MPLog follow-ups

The MPLog parser ships in v0.10.5 covering the patterns we saw in a real
51k-line sample. A few things to revisit when we get more samples:

- [ ] **Real Defender detection lines**. The current parser has a
  `Detection` EventType wired but never ground-truthed against a real
  `THREAT:` block. Need a sample MPLog from a machine that actually
  caught malware to pin the detection-line regex + severity (probably
  `high`/`crit`).
- [ ] **Quarantine block parsing**. We see 376 `Quarantine ID:` lines
  in the sample but they're continuation-style (preceded by a
  `Threat Name:` line we don't currently parse). Treat them as their
  own block type when we have a sample with non-zero-GUID quarantine
  IDs to ground-truth against.
- [ ] **Multi-file MPLog**. Defender rotates these. Currently each
  `.log` file becomes its own artifact tab. Worth considering a
  combined view that merges adjacent rotation files into one
  chronological set.

## Cross-platform artifact support

Douglas today is Windows-only at the artifact layer. The Go binary runs
on Linux/macOS fine, and the UI is platform-agnostic, but every artifact
type in the registry is Windows-flavored (MFT, Amcache, Shimcache,
Prefetch, EvtxECmd, MPLog, etc). Adding Linux and macOS would meaningfully
broaden the tool -- many IR engagements touch *nix systems too.

### Linux (higher priority)

Likely starting set, roughly in order of analyst value:

- [ ] **syslog / auth.log / secure**. `/var/log/syslog`, `/var/log/auth.log`,
  `/var/log/secure`. Plain text, timestamped, well-understood format.
  Parse to columns: timestamp, host, process, pid, message. Severity
  bumps for sudo failures, accepted/failed logins, su events. Probably
  the most-bang-for-buck artifact -- maps cleanly onto the EvtxECmd
  mental model.
- [ ] **systemd-journal**. The modern equivalent. Native format is
  binary; analysts typically export with `journalctl --output=json`
  before collection. We'd parse the JSON, same column shape as syslog
  plus the systemd-specific `_SYSTEMD_UNIT` and friends.
- [ ] **bash_history / zsh_history** per user. No native timestamps
  (unless `HISTTIMEFORMAT` is set, which it usually isn't). Surface
  what we can: command, user, source file. Useful for "what did the
  attacker type" analysis even without timestamps.
- [ ] **auditd logs**. `/var/log/audit/audit.log`. Highly structured
  but the format is rough (one event spans multiple lines joined by
  the same msg= ID). Plaso parses these well -- might be a good case
  for the "preprocessor produces CSV" pattern instead of native Go.
- [ ] **cron + systemd unit files**. Persistence-focused. Not really
  time-series; more of a "what's configured" inventory view. May not
  fit Douglas's row-oriented model cleanly -- worth a UX think.
- [ ] **ext4 filesystem timeline**. Sleuth Kit's `fls` + `mactime`
  produces a body file then a timeline CSV. Closest analogue to MFT.
  Already CSV; just needs a registry entry + schema.

**Design choice to make first**: do we follow the EZ Tools pattern
(write a Linux preprocessor that outputs CSVs Douglas already knows
how to read), or go native-Go like we did for MPLog? Arguments either
way:

- *Preprocessor pattern* (CSV): keeps Douglas's Go code small,
  leverages existing parsers (plaso, sleuth kit). Cost: another tool
  to ship/document, and analysts on Linux investigation hosts need to
  install plaso etc.
- *Native parser* (like mplog.go): self-contained binary, analyst
  drops raw `auth.log` and it Just Works. Cost: more Go code to
  maintain per artifact type.

My current lean is **native for plain-text logs** (syslog/auth.log/
bash_history are easy to parse) and **CSV-preprocessor for the
hard ones** (auditd, ext4 timeline -- both benefit from mature
existing tools).

### macOS (lower priority)

Most DFIR work on macOS goes through specialized commercial tools or
plaso. Likely set, when we get there:

- [ ] **Unified logs** (`log show --predicate '...' --style json`).
  Binary log format, but `log show` produces structured output. Map
  to columns like the Linux journal: timestamp, process, subsystem,
  category, message, sender. The challenge is volume -- unified
  logs can be huge.
- [ ] **FSEvents**. Filesystem activity stream. Requires reading
  `.fseventsd/` from the disk image; not something an analyst pulls
  live. Existing parsers (FSEventsParser by David Cowen) produce
  CSV.
- [ ] **Quarantine DB**. `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`
  -- SQLite. Lists downloads with source URL + timestamp. Small,
  high-signal.
- [ ] **plist inventory**. LaunchAgents, LaunchDaemons, login items,
  Spotlight metadata. Persistence-focused -- same UX consideration
  as Linux's cron/systemd inventory.
- [ ] **Spotlight metadata**. `.Spotlight-V100` index. Sometimes
  preserves filesystem history past file deletion. Requires a Mac
  to extract usefully.

macOS support is more speculative -- I haven't seen the same volume
of analyst demand for it that the Linux side has. Park it until
either (a) we hit a real engagement that needs it, or (b) Linux is
solid enough that we're looking for the next direction.

### Strategic note

Adding cross-platform support is the kind of change that affects the
tool's identity -- Douglas stops being "Windows DFIR review" and
becomes "host DFIR review across platforms." Worth thinking about
the UI implications too: a host's "Operating System" field already
exists in `host.json`; the sidebar could group hosts by OS, or
filter artifact tabs to OS-relevant types. Currently every host
shows every artifact type icon even when most don't apply.

## v0.11.0 — Drag-and-drop upload (SHIPPED)

Both server-side and front-end shipped. CSV passthrough only; raw
artifacts get a clear "needs preprocessing" error pointing at the
wizard.

## v0.12.0 — Phase-1 host overview (SHIPPED)

`host.json` extended with optional `identity` / `hardware` / `network` /
`triage` nested blocks. Preprocessor populates the offline-derivable
fields; UI shows "Not collected" placeholders for missing blocks.

## v0.13.0 — Preprocess wizard (SHIPPED)

In-app subprocess execution of `Run-ZimmermanTools.ps1`.

**Done:**
- [x] Embedded PS1 via `//go:embed`, extracted to temp file at startup
- [x] `internal/preprocess.Runner` with typed `Config`, strict
  `Validate()`, safe argv construction (never from concatenated
  strings), PowerShell discovery (pwsh preferred, falls back to
  Windows PowerShell)
- [x] `POST /api/preprocess` endpoint that validates + enqueues into
  the job system, streams output to the job's progress field
- [x] `GET /api/preprocess/tools` returns the canonical -ToolFilter
  list for the UI checkbox grid
- [x] Wizard modal with form fields, tool checkboxes, addon toggles
  (Hayabusa / BitsParser), browse buttons, live log streaming via
  1Hz polling, cancel support, "Open case" on success
- [x] Settings dropdown (gear icon, top-right) with entry points
  scoped to whether a case is open
- [x] Makefile `check-ps1` target that fails the build if root copy
  and embedded copy diverge

**Security invariants:**
- All subprocess args constructed from typed fields, validated
  before invocation. Free-form fields (operator, collectionMethod)
  pass through `os/exec`'s argv array — no shell interpretation.
- HostName and CaseID restricted to `[A-Za-z0-9._-]+` regex.
- ToolFilter entries validated against the canonical list before
  any flag is built.
- ImagePath and OutputRoot parent must be existing directories
  before the subprocess is allowed to start.
- Runner returns nil if no PowerShell interpreter is found, in
  which case the endpoint returns 503 and the UI hides the wizard
  entry points (no "feature broken" surprise).

## v0.14.0 — Phase-2 host overview Detections histogram (SHIPPED)

Severity-bucketed bar chart on the host overview card row. Reads
SeverityCounts from each ArtifactSummary (populated at host-discovery
time by quickStat) and sums them across artifacts.

**Done:**
- [x] `model.ArtifactSummary.SeverityCounts map[string]int` with
  `omitempty` JSON tag — absent on artifacts without severity columns
- [x] `quickStat` recognises both "Level" (Hayabusa) and "Severity"
  (MPLog) columns; values normalised via `classifySeverity` to one
  of `critical`/`high`/`medium`/`low`/`info`
- [x] `internal/ingest/severity_test.go` pins the classifier mapping
  and integration-tests quickStat against synthetic CSVs
- [x] `renderHostDetectionsCard` renders the 5-row histogram with
  bar widths scaled relative to the largest bucket on the host
- [x] Triage card now sits side-by-side with Detections in a 2-col
  grid (was full-width in phase 1)
- [x] Empty state when no severity-tagged artifacts loaded
- [x] "Open timeline →" link in the card head; opens the host
  timeline (no severity pre-filter for now)

**Known limitations:**
- Non-CSV artifacts (MPLog) don't contribute to the histogram at
  first paint; severity counting happens at quickStat which only
  runs on CSVs. Hayabusa is the main detection source so this is
  acceptable for phase 2.

## v0.15.0 — Host overview redesign (SHIPPED)

Visual rewrite of the host landing page to match the static handoff
at /handoff-overview/. Same cards, new structure and styling.

**Done:**
- [x] Removed phase-1 + phase-2 overview CSS from extras.css (~270
  lines deleted), replaced with the handoff's `.host-ov-*` /
  `.ho-*` class names verbatim
- [x] New `renderHostOverview` produces the briefing layout: header
  with avatar + name + tag pill + role + FQDN strip + Triaged
  status pill, then a 3-col responsive grid of Identity / Hardware /
  Network / Triage collection / Detections cards, then the
  artifacts grid as horizontal cards
- [x] New helpers: `hoSection`, `kvRow`, `hostStatusPill`, `sevBar`
  mirror the handoff's React components (`<Section>`, `<Kv>`,
  `<StatusPill>`, `<SevBar>`)
- [x] Detections histogram reuses v0.14.0's `severityCounts` on each
  `ArtifactSummary` — same data, no re-scan of Hayabusa rows
- [x] Artifact tiles use the handoff's `.ho-art-card` style (icon
  square + name/tool/file + count + alerts)
- [x] Responsive: 3-col >=1280px, 2-col 820-1280px, 1-col <820px;
  status pill stacks below header on narrow viewports

**Skipped intentionally:**
- EDR/AV status pills (no live-machine probe; you said skip earlier)
- Local Users table (no source data yet; the .wide Section pattern
  is in place for when users data lands)

## v0.15.1 — GitHub Pages site (SHIPPED)

Public-facing landing page + interactive demo, served from `/docs`
on the default branch.

**Done:**
- [x] `docs/index.html` — landing page (hero + features grid +
  artifact list grouped by category + install/run snippets).
  Velociraptor cyan theme.
- [x] `docs/demo.html` — self-contained interactive UI walkthrough
  with full app chrome (brand bar, sidebar, top tab strip, status
  bar) in Yaru Dark. Four primary tabs (Overview / Timeline /
  Event Logs / Hayabusa) + a 5th Pivot tab opening dynamically
  when a Row Detail time-window button is clicked.
- [x] `docs/.nojekyll` so Pages serves the HTML as-is.
- [x] `docs/README.md` notes for maintainers (keep CSS variables
  in sync with the real app's themes.css / extras.css).

## v0.16.0 — Triage panel + deep-link fix (SHIPPED)

Two pieces that landed together: a "Quick Hits" triage sweep on
the Host Overview that surfaces low-hanging-fruit findings from
already-parsed artifacts, and a general fix for the app-wide bug
where "open in <artifact>" links navigated to the right artifact
but failed to target the specific row.

**Quick Hits triage panel (server-side):**
- [x] New `internal/triage` package with pure-function filters over
  `[]model.Row` — testable in isolation, no I/O. Categories
  shipped: Run / RunOnce keys, Winlogon autostart, suspicious
  services (filtered to suspicious-path / launcher heuristic),
  scheduled tasks, suspicious-path Amcache entries, suspicious-
  path Prefetch entries.
- [x] Filter on deterministic `KeyPath` substrings, not RECmd's
  `Category` column (which varies by batch file). Robust against
  Kroll_Batch.reb vs other batches.
- [x] Services group is opinionated (signal > completeness): only
  services whose ImagePath/ValueData lives in `\Temp\`, `\Users\`,
  `\ProgramData\` etc., OR references `cmd.exe` / `powershell` /
  `rundll32` / `.bat` / `.ps1` / `-enc` and similar launchers.
  Documented blind spot: a malicious service in System32 with a
  normal-looking path won't flag here — pinned in
  `TestServices_KnownFalseNegative`.
- [x] `GET /api/triage?host=<id>` handler; loads registry/amcache/
  prefetch best-effort (nil-tolerant) and returns grouped findings.
- [x] Each finding carries the source row's `__row` index so the UI
  can deep-link back to the exact row.

**Quick Hits triage panel (frontend):**
- [x] `renderTriagePanel` on the host overview, between the briefing
  cards and the artifact tiles. Collapsible groups; expanded by
  default when there are findings, collapsed when "none found".
  The analyst's manual toggle overrides the default and persists
  for the session.
- [x] Empty groups render a per-category "none found" message
  (e.g. "Shell / Userinit / Notify all default") so "checked,
  clean" is visually distinct from "didn't check".
- [x] Triage result cached per host in `state.triageCache` so
  re-renders don't refetch.
- [x] Every finding has an "open in <Artifact> →" link that
  navigates to the source artifact AND scrolls the exact row
  into view (see deep-link fix below).

**App-wide deep-link fix:**
- [x] Tab objects now carry `targetRowKey`. The artifact view's
  row-resolution step matches first on `rowKeyOf(r)` (the content
  hash used by marks / pivots / timeline) and falls back to
  matching `r.__row` directly (used by triage, which has the raw
  index on hand and shouldn't have to duplicate the JS hashing in
  Go).
- [x] One-shot `_forceReveal` flag on `ui` forces
  `mountVirtualTable` to scroll the selected row into view even
  when the tab was already open — fixes the case where clicking
  "open in" with the artifact tab already open used to be a
  silent no-op.
- [x] `openTab` dedup branch carries the deep-link target onto an
  already-open tab so re-targeting works.
- [x] If the target row exists in the artifact but is hidden by an
  active filter (severity chips, "Marked only", MPLog default
  filter), surface a toast: "Row is hidden by an active filter —
  clear filters to see it" rather than silently selecting the
  wrong row.
- [x] Wired existing timeline "Open in <artifact>" + artifact-chip
  links to pass `targetRowKey: e.rowKey` — fixes the bug in place
  for the pre-existing callers.

**CSS cleanup:**
- [x] `--mono` variable defined once in `themes.css`'s theme-
  invariant `:root` (separate from per-theme palette blocks since
  the mono font stack doesn't vary by theme). All 28 inline
  `'JetBrains Mono'`-family declarations across `app.css` and
  `extras.css` consolidated to `var(--mono)`. Single source of
  truth.

**Not in this release (deferred):**
- Tier-2 triage items (PowerShell encoded-command detection,
  recently-created executables in user-writable paths from MFT,
  WMI persistence). Will land as v0.17.0 if there's appetite.
- Per-host Triage panel collapse state persistence across page
  reloads (currently session-scoped via `state.collapsedTriage`).

### Phase 3 host overview — Per-host targeted re-preprocessing

Re-runs `Run-ZimmermanTools.ps1` against an existing host's image
without creating a new case. UI is the v0.13.0 wizard with:
  - OutputRoot locked to current case dir
  - HostName locked to the target host
  - Default tool selection is empty (re-run is selective by design)
  - Existing CSVs overwritten by tool re-runs (analyst-acknowledged)

The "Local Users + SUSPECT classification" idea is dropped — the
SUSPECT logic needs explicit rules that didn't exist, and the
mockup's analyst value can be served by inspecting the Hayabusa
4624 rows directly in the artifact tab.

### Watched directory

Was originally v0.12.0; superseded by the drag-and-drop + wizard
combo. Bring back only if analysts hit a case where neither covers
the workflow.

### Distribution bundling

`make dist` should produce a Windows zip with `douglas.exe`,
`Run-ZimmermanTools.ps1`, and a README pointing analysts at the
gear icon. Currently `make windows` produces just the binary.

### Cross-platform artifact support

See historical notes; Linux artifacts (auditd, journal, etc.)
and macOS (FSEvents, unified logs) need their own parsers and
preprocessors.

