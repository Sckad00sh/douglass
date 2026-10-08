# Security

## Threat model

Douglas is a local, single-binary DFIR review tool. Its security
posture is shaped by four facts:

1. **Artifact data is hostile.** The CSVs Douglas parses come from
   compromised machines. Field contents (file paths, registry values,
   event descriptions) can contain arbitrary bytes, including HTML,
   script, and spreadsheet formulas. All artifact data is treated as
   untrusted.
2. **It's a local web server reachable from the analyst's browser.**
   It binds to `127.0.0.1:<random-port>`. The browser is the main
   untrusted vector — a malicious web page the analyst has open could
   try to reach the local API (DNS rebinding, CSRF).
3. **It runs subprocesses.** The preprocessor invokes PowerShell + EZ
   Tools. Argument handling is the command-injection surface.
4. **It reads and writes the filesystem.** Case folders, artifact
   files, uploads, and the marks file. Path traversal is the surface.

The analyst (the local user) is trusted. A local process running as
the same user is outside the threat model — it already has the
analyst's filesystem access. The defenses target the browser vector
and hostile artifact data, not the local user.

## Defenses in place

**Network boundary**
- Host-header allowlist (`127.0.0.1` / `localhost` / `::1` only) —
  defeats DNS rebinding.
- CSRF guard: mutating + most GET `/api/*` calls require a custom
  `X-Requested-By: douglas` header. No `Access-Control-Allow-*` headers
  are ever returned, so a cross-origin preflight fails before the real
  request is sent.
- Strict CSP: `script-src 'self'`, `style-src 'self'`,
  `frame-ancestors 'none'`, `form-action 'none'`, `base-uri 'none'`.
  Plus `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`.

**XSS / hostile artifact data**
- The frontend has no `innerHTML` injection sink. The DOM helper
  (`$()` in app.js) routes all data through `document.createTextNode`,
  which escapes by construction. There is intentionally no innerHTML
  escape hatch.
- No dynamic `href`/`src` (no `javascript:` URI vector), no `eval` /
  `new Function` / string-form timers, no template engine.

**Command injection (preprocessor)**
- Subprocess invocation uses `exec.CommandContext` with separate argv
  elements — no shell, so shell metacharacters cannot break out.
- Free-form fields (`Operator`, `CollectionMethod`) are passed as
  named-parameter values; PowerShell's binder takes the following token
  as the argument even if it starts with `-`, so parameter smuggling is
  not viable. NUL bytes are rejected defensively.

**Path traversal**
- Artifact loading (`LoadArtifact`) and triage build no path from
  request strings — they allowlist-match host/artifact IDs against the
  discovered case, so `../` values return "not found."
- Upload validates `hostID` against the known-host list before building
  any path, sanitizes the filename (`filepath.Base` + safe-charset
  regex + NUL strip + dot/space trim + 200-char cap), and verifies the
  resolved destination is within the host's artifacts dir via an
  absolute-path prefix check.
- `-RECmdBatch` (preprocessor) is validated to be an existing `.reb`
  file.

**Resource / DoS**
- All JSON request bodies are size-capped via `http.MaxBytesReader`
  before decoding.
- Uploads cap at 10 GB with artifact-type validation.
- The marks file read is capped with `io.LimitReader` (16 MB) so a
  planted/corrupted `marks.json` can't OOM the process.

**Other**
- Marks are written atomically (temp + rename) as JSON; no injection
  vector (JSON encoding escapes by construction).
- No decompression code anywhere — zero zip-slip surface.
- Logging records only paths, host counts, and the interpreter path —
  no secrets (the app has no auth/tokens).

## Accepted residual risks (by design)

- `/api/open` and `/api/browse` can read any path the analyst's user
  can access. This is intentional: a local DFIR tool must let the
  analyst open a case from anywhere, same trust boundary as the CLI.
  The only residual risk is a malicious *local* process that discovered
  the random port — which already has the user's filesystem access, so
  this grants nothing new. The network defenses above gate the browser
  vector.

## Known forward-looking item

- **CSV export does not exist yet.** When it's built, fields must be
  escaped against spreadsheet formula injection (leading `= + - @` tab
  CR). See the Deferred features note in TODO.md. Douglas renders data
  as text and never evaluates it, so this only matters once data is
  handed to an external spreadsheet via export.

## Audit history

- **2026-05-28 (v0.17.0)** — Full read of all HTTP handlers, the
  subprocess runner, path handling, frontend rendering, and file I/O.
  No exploitable vulnerability found. The defenses above were verified
  present and correct. The only safe, non-disruptive hardening
  candidates considered were either already implemented (marks read
  cap) or would harm legitimate usage (e.g. `0600` on `marks.json`
  would break multi-analyst case sharing on Unix and is a no-op on
  Windows), so no code changes were made. The single forward-looking
  item (CSV export escaping) was recorded for when that feature exists.
- **(earlier, "Aurora" lineage)** — a prior audit on a related codebase
  fixed an OAuth token log leak, added field-length constraints, and
  added login rate limiting. Those issues do not apply here (Douglas
  has no auth, no tokens, no login).
