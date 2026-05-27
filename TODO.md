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

## Polish

(empty -- add as things come up)
