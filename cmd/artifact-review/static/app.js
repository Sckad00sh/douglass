// ============================================================
// Douglas — DFIR artifact review front-end
// Vanilla JS, no build step. Consumes the Go server's JSON API.
// ============================================================
'use strict';

// ---------------------- small helpers ----------------------

const $ = (tag, props = {}, ...children) => {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === 'class') el.className = v;
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    // No innerHTML escape hatch. All children go through createTextNode
    // (see appendChild below), which escapes by construction. CSV data
    // from a compromised host can contain arbitrary HTML; routing it
    // through innerHTML would be XSS.
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  const appendChild = (c) => {
    if (c == null || c === false || c === true) return;
    if (Array.isArray(c)) { for (const inner of c) appendChild(inner); return; }
    if (typeof c === 'string' || typeof c === 'number') {
      el.appendChild(document.createTextNode(String(c)));
      return;
    }
    if (c instanceof Node) {
      el.appendChild(c);
      return;
    }
    // anything else (object, function from a bad ternary, etc) -- log and skip
    // so a single mis-typed value doesn't kill the whole render.
    console.warn('$(): skipped non-renderable child', c, 'in <' + tag + '>');
  };
  for (const c of children) appendChild(c);
  return el;
};

const fmtBytes = (n) => {
  n = Number(n);
  if (!isFinite(n) || n === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n.toFixed(0) : n.toFixed(1)) + ' ' + units[i];
};

const truncateHash = (s) => (s && s.length > 12 ? s.slice(0, 12) + '…' : s || '');

const debounce = (fn, ms) => {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
};

const fetchJSON = async (url, opts) => {
  // Inject the CSRF guard header. The server requires X-Requested-By
  // on every /api/* call (except /api/health). Browsers won't send a
  // custom header on cross-origin requests without a CORS preflight,
  // and we never return CORS allow-headers -- so an attacker page can't
  // forge this header even via DNS rebinding.
  const merged = {
    ...opts,
    headers: {
      'X-Requested-By': 'douglas',
      ...(opts && opts.headers),
    },
  };
  const r = await fetch(url, merged);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
};

// Severity rank for sorting / display
const SEV_RANK = { crit: 0, high: 1, med: 2, low: 3, info: 4 };

// ---------------------- ui sizing prefs ----------------------
// Per-user UI prefs persisted in localStorage so column widths and the
// detail-drawer height survive reloads. Keyed by artifact id for columns
// (column widths are a property of the artifact schema, not the host or
// case) and a single global key for drawer height.

const COLW_KEY = 'ar.colWidths.v1';      // { [artifactId]: { [colKey]: w } }
const DRAWERH_KEY = 'ar.drawerHeight.v1';  // number, px
const DRAWER_MIN = 80;
const DRAWER_MAX_RATIO = 0.7;            // never let drawer exceed 70% of wrap
const COL_MIN = 40;                      // never let a column drop below 40px

const loadColWidths = (artifactId) => {
  try {
    const raw = localStorage.getItem(COLW_KEY);
    if (!raw) return {};
    const all = JSON.parse(raw);
    return (all && typeof all === 'object' && all[artifactId]) || {};
  } catch { return {}; }
};
const saveColWidth = (artifactId, colKey, w) => {
  try {
    const raw = localStorage.getItem(COLW_KEY);
    const all = raw ? JSON.parse(raw) : {};
    if (!all[artifactId]) all[artifactId] = {};
    all[artifactId][colKey] = Math.max(COL_MIN, Math.round(w));
    localStorage.setItem(COLW_KEY, JSON.stringify(all));
  } catch {}
};
const loadDrawerHeight = () => {
  try {
    const v = parseInt(localStorage.getItem(DRAWERH_KEY), 10);
    return isFinite(v) && v >= DRAWER_MIN ? v : 280;
  } catch { return 280; }
};
const saveDrawerHeight = (h) => {
  try { localStorage.setItem(DRAWERH_KEY, String(Math.round(h))); } catch {}
};

// effectiveColWidth returns the analyst-overridden width for a column if
// one is stored, otherwise the schema default. Applied at render time so
// the in-memory registry stays untouched.
const effectiveColWidth = (artifactId, col, overrides) => {
  const o = (overrides && overrides[col.key]);
  return o ? Math.max(COL_MIN, o) : (col.w || 120);
};

// ---------------------- export helpers ----------------------

// Trigger a browser download for the given content.
const downloadBlob = (filename, content, mime) => {
  const blob = content instanceof Blob
    ? content
    : new Blob([content], { type: mime || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  // microtask to ensure click has fired before revoking
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 0);
};

// RFC-4180 CSV escape: quote any field containing comma, quote, CR, or LF.
// Doubles internal quotes. Always uses \r\n line terminator for max
// compatibility with Excel / PowerShell Import-Csv.
const csvEscape = (v) => {
  if (v == null) return '';
  const s = String(v);
  if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
};
const toCSV = (headers, rows) => {
  const out = [headers.map(csvEscape).join(',')];
  for (const row of rows) {
    out.push(headers.map(h => csvEscape(row[h])).join(','));
  }
  return out.join('\r\n') + '\r\n';
};

// Filename-safe slug (alphanumeric + dash, collapsed).
const slugify = (s) => String(s || 'export')
  .replace(/[^A-Za-z0-9._-]+/g, '-')
  .replace(/^-+|-+$/g, '')
  .toLowerCase() || 'export';

// Date stamp YYYYMMDD-HHMMSS in local time, for filenames.
const stamp = () => {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
};

// collectFieldKeys returns the ordered union of every field present in the
// given rows. Schema columns come first (in their declared display order),
// followed by any extra fields the parser found in the CSV but that aren't
// in our curated schema, sorted alphabetically. Internal markers (__row)
// are excluded.
const collectFieldKeys = (art, rows) => {
  const schemaKeys = (art.columns || []).map(c => c.key);
  const schemaSet = new Set(schemaKeys);
  const extras = new Set();
  for (const { r } of rows) {
    for (const k of Object.keys(r)) {
      if (k.startsWith('__')) continue;
      if (schemaSet.has(k)) continue;
      extras.add(k);
    }
  }
  return {
    schema: schemaKeys,
    extra: [...extras].sort((a, b) => a.localeCompare(b)),
  };
};

// Export a list of rows from the artifact view, including ONLY the field
// keys named in `selectedKeys` (an ordered array). Used by the export
// picker modal so the analyst controls exactly which columns ship.
const exportArtifactRows = (art, host, rows, format, selectedKeys) => {
  // Fall back to all schema columns if no explicit selection was passed
  // (keeps older call sites working).
  const headers = (selectedKeys && selectedKeys.length)
    ? selectedKeys
    : (art.columns || []).map(c => c.key);
  const base = `${slugify(host.name)}-${slugify(art.id)}-${stamp()}`;
  // Strip our internal __row marker; keep only the chosen keys.
  const clean = rows.map(({ r }) => {
    const out = {};
    for (const h of headers) out[h] = r[h] != null ? r[h] : '';
    return out;
  });
  if (format === 'csv') {
    // Lead with UTF-8 BOM so Excel auto-detects encoding. Python/pandas
    // need encoding='utf-8-sig' to read this cleanly.
    downloadBlob(`${base}.csv`, '\ufeff' + toCSV(headers, clean), 'text/csv;charset=utf-8');
  } else {
    // For JSON, include the column metadata only for those schema columns
    // that were actually selected, so the envelope stays consistent.
    const selSet = new Set(headers);
    const selectedCols = (art.columns || []).filter(c => selSet.has(c.key));
    downloadBlob(`${base}.json`, JSON.stringify({
      host: { id: host.id, name: host.name },
      artifact: { id: art.id, name: art.name, tool: art.tool, sourceFile: art.sourceFile },
      exportedAt: new Date().toISOString(),
      rowCount: clean.length,
      fields: headers,
      columns: selectedCols,
      rows: clean,
    }, null, 2), 'application/json');
  }
  toast(`exported ${clean.length} rows (${headers.length} fields) as ${format.toUpperCase()}`);
};

// openExportPicker shows a modal letting the analyst choose the output
// format and exactly which fields to include. Schema columns are listed
// first (pre-checked), then any extra CSV fields (also pre-checked, but
// visually grouped so the analyst sees what's "beyond" the curated view).
function openExportPicker(art, host, rows) {
  document.querySelectorAll('.modal-backdrop').forEach(el => el.remove());

  const { schema, extra } = collectFieldKeys(art, rows);
  // label lookup: schema columns have friendly labels; extras use the key.
  const labelFor = {};
  for (const c of (art.columns || [])) labelFor[c.key] = c.label || c.key;

  // selection state — every key starts checked
  const checked = new Set([...schema, ...extra]);
  let format = 'csv';
  let rerender;

  const backdrop = $('div', {
    class: 'modal-backdrop',
    onclick: (e) => { if (e.target === backdrop) backdrop.remove(); },
  });

  const doExport = () => {
    // Preserve declared order: schema keys first (in schema order), then
    // extras (in their sorted order), filtered to the checked set.
    const ordered = [...schema, ...extra].filter(k => checked.has(k));
    if (ordered.length === 0) {
      toast('select at least one field to export', true);
      return;
    }
    exportArtifactRows(art, host, rows, format, ordered);
    backdrop.remove();
  };

  const fieldRow = (key, isExtra) => {
    const id = 'exp-fld-' + key;
    return $('label', { class: 'exp-field', for: id },
      $('input', {
        type: 'checkbox',
        id,
        checked: checked.has(key) ? 'checked' : false,
        onchange: (e) => {
          if (e.target.checked) checked.add(key);
          else checked.delete(key);
          rerender();
        },
      }),
      $('span', { class: 'exp-field-label' }, isExtra ? key : (labelFor[key] || key)),
      isExtra && $('span', { class: 'exp-field-tag' }, 'extra'),
    );
  };

  const buildModal = () => {
    const selCount = [...schema, ...extra].filter(k => checked.has(k)).length;
    const total = schema.length + extra.length;
    return $('div', { class: 'modal export-modal', onclick: (e) => e.stopPropagation() },
      $('div', { class: 'modal-head' },
        $('div', { class: 'ico' }, '⤓'),
        $('h3', null, 'Export artifact'),
        $('button', { class: 'close', title: 'close', onclick: () => backdrop.remove() }, '✕'),
      ),
      $('div', { class: 'modal-body' },
        $('p', null,
          `${rows.length.toLocaleString()} row(s) from ${art.name}. ` +
          'Choose a format and which fields to include.'),

        $('label', null, 'Format'),
        $('div', { class: 'exp-format' },
          ...['csv', 'json'].map(f => $('button', {
            class: 'btn' + (format === f ? ' primary' : ''),
            onclick: () => { format = f; rerender(); },
          }, f.toUpperCase())),
        ),

        $('div', { class: 'exp-fields-head' },
          $('label', null, `Fields (${selCount} of ${total})`),
          $('span', { class: 'tb-spacer' }),
          $('button', {
            class: 'linkbtn',
            onclick: () => { [...schema, ...extra].forEach(k => checked.add(k)); rerender(); },
          }, 'All'),
          $('button', {
            class: 'linkbtn',
            onclick: () => { checked.clear(); rerender(); },
          }, 'None'),
          $('button', {
            class: 'linkbtn',
            onclick: () => {
              checked.clear();
              schema.forEach(k => checked.add(k));
              rerender();
            },
          }, 'Schema only'),
        ),

        $('div', { class: 'exp-field-list' },
          schema.length > 0 && $('div', { class: 'exp-group-label' }, 'Displayed columns'),
          ...schema.map(k => fieldRow(k, false)),
          extra.length > 0 && $('div', { class: 'exp-group-label' },
            `Additional fields in source CSV (${extra.length})`),
          ...extra.map(k => fieldRow(k, true)),
        ),
      ),
      $('div', { class: 'modal-foot' },
        $('button', { class: 'btn', onclick: () => backdrop.remove() }, 'Cancel'),
        $('button', { class: 'btn primary', onclick: doExport },
          `Export ${selCount} field(s)`),
      ),
    );
  };

  rerender = () => {
    backdrop.innerHTML = '';
    backdrop.appendChild(buildModal());
  };

  document.body.appendChild(backdrop);
  rerender();
  const onKey = (e) => {
    if (e.key === 'Escape') {
      backdrop.remove();
      document.removeEventListener('keydown', onKey);
    }
  };
  document.addEventListener('keydown', onKey);
}

// Export the timeline (marks) with the FULL underlying artifact row for
// each mark. Marks can span different artifact types with different
// snapshot schemas, so the CSV variant emits the core mark fields followed
// by the union of every snapshot field seen across all marks, each
// namespaced with a "data." prefix to avoid colliding with mark metadata.
// Cells are blank where a given mark's artifact lacks that field.
// The JSON variant carries each mark's snapshot object verbatim.
const TL_CORE_COLS = ['ts', 'sev', 'hostId', 'artifactId', 'label', 'note', 'createdAt'];
const exportTimelineEvents = (events, scopeLabel, format) => {
  const base = `timeline-${slugify(scopeLabel || 'global')}-${stamp()}`;

  if (format === 'csv') {
    // Collect the union of snapshot field keys across every mark.
    const snapKeys = new Set();
    for (const e of events) {
      const snap = e.snapshot || {};
      for (const k of Object.keys(snap)) {
        if (k.startsWith('__')) continue;
        snapKeys.add(k);
      }
    }
    const dataCols = [...snapKeys].sort((a, b) => a.localeCompare(b));
    // Final header: core mark columns + namespaced snapshot columns.
    const headers = [...TL_CORE_COLS, ...dataCols.map(k => 'data.' + k)];
    const rows = events.map(e => {
      const row = {
        ts: e.ts || '',
        sev: e.sev || '',
        hostId: e.hostId || '',
        artifactId: e.artifactId || '',
        label: e.label || '',
        note: e.note || '',
        createdAt: e.createdAt || '',
      };
      const snap = e.snapshot || {};
      for (const k of dataCols) {
        row['data.' + k] = snap[k] != null ? snap[k] : '';
      }
      return row;
    });
    downloadBlob(`${base}.csv`, '\ufeff' + toCSV(headers, rows), 'text/csv;charset=utf-8');
  } else {
    // JSON: each event already carries its snapshot. Emit a clean envelope
    // with the full mark objects (snapshot included).
    downloadBlob(`${base}.json`, JSON.stringify({
      scope: scopeLabel || 'global',
      exportedAt: new Date().toISOString(),
      count: events.length,
      events: events.map(e => ({
        ts: e.ts || '',
        severity: e.sev || '',
        hostId: e.hostId || '',
        artifactId: e.artifactId || '',
        label: e.label || '',
        note: e.note || '',
        createdAt: e.createdAt || '',
        rowKey: e.rowKey || '',
        snapshot: e.snapshot || {},
      })),
    }, null, 2), 'application/json');
  }
  toast(`exported ${events.length} events as ${format.toUpperCase()}`);
};

// Small inline two-option export menu. Anchors itself below the trigger
// button and closes on outside click.
const showExportMenu = (anchor, onChoose) => {
  // tear down any existing menu first
  document.querySelectorAll('.export-menu').forEach(el => el.remove());
  const rect = anchor.getBoundingClientRect();
  const menu = $('div', {
    class: 'export-menu',
    style: {
      position: 'fixed',
      top: (rect.bottom + 4) + 'px',
      left: rect.left + 'px',
      zIndex: '50',
    },
  },
    $('div', {
      class: 'export-opt',
      onclick: () => { onChoose('csv'); menu.remove(); },
    }, 'CSV (.csv)'),
    $('div', {
      class: 'export-opt',
      onclick: () => { onChoose('json'); menu.remove(); },
    }, 'JSON (.json)'),
  );
  document.body.appendChild(menu);
  // close on next click anywhere else
  setTimeout(() => {
    const off = (ev) => {
      if (menu.contains(ev.target)) return;
      menu.remove();
      document.removeEventListener('click', off, true);
    };
    document.addEventListener('click', off, true);
  }, 0);
};

// ---------------------- import-case modal ----------------------

const RECENT_KEY = 'ar.recentCases';
const RECENT_MAX = 8;

const loadRecent = () => {
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr.filter(x => typeof x === 'string') : [];
  } catch { return []; }
};
const saveRecent = (list) => {
  try { localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, RECENT_MAX))); }
  catch {}
};
const rememberCase = (path) => {
  if (!path) return;
  const list = loadRecent().filter(p => p !== path);
  list.unshift(path);
  saveRecent(list);
};
const forgetCase = (path) => {
  saveRecent(loadRecent().filter(p => p !== path));
};

// openImportModal renders a modal letting the analyst type or pick a path
// to a case folder, then POSTs it to /api/open. On success the modal closes
// and the app re-bootstraps to load the new case.
function openImportModal() {
  // tear down any existing modal first
  document.querySelectorAll('.modal-backdrop').forEach(el => el.remove());

  let pathValue = '';
  let errMsg = '';
  let busy = false;

  // forward-declared so handlers below can call it
  let rerender;

  const submit = async (path) => {
    const p = (path || pathValue || '').trim();
    if (!p) {
      errMsg = 'Path is required.';
      rerender();
      return;
    }
    // If a different case is already open, confirm. Comparing the absolute
    // path the server resolved against the requested path is best-effort;
    // we use string equality as a heuristic.
    if (state.caseDir && state.caseDir !== p && !confirm(
        `A case is currently open:\n  ${state.caseDir}\n\nOpening "${p}" will close any unsaved tabs. Continue?`
    )) {
      return;
    }
    busy = true;
    errMsg = '';
    rerender();
    try {
      const result = await api.open(p);
      if (result && result.warning) {
        // server opened the case but marks.json had issues — surface but proceed
        toast('opened with warning: ' + result.warning, true);
      } else {
        toast('case opened: ' + p);
      }
      // Empty-artifact count is surfaced from bootstrap() below via /api/case,
      // so we don't double-toast here.
      rememberCase(p);
      backdrop.remove();
      // re-bootstrap to load the new case data
      await bootstrap();
    } catch (e) {
      errMsg = (e && e.message ? e.message : String(e)).replace(/^\{[^}]*"error":\s*"([^"]+)".*$/, '$1');
      busy = false;
      rerender();
    }
  };

  const recent = loadRecent();

  const backdrop = $('div', {
    class: 'modal-backdrop',
    onclick: (e) => { if (e.target === backdrop) backdrop.remove(); },
  });

  rerender = () => {
    backdrop.innerHTML = '';
    backdrop.appendChild(buildModal());
    const inp = backdrop.querySelector('input[type="text"]');
    if (inp) {
      inp.focus();
      inp.setSelectionRange(inp.value.length, inp.value.length);
    }
  };

  const buildModal = () => $('div', {
      class: 'modal',
      onclick: (e) => e.stopPropagation(),
      // Allow drag-and-drop onto the whole modal body. Browsers don't expose
      // host paths for security reasons, but a few drag sources (e.g. dragging
      // text from File Explorer's address bar) provide a usable string —
      // we accept it. Otherwise we show a hint.
      ondragover: (e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; },
      ondrop: (e) => {
        e.preventDefault();
        const tryPath = extractDroppedPath(e.dataTransfer);
        if (tryPath) {
          pathValue = tryPath;
          errMsg = '';
          rerender();
        } else {
          errMsg = "Couldn't extract a path from that drop. Browser security prevents reading host file paths from dragged folders. Use the Browse button instead, or paste the path manually.";
          rerender();
        }
      },
    },
    $('div', { class: 'modal-head' },
      $('div', { class: 'ico' }, '📂'),
      $('h3', null, 'Import case'),
      $('button', {
        class: 'close',
        title: 'close',
        onclick: () => backdrop.remove(),
      }, '✕'),
    ),
    $('div', { class: 'modal-body' },
      $('p', null,
        'Open a case directory containing one subdirectory per host. ' +
        'Click Browse to pick from a folder tree, paste a path below, or drag the path text from File Explorer.'),
      $('label', null, 'Case folder path'),
      $('div', { class: 'path-row' },
        $('input', {
          type: 'text',
          class: errMsg ? 'err' : '',
          placeholder: '/path/to/case   or   C:\\cases\\acme-2025',
          value: pathValue,
          disabled: busy ? 'disabled' : false,
          oninput: (e) => { pathValue = e.target.value; if (errMsg) { errMsg = ''; rerender(); } },
          onkeydown: (e) => { if (e.key === 'Enter') submit(); },
        }),
        $('button', {
          class: 'btn',
          disabled: busy ? 'disabled' : false,
          onclick: () => openFolderBrowser(pathValue, (picked) => {
            pathValue = picked;
            errMsg = '';
            rerender();
          }),
        }, '📁 Browse...'),
      ),
      errMsg && $('div', { class: 'err-msg' }, '⚠ ' + errMsg),
      $('label', null, `Recent cases (${recent.length})`),
      recent.length
        ? $('div', { class: 'recent-list' },
            ...recent.map(p => $('div', {
              class: 'recent-row',
              onclick: () => submit(p),
            },
              $('span', { class: 'path', title: p }, p),
              $('button', {
                class: 'forget',
                title: 'remove from history',
                onclick: (e) => { e.stopPropagation(); forgetCase(p); rerender(); },
              }, '✕'),
            )),
          )
        : $('div', { class: 'recent-list' },
            $('div', { class: 'recent-empty' }, 'No recent cases yet.'),
          ),
    ),
    $('div', { class: 'modal-foot' },
      $('button', {
        class: 'btn',
        disabled: busy ? 'disabled' : false,
        onclick: () => backdrop.remove(),
      }, 'Cancel'),
      $('button', {
        class: 'btn primary',
        disabled: busy ? 'disabled' : false,
        onclick: () => submit(),
      }, busy ? 'Opening…' : 'Open case'),
    ),
  );

  document.body.appendChild(backdrop);
  rerender();
  // ESC to close
  const onKey = (e) => {
    if (e.key === 'Escape') {
      backdrop.remove();
      document.removeEventListener('keydown', onKey);
    }
  };
  document.addEventListener('keydown', onKey);
}

// extractDroppedPath inspects a DataTransfer and tries to find a usable
// host-filesystem path. Browser security prevents reading the actual host
// path of a dragged folder in most cases, but a few drag sources DO expose
// path-like text:
//   * dragging text from File Explorer's address bar (Edge/Chrome on Win)
//     surfaces "text/plain" containing the path
//   * dragging a folder shortcut may surface "text/uri-list" with file://
// Returns "" if nothing usable was found.
function extractDroppedPath(dt) {
  if (!dt) return '';
  // Try text/uri-list first (most reliable when present)
  const uriList = dt.getData('text/uri-list');
  if (uriList) {
    const first = uriList.split(/\r?\n/).find(l => l && !l.startsWith('#'));
    if (first && first.startsWith('file://')) {
      // file:///C:/Users/...  ->  C:/Users/...
      // file:///home/...      ->  /home/...
      try {
        let p = decodeURIComponent(first.slice('file://'.length));
        // Windows: file:///C:/foo -> /C:/foo -> strip the leading slash
        if (/^\/[A-Za-z]:/.test(p)) p = p.slice(1);
        // Normalize forward slashes to backslashes on Windows-style paths
        if (/^[A-Za-z]:/.test(p)) p = p.replace(/\//g, '\\');
        return p;
      } catch { /* fall through */ }
    }
  }
  // Try plain text — Explorer address bar gives a usable path here
  const text = dt.getData('text/plain');
  if (text && (text.match(/^[A-Za-z]:[\\/]/) || text.startsWith('/') || text.startsWith('\\\\'))) {
    return text.trim().replace(/^["']|["']$/g, '');
  }
  return '';
}

// openFolderBrowser pops a sub-modal showing a server-side directory tree.
// onPick(path) is called with the chosen folder path when the user clicks
// "Select this folder". The sub-modal closes on its own.
//
// startPath: optional initial path to start the browser at. If empty, the
// browser begins at the filesystem root listing.
function openFolderBrowser(startPath, onPick) {
  document.querySelectorAll('.browser-backdrop').forEach(el => el.remove());

  let currentDir = '';
  let entries = [];
  let parent = '';
  let separator = '/';
  let isRoot = true;
  let hasArtifactHere = false;
  let loading = true;
  let errMsg = '';

  const backdrop = $('div', {
    class: 'modal-backdrop browser-backdrop',
    onclick: (e) => { if (e.target === backdrop) backdrop.remove(); },
  });

  const load = async (dir) => {
    loading = true;
    errMsg = '';
    rerender();
    try {
      const r = await api.browse(dir || '');
      currentDir = r.dir || '';
      parent = r.parent || '';
      separator = r.separator || '/';
      entries = r.entries || [];
      isRoot = !!r.isRoot;
      hasArtifactHere = !!r.hasArtifactHere;
    } catch (e) {
      errMsg = (e.message || String(e)).replace(/^\{[^}]*"error":\s*"([^"]+)".*$/, '$1');
      entries = [];
    } finally {
      loading = false;
      rerender();
    }
  };

  // Build a breadcrumb showing the current path. The home link returns
  // to the root listing; the rest of the path is non-clickable (use Up).
  // Reconstructing intermediate paths reliably from a separator-split is
  // hard across Windows/Unix edge cases (UNC paths, drive letters, trailing
  // separators), so we keep this simple and rely on the Up button for
  // navigation.
  const renderCrumbs = () => {
    if (!currentDir) {
      return $('div', { class: 'fb-crumbs' },
        $('span', { class: 'crumb cur' }, 'My computer'));
    }
    return $('div', { class: 'fb-crumbs' },
      $('span', {
        class: 'crumb link',
        onclick: () => load(''),
      }, 'My computer'),
      $('span', { class: 'crumb-sep' }, separator),
      $('span', { class: 'crumb cur' }, currentDir),
    );
  };

  const buildSub = () => $('div', {
      class: 'modal browser-modal',
      onclick: (e) => e.stopPropagation(),
    },
    $('div', { class: 'modal-head' },
      $('div', { class: 'ico' }, '📁'),
      $('h3', null, 'Choose a case folder'),
      $('button', {
        class: 'close',
        title: 'close',
        onclick: () => backdrop.remove(),
      }, '✕'),
    ),
    $('div', { class: 'modal-body' },
      renderCrumbs(),
      !isRoot && $('div', { class: 'fb-action-row' },
        $('button', {
          class: 'btn',
          onclick: () => load(parent || ''),
        }, '↰ Up'),
        $('span', { class: 'tb-spacer' }),
        hasArtifactHere && $('span', { class: 'fb-hint' },
          '⚡ This folder contains recognized artifact CSVs'),
      ),
      loading && $('div', { class: 'fb-loading' }, 'Loading…'),
      errMsg && $('div', { class: 'err-msg' }, '⚠ ' + errMsg),
      !loading && !errMsg && entries.length === 0 && $('div', { class: 'fb-empty' },
        isRoot ? 'No filesystem roots found.' : 'No subdirectories here.'),
      !loading && entries.length > 0 && $('div', { class: 'fb-list' },
        ...entries.map(e => $('div', {
          class: 'fb-row' + (e.hasArtifactsHint ? ' hint' : ''),
          onclick: () => load(e.path),
          title: e.path,
        },
          $('span', { class: 'fb-ico' }, e.hasArtifactsHint ? '⚡' : '📁'),
          $('span', { class: 'fb-name' }, e.name),
          $('span', { class: 'fb-path' }, e.path),
        )),
      ),
    ),
    $('div', { class: 'modal-foot' },
      $('div', { class: 'fb-current' },
        currentDir ? ('Selected: ' + currentDir) : 'No folder selected'),
      $('span', { class: 'tb-spacer' }),
      $('button', { class: 'btn', onclick: () => backdrop.remove() }, 'Cancel'),
      $('button', {
        class: 'btn primary',
        disabled: !currentDir || loading ? 'disabled' : false,
        onclick: () => {
          onPick(currentDir);
          backdrop.remove();
        },
      }, 'Select this folder'),
    ),
  );

  const rerender = () => {
    backdrop.innerHTML = '';
    backdrop.appendChild(buildSub());
  };

  document.body.appendChild(backdrop);
  // ESC closes
  const onKey = (e) => {
    if (e.key === 'Escape') {
      backdrop.remove();
      document.removeEventListener('keydown', onKey);
    }
  };
  document.addEventListener('keydown', onKey);

  // Initial load: start at the given path if provided, else at filesystem roots.
  load(startPath || '');
}

const THEMES = [
  { id: 'yaru-dark',      name: 'Yaru Dark',      desc: 'Ubuntu' },
  { id: 'yaru-light',     name: 'Yaru Light',     desc: 'Ubuntu light' },
  { id: 'velociraptor',   name: 'Velociraptor',   desc: 'DFIR classic' },
  { id: 'dracula',        name: 'Dracula',        desc: 'High contrast' },
  { id: 'nord',           name: 'Nord',           desc: 'Cool blues' },
  { id: 'solarized-dark', name: 'Solarized Dark', desc: 'Old reliable' },
];

const loadTheme = () => localStorage.getItem('ar.theme') || 'yaru-dark';
const saveTheme = (id) => localStorage.setItem('ar.theme', id);
const applyTheme = (id) => document.documentElement.setAttribute('data-theme', id);

// ---------------------- application state ----------------------

const state = {
  caseInfo: null,    // { id, name, ... }
  caseDir: '',
  hosts: [],         // [Host]
  marks: [],         // [Mark]
  expandedHosts: new Set(),
  tabs: [],          // [{ kind: 'artifact'|'host-timeline'|'global-timeline', hostId, artifactId, label }]
  activeTab: -1,
  artifactCache: {}, // key "host|art" -> full artifact
  searchHost: '',
  theme: loadTheme(),
};

applyTheme(state.theme);

// per-tab UI state, keyed by tab index
const tabState = new Map();
const getTabState = (i) => {
  if (!tabState.has(i)) {
    tabState.set(i, {
      selectedRow: -1,
      drawerOpen: true,
      filter: '',
      // Per-column filter strings, keyed by column.key. Empty string ==
      // no filter on that column. Parsed lazily via parseColumnFilter.
      colFilters: {},
      // Set of column keys with their filter input currently expanded
      // beneath the column header. Click the funnel toggle on a th to
      // open/close. Active filters stay applied regardless of expansion;
      // collapsing just hides the input.
      openFilterCols: new Set(),
      severities: new Set(),
      markedOnly: false,
      sortKey: null,
      sortDir: 'asc',
      expandedEvents: new Set(),
      tlSeverities: new Set(),
      tlHostFilter: new Set(),
      tlSearch: '',
      tlSort: 'asc',
    });
  }
  return tabState.get(i);
};

// ---------------------- API wrappers ----------------------

const api = {
  case: () => fetchJSON('/api/case'),
  open: (dir) => fetchJSON('/api/open', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ dir }),
  }),
  browse: (dir) => fetchJSON('/api/browse' + (dir ? '?dir=' + encodeURIComponent(dir) : '')),
  artifact: (h, a) => fetchJSON(`/api/artifact?h=${encodeURIComponent(h)}&a=${encodeURIComponent(a)}`),
  listMarks: (host) => fetchJSON('/api/marks' + (host ? `?host=${encodeURIComponent(host)}` : '')),
  saveMark: (m) => fetchJSON('/api/marks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(m),
  }),
  deleteMark: (id) => fetchJSON('/api/marks/' + encodeURIComponent(id), { method: 'DELETE' }),
};

// ---------------------- toast ----------------------

let toastTimer = null;
const toast = (msg, isErr = false) => {
  document.querySelectorAll('.toast').forEach(t => t.remove());
  const el = $('div', { class: 'toast' + (isErr ? ' err' : '') }, msg);
  document.body.appendChild(el);
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.remove(), 3000);
};

// ---------------------- mark helpers (client-side) ----------------------

const markId = (hostId, artifactId, rowKey) => `${hostId}|${artifactId}|${rowKey}`;
const findMark = (hostId, artifactId, rowKey) =>
  state.marks.find(m => m.id === markId(hostId, artifactId, rowKey));

// derive a stable rowKey from a row. Mirrors marks.RowKey on the server.
// Server uses SHA-1 of joined "key=value" pairs; here we use a cheaper
// JS-side fingerprint that's stable across reloads of the same data.
const PREFERRED_KEYS = [
  'Timestamp', 'TimeCreated', 'LastRun', 'FileKeyLastWriteTimestamp',
  'Created0x10', 'LastModified0x10', 'EntryNumber',
  'FileName', 'FullPath', 'Path', 'LocalPath', 'TargetPath',
  'RuleTitle', 'MapDescription', 'ApplicationName', 'ExecutableName',
];
const rowKeyOf = (row) => {
  const parts = [];
  for (const k of PREFERRED_KEYS) {
    if (row[k]) parts.push(k + '=' + row[k]);
  }
  if (!parts.length) return row.__row || '';
  // Same idea as server: take a hex digest of the first chunk.
  // We don't need cryptographic strength here, just stability + brevity.
  let hash = 0xdeadbeef;
  const s = parts.join('|');
  for (let i = 0; i < s.length; i++) {
    hash = (hash ^ s.charCodeAt(i)) * 0x01000193 >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
};

const extractTimestamp = (row) => {
  for (const k of ['Timestamp', 'TimeCreated', 'LastRun', 'FileKeyLastWriteTimestamp',
                   'LastModifiedTimeUTC', 'Created0x10', 'LastWriteTimestamp',
                   'SourceCreated', 'TargetCreated', 'LastModified']) {
    if (row[k]) return row[k];
  }
  return '';
};

const extractLabel = (row) => {
  for (const k of ['RuleTitle', 'MapDescription', 'ExecutableName', 'ApplicationName',
                   'Path', 'FullPath', 'FileName', 'KeyPath']) {
    if (row[k]) return row[k];
  }
  return '(no label)';
};

const deriveSeverity = (artifactId, row) => {
  if (artifactId === 'hayabusa') {
    const lv = (row.Level || '').toLowerCase().trim();
    if (lv === 'crit' || lv === 'critical') return 'crit';
    if (lv === 'high') return 'high';
    if (lv === 'med' || lv === 'medium') return 'med';
    if (lv === 'low') return 'low';
    if (lv === 'info' || lv === 'informational') return 'info';
  } else if (artifactId === 'evtx') {
    const lv = (row.Level || '').toLowerCase().trim();
    if (lv === 'error' || lv === 'critical') return 'crit';
    if (lv === 'warning') return 'high';
  }
  return 'info';
};

// ---------------------- tab management ----------------------

const openTab = (tab) => {
  // dedupe
  const i = state.tabs.findIndex(t =>
    t.kind === tab.kind && t.hostId === tab.hostId && t.artifactId === tab.artifactId);
  if (i >= 0) {
    state.activeTab = i;
  } else {
    state.tabs.push(tab);
    state.activeTab = state.tabs.length - 1;
  }
  render();
};

const closeTab = (i) => {
  state.tabs.splice(i, 1);
  tabState.delete(i);
  // re-key tab state for shifted indices
  const remap = new Map();
  for (const [k, v] of tabState.entries()) {
    if (k > i) remap.set(k - 1, v); else remap.set(k, v);
  }
  tabState.clear();
  for (const [k, v] of remap.entries()) tabState.set(k, v);

  if (state.activeTab >= state.tabs.length) state.activeTab = state.tabs.length - 1;
  if (state.activeTab > i) state.activeTab--;
  render();
};

// ---------------------- bootstrap ----------------------

async function bootstrap() {
  // Reset transient state so reopening a case doesn't leave stale tabs,
  // marks, or artifact caches pointing at the previous case's data.
  state.tabs = [];
  state.activeTab = -1;
  state.artifactCache = {};
  state.expandedHosts = new Set();
  state.searchHost = '';
  tabState.clear();

  try {
    const c = await api.case();
    if (c.open) {
      state.caseInfo = c.case;
      state.caseDir = c.dir;
      state.hosts = c.hosts || [];
      state.marks = await api.listMarks();
      // Surface empty-artifact count if the server reported any. We toast
      // unconditionally here (not just on first load) so the analyst sees
      // it after a Refresh too. The import-modal flow already toasts via
      // its own success path, so a user opening through the modal may see
      // this *and* the modal's toast — which is fine; both messages are
      // useful and the modal's fires first.
      if (typeof c.emptyCount === 'number' && c.emptyCount > 0) {
        toast(`${c.emptyCount} empty artifact(s) filtered — see Empty_Artifacts.txt`);
      }
      // Auto-expand the first host & open its Overview page. Landing on
      // a per-host overview gives the analyst context before they dive
      // into a specific artifact.
      if (state.hosts.length) {
        const first = state.hosts[0];
        state.expandedHosts.add(first.id);
        openTab({
          kind: 'host-overview',
          hostId: first.id,
          artifactId: '',
          label: `${first.name} · Overview`,
        });
        return; // render() called by openTab
      }
    } else {
      // server reports no case open — reset display state too
      state.caseInfo = null;
      state.caseDir = '';
      state.hosts = [];
      state.marks = [];
    }
  } catch (e) {
    console.error(e);
    toast('failed to load case: ' + e.message, true);
  }
  render();
}

// ---------------------- render: top-level shell ----------------------

function render() {
  const root = document.getElementById('root');

  // Capture focus + selection state so re-render doesn't yank the cursor
  // out of whatever input the user is typing in.
  let restoreKey = null;
  let restorePos = null;
  const focused = document.activeElement;
  if (focused && focused.dataset && focused.dataset.focusKey) {
    restoreKey = focused.dataset.focusKey;
    if (focused.selectionStart != null) {
      restorePos = [focused.selectionStart, focused.selectionEnd];
    }
  }

  // Capture the artifact table's scroll position. A full render() tears
  // down and rebuilds the .table-scroll element, which would otherwise
  // reset scrollTop/scrollLeft to 0 -- jarring when the user clicks a row
  // partway down (or scrolled horizontally into wider columns). We stash
  // both axes here and restore after the rebuild, but ONLY when the
  // rebuilt table is for the same tab (otherwise opening a different
  // artifact would inherit the old one's scroll offset).
  let restoreScrollTop = null;
  let restoreScrollLeft = null;
  let restoreScrollTab = null;
  const prevScroll = document.querySelector('.table-scroll');
  if (prevScroll) {
    restoreScrollTop = prevScroll.scrollTop;
    restoreScrollLeft = prevScroll.scrollLeft;
    restoreScrollTab = prevScroll.dataset.tabKey || null;
  }

  // Same dance for the timeline view's scroll container. Deleting a mark,
  // expanding/collapsing event details, or toggling severity chips all
  // re-render the timeline and would otherwise snap the user back to the
  // top of a long marks list. Tab-key matching ensures we don't apply a
  // global timeline's scroll position to a host timeline (or vice versa).
  let restoreTlScrollTop = null;
  let restoreTlScrollTab = null;
  const prevTl = document.querySelector('.tl-body');
  if (prevTl) {
    restoreTlScrollTop = prevTl.scrollTop;
    restoreTlScrollTab = prevTl.dataset.tabKey || null;
  }

  // Same for the correlation tab's body. Toggling artifact-filter chips
  // would otherwise jump the analyst back to the top of a long event
  // window.
  let restoreCorrScrollTop = null;
  let restoreCorrScrollTab = null;
  const prevCorr = document.querySelector('.corr-body');
  if (prevCorr) {
    restoreCorrScrollTop = prevCorr.scrollTop;
    restoreCorrScrollTab = prevCorr.dataset.tabKey || null;
  }

  root.innerHTML = '';

  const totalMarks = state.marks.length;
  const activeTab = state.activeTab >= 0 ? state.tabs[state.activeTab] : null;

  try {
    const window_ = $('div', { class: 'window' },
      renderTitlebar(activeTab, totalMarks),
      $('div', { class: 'workspace' },
        renderSidebar(),
        renderMain(activeTab),
      ),
      renderStatusbar(activeTab),
    );
    root.appendChild(window_);
  } catch (err) {
    console.error('render failed:', err);
    root.appendChild($('div', {
      style: {
        padding: '24px', fontFamily: 'monospace', color: 'var(--crit, #e34646)',
        background: 'var(--bg, #1e1e1e)', height: '100vh', overflow: 'auto',
      },
    },
      $('h2', null, 'Render error'),
      $('pre', null, (err && err.stack) || String(err)),
      $('p', null, 'Open browser devtools console for full trace. Refresh to retry.'),
    ));
    return;
  }

  // restore focus on whatever input had it
  if (restoreKey) {
    const next = root.querySelector(`[data-focus-key="${restoreKey}"]`);
    if (next) {
      next.focus();
      if (restorePos && next.setSelectionRange) {
        try { next.setSelectionRange(restorePos[0], restorePos[1]); } catch {}
      }
    }
  }

  // Wire up virtualized table scrolling, if an artifact table was rendered.
  // Done after the DOM is attached so clientHeight/scrollTop are real.
  // Pass the captured scroll position so re-rendering the same table
  // (e.g. after clicking a row) keeps the viewport where the user left it.
  mountVirtualTable(restoreScrollTop, restoreScrollTab, restoreScrollLeft);

  // Restore the timeline body's scroll position if the rebuilt timeline
  // belongs to the same tab. Operations that re-render the timeline
  // (deleting a mark, toggling event details, changing filters) would
  // otherwise snap back to the top of a long list.
  const newTl = document.querySelector('.tl-body');
  if (newTl && restoreTlScrollTab && newTl.dataset.tabKey === restoreTlScrollTab) {
    newTl.scrollTop = restoreTlScrollTop;
  }

  // Same for the correlation tab body.
  const newCorr = document.querySelector('.corr-body');
  if (newCorr && restoreCorrScrollTab && newCorr.dataset.tabKey === restoreCorrScrollTab) {
    newCorr.scrollTop = restoreCorrScrollTop;
  }
}

function renderTitlebar(activeTab, totalMarks) {
  const themeName = (THEMES.find(t => t.id === state.theme) || {}).name || state.theme;
  const hostName = activeTab && activeTab.hostId
    ? (state.hosts.find(h => h.id === activeTab.hostId) || {}).name || ''
    : '—';
  return $('div', { class: 'titlebar' },
    $('div', { class: 'traffic' },
      $('span', { class: 'dot r' }),
      $('span', { class: 'dot y' }),
      $('span', { class: 'dot g' }),
    ),
    $('span', { class: 'title' },
      `Douglas · ${hostName}`),
    $('span', { class: 'grow' }),
    $('span', { class: 'title', style: { color: 'var(--fg-3)' } },
      state.caseInfo ? `case ${state.caseInfo.id}` : 'no case'),
    $('span', { class: 'title', style: { color: 'var(--fg-3)' } },
      `🚩 ${totalMarks}`),
    $('span', { class: 'title', style: { color: 'var(--fg-3)' } }, themeName),
  );
}

function renderStatusbar(activeTab) {
  const rowCount = (() => {
    if (!activeTab || activeTab.kind !== 'artifact') return '—';
    const key = `${activeTab.hostId}|${activeTab.artifactId}`;
    const art = state.artifactCache[key];
    return art ? art.rowCount.toLocaleString() : '…';
  })();
  const host = activeTab && activeTab.hostId
    ? state.hosts.find(h => h.id === activeTab.hostId) : null;
  const artName = activeTab && activeTab.artifactId
    ? (host ? ((host.artifacts || []).find(a => a.id === activeTab.artifactId) || {}).name : '')
    : '';
  return $('div', { class: 'statusbar' },
    $('span', { class: 'pill' }, $('span', { class: 'dot' }), 'ready'),
    state.caseInfo && $('span', null, `case: ${state.caseInfo.id}`),
    host && $('span', null, `host: ${host.name}`),
    artName && $('span', null, `artifact: ${artName}`),
    $('span', { class: 'grow' }),
    activeTab && activeTab.kind === 'artifact' && $('span', null, `rows: ${rowCount}`),
    $('span', null, (THEMES.find(t => t.id === state.theme) || {}).name || state.theme),
  );
}

// ---------------------- sidebar ----------------------

function renderSidebar() {
  const q = state.searchHost.toLowerCase();
  const visibleHosts = state.hosts.filter(h => {
    if (!q) return true;
    if (h.name.toLowerCase().includes(q)) return true;
    return (h.artifacts || []).some(a => a.name.toLowerCase().includes(q));
  });

  return $('aside', { class: 'sidebar' },
    $('div', { class: 'brand' },
      $('div', { class: 'mark' }, 'D'),
      $('div', null,
        $('span', { class: 'name' }, 'Douglas'),
        $('span', { class: 'ver' }, 'v0.1'),
      ),
    ),
    $('div', { class: 'sb-search' },
      $('span', { class: 'icon' }, '⌕'),
      $('input', {
        type: 'text',
        placeholder: 'Search hosts & artifacts',
        value: state.searchHost,
        'data-focus-key': 'sidebar-search',
        oninput: (e) => { state.searchHost = e.target.value; render(); },
      }),
    ),
    $('div', { class: 'sb-section' }, $('span', null, 'Investigation')),
    $('div', { class: 'sb-tree', style: { flex: '0 0 auto', paddingBottom: '4px' } },
      $('div', {
        class: 'art-row' + (
          state.activeTab >= 0 &&
          state.tabs[state.activeTab].kind === 'global-timeline' ? ' active' : ''),
        onclick: () => openTab({
          kind: 'global-timeline', hostId: '', artifactId: '',
          label: 'Global Timeline',
        }),
      },
        $('span', { class: 'ico' }, '🌐'),
        $('span', { class: 'label' }, 'Global Timeline'),
        $('span', { class: 'count' }, String(state.marks.length)),
      ),
    ),
    $('div', { class: 'sb-section' },
      $('span', null, `Hosts (${state.hosts.length})`),
      $('span', { class: 'actions' },
        $('button', { title: 'import case', onclick: () => openImportModal() }, '📂'),
        $('button', { title: 'refresh', onclick: () => bootstrap() }, '↻'),
      ),
    ),
    $('div', { class: 'sb-tree' }, ...visibleHosts.map(renderHostBranch)),
    $('div', { class: 'sb-foot' },
      $('div', { class: 'avatar' }, 'A'),
      $('div', { class: 'who' },
        $('div', { class: 'name' }, 'analyst'),
        $('div', { class: 'sub' }, 'DFIR'),
      ),
      renderThemePicker(),
    ),
  );
}

function renderHostBranch(host) {
  const open = state.expandedHosts.has(host.id);
  const hostMarks = state.marks.filter(m => m.hostId === host.id);
  const activeTab = state.activeTab >= 0 ? state.tabs[state.activeTab] : null;
  const totalRows = (host.artifacts || []).reduce((s, a) => s + (a.rowCount || 0), 0);

  return $('div', { class: 'host' },
    $('div', {
      class: 'host-row' + (open ? ' open' : ''),
      onclick: () => {
        // Toggle expansion AND open the host-overview tab. This makes the
        // host row a real navigational action rather than just a sidebar
        // visibility toggle. The chevron's rotation still indicates
        // expansion state.
        if (open && activeTab && activeTab.kind === 'host-overview' && activeTab.hostId === host.id) {
          // Already showing overview for this host -- collapse without
          // changing the tab. Lets the analyst tidy the sidebar.
          state.expandedHosts.delete(host.id);
          render();
          return;
        }
        state.expandedHosts.add(host.id);
        openTab({
          kind: 'host-overview', hostId: host.id, artifactId: '',
          label: `${host.name} · Overview`,
        });
      },
    },
      $('span', { class: 'chev' }, '▸'),
      $('div', { class: 'host-avatar' }, (host.name || '?').slice(0, 2).toUpperCase()),
      $('div', { class: 'host-meta' },
        $('span', { class: 'host-name' }, host.name),
        $('span', { class: 'host-sub' },
          [host.role, host.ip].filter(Boolean).join(' · ') || host.fqdn || `${totalRows.toLocaleString()} rows`),
      ),
      $('span', { class: 'host-tag ' + (host.tag === 'DC' ? 'dc' : 'ws') }, host.tag || 'WS'),
    ),
    open && $('div', { class: 'art-list' },
      // per-host overview pseudo-entry (host KPIs + artifact tiles)
      $('div', {
        class: 'art-row' + (
          activeTab && activeTab.kind === 'host-overview' && activeTab.hostId === host.id
            ? ' active' : ''),
        onclick: () => openTab({
          kind: 'host-overview', hostId: host.id, artifactId: '',
          label: `${host.name} · Overview`,
        }),
      },
        $('span', { class: 'ico' }, '📊'),
        $('span', { class: 'label' }, 'Overview'),
        $('span', { class: 'count' }, String((host.artifacts || []).length)),
      ),
      // per-host timeline pseudo-entry
      $('div', {
        class: 'art-row' + (
          activeTab && activeTab.kind === 'host-timeline' && activeTab.hostId === host.id
            ? ' active' : ''),
        onclick: () => openTab({
          kind: 'host-timeline', hostId: host.id, artifactId: '',
          label: `${host.name} · Timeline`,
        }),
      },
        $('span', { class: 'ico' }, '⏱'),
        $('span', { class: 'label' }, 'Timeline'),
        $('span', { class: 'count' }, String(hostMarks.length)),
      ),
      ...(host.artifacts || []).map(a => $('div', {
        class: 'art-row' + (
          activeTab && activeTab.kind === 'artifact' &&
          activeTab.hostId === host.id && activeTab.artifactId === a.id
            ? ' active' : ''),
        onclick: () => openTab({
          kind: 'artifact', hostId: host.id, artifactId: a.id,
          label: `${host.name} · ${a.name}`,
        }),
      },
        $('span', { class: 'ico' }, a.icon || '·'),
        $('span', { class: 'label' }, a.name),
        a.alertCount > 0 && $('span', { class: 'dot-sev' }),
        $('span', { class: 'count' }, (a.rowCount || 0).toLocaleString()),
      )),
    ),
  );
}

function renderThemePicker() {
  let open = false;
  const wrap = $('div', { class: 'theme-picker' });
  const button = $('button', {
    class: 'icon-btn',
    title: 'Theme',
    onclick: (e) => {
      e.stopPropagation();
      open = !open;
      menu.style.display = open ? 'block' : 'none';
    },
  }, '🎨');
  const menu = $('div', { class: 'theme-menu', style: { display: 'none', bottom: '100%', right: '0', top: 'auto' } },
    ...THEMES.map(t => $('div', {
      class: 'opt' + (t.id === state.theme ? ' active' : ''),
      onclick: () => {
        state.theme = t.id;
        saveTheme(t.id);
        applyTheme(t.id);
        open = false;
        menu.style.display = 'none';
        render();
      },
    },
      $('span', { class: 'swatch' },
        // Build a tiny preview - we don't have direct access to the theme's
        // colors from JS here, so we just show the accent.
        $('i', { style: { background: 'var(--accent)' } }),
        $('i', { style: { background: 'var(--bg-1)' } }),
        $('i', { style: { background: 'var(--bg-2)' } }),
      ),
      $('div', { style: { flex: 1 } },
        $('div', null, t.name),
        $('div', { style: { fontSize: '10px', color: 'var(--fg-3)' } }, t.desc),
      ),
    )),
  );
  wrap.appendChild(button);
  wrap.appendChild(menu);
  // close on outside click
  setTimeout(() => {
    document.addEventListener('click', () => {
      if (open) { open = false; menu.style.display = 'none'; }
    }, { once: true });
  }, 0);
  return wrap;
}

// ---------------------- main panel ----------------------

function renderMain(activeTab) {
  if (!state.caseInfo) {
    return $('main', { class: 'main' }, renderWelcome());
  }
  return $('main', { class: 'main' },
    renderTabBar(),
    activeTab
      ? renderTabBody(activeTab)
      : renderEmpty('No tab open', 'Click a host or artifact in the sidebar to begin.'),
  );
}

function renderWelcome() {
  const recent = loadRecent();
  return $('div', { class: 'welcome' },
    $('div', { class: 'welcome-card' },
      $('h2', null, 'Open a case to begin'),
      $('p', null,
        'Douglas reads a folder containing one subdirectory per host. ' +
        'Each host directory should contain the EZ Tools / Hayabusa CSVs to review.',
      ),
      $('div', { class: 'row' },
        $('button', {
          class: 'btn primary',
          onclick: () => openImportModal(),
        }, '📂 Import case folder'),
        recent.length > 0 && $('button', {
          class: 'btn',
          onclick: () => openImportModal(),
        }, `${recent.length} recent`),
      ),
      $('p', { class: 'hint' },
        'Tip: you can also pass --case <path> on the command line at launch.'),
    ),
  );
}

function renderEmpty(title, sub) {
  return $('div', { class: 'empty' },
    $('div', { class: 'e-inner' },
      $('div', { class: 'e-icon' }, '◌'),
      $('h3', null, title),
      $('p', null, sub),
    ),
  );
}

function renderTabBar() {
  return $('div', { class: 'art-tabs' },
    ...state.tabs.map((t, i) => {
      const isActive = i === state.activeTab;
      return $('button', {
        class: 'art-tab' + (isActive ? ' active' : ''),
        onclick: () => { state.activeTab = i; render(); },
      },
        $('span', null, tabIcon(t)),
        $('span', null, t.label),
        $('span', {
          class: 'x',
          onclick: (e) => { e.stopPropagation(); closeTab(i); },
        }, '✕'),
      );
    }),
  );
}

function tabIcon(t) {
  if (t.kind === 'global-timeline') return '🌐';
  if (t.kind === 'host-timeline') return '⏱';
  if (t.kind === 'host-overview') return '📊';
  if (t.kind === 'correlation') return '🔗';
  const host = state.hosts.find(h => h.id === t.hostId);
  const art = host && (host.artifacts || []).find(a => a.id === t.artifactId);
  return (art && art.icon) || '·';
}

function renderTabBody(tab) {
  if (tab.kind === 'artifact') return renderArtifactTab(tab);
  if (tab.kind === 'host-timeline') return renderTimeline(tab.hostId);
  if (tab.kind === 'global-timeline') return renderTimeline('');
  if (tab.kind === 'host-overview') return renderHostOverview(tab.hostId);
  if (tab.kind === 'correlation') return renderCorrelation(tab);
  return renderEmpty('Unknown tab', '');
}

// ---------------------- artifact view ----------------------

// parseColumnFilter compiles a column filter expression into a predicate
// matchValue(string) -> bool. Supported syntax:
//
//   1102               match value exactly (digits only) OR substring (text)
//   1102,4624          OR-match: row passes if value matches any token
//   !1102              NOT: row passes if value does NOT match this token
//   !1102,!4625        Multiple negations: row must not match ANY of them
//   "powershell exe"   Quoted literal substring (lets you include spaces/commas)
//   >=2026-03-01       Comparison: numeric on numeric values, lexicographic
//   <100               on strings (which is correct for ISO-formatted dates).
//   <=2025-12-31       Operators: > >= < <= = (= is explicit equality)
//
// Mixed: "4624,!4625" means "(=4624) OR (!=4625)" -- effectively "anything
// except 4625, plus also 4624" which simplifies to "not 4625". That's a
// weird case; we OR positives and AND negatives separately, which matches
// what an analyst expects: positives broaden, negatives narrow.
//
// Numeric tokens (all-digit) match exactly. Text tokens match case-
// insensitive substring. This rule lets analysts type EventIDs without
// special syntax: "1102" won't match 11020 or 41102.
function parseColumnFilter(expr) {
  if (!expr) return null;
  // Tokenize on commas, respecting quotes. We don't do nested escaping --
  // this is a search box, not a parser. Empty tokens are skipped.
  const tokens = [];
  let cur = '';
  let inQuote = false;
  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i];
    if (ch === '"') { inQuote = !inQuote; continue; }
    if (ch === ',' && !inQuote) {
      if (cur.trim()) tokens.push(cur.trim());
      cur = '';
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) tokens.push(cur.trim());
  if (tokens.length === 0) return null;

  const positives = [];
  const negatives = [];
  for (const t of tokens) {
    if (t.startsWith('!')) negatives.push(t.slice(1).trim());
    else positives.push(t);
  }

  // Parse a comparison-operator prefix off a token. Returns
  // { op, operand } where op is one of '>=' '<=' '>' '<' '=' or null.
  // Two-char operators are checked first so '>=' doesn't get split into '>'.
  const splitCmp = (token) => {
    for (const op of ['>=', '<=', '>', '<', '=']) {
      if (token.startsWith(op)) {
        return { op, operand: token.slice(op.length).trim() };
      }
    }
    return { op: null, operand: token };
  };

  // Decide whether two strings should be compared numerically. Both must
  // look like numbers; otherwise we fall back to lexicographic, which is
  // also what an analyst wants for ISO dates ("2026-03-01" < "2026-03-15").
  const cmpValues = (a, b) => {
    const na = Number(a), nb = Number(b);
    if (a !== '' && b !== '' && !isNaN(na) && !isNaN(nb)) {
      return na - nb;
    }
    return String(a).localeCompare(String(b));
  };

  const tokenMatches = (token, valueStr) => {
    if (!token) return false;
    const { op, operand } = splitCmp(token);
    if (op) {
      if (!operand) return false;
      const c = cmpValues(valueStr.trim(), operand);
      if (op === '=')  return c === 0;
      if (op === '>')  return c > 0;
      if (op === '>=') return c >= 0;
      if (op === '<')  return c < 0;
      if (op === '<=') return c <= 0;
    }
    // No operator: numeric tokens get exact equality, text tokens get
    // case-insensitive substring. This is the rule that makes "1102"
    // not match "11020".
    if (/^-?\d+$/.test(token)) {
      const trimmed = valueStr.trim();
      if (/^-?\d+$/.test(trimmed)) {
        return Number(trimmed) === Number(token);
      }
      return trimmed === token;
    }
    return valueStr.toLowerCase().includes(token.toLowerCase());
  };

  return (value) => {
    const v = value == null ? '' : String(value);
    // Positives: row passes the positives test if ANY positive matches
    // (OR semantics). If there are no positives, the test is satisfied.
    const positivesPass = positives.length === 0
      ? true
      : positives.some(t => tokenMatches(t, v));
    if (!positivesPass) return false;
    // Negatives: row must NOT match any negative (AND semantics).
    for (const t of negatives) {
      if (tokenMatches(t, v)) return false;
    }
    return true;
  };
}

// parseGlobalQuery compiles a search-bar expression into a row-level
// predicate (row -> bool). The bar accepts:
//
//   powershell                   bare text: substring across ALL values
//   EventID:4624                 field-prefixed: same expr syntax as
//                                column inputs (uses parseColumnFilter)
//   EventID:4624,4625            OR-tokens inside the column expression
//   EventID:!4625                negation inside the column expression
//   EventID:>=1000               comparison inside the column expression
//   Date:>=2026-03-01            ISO dates work via lexicographic compare
//   EventID:4624 Path:system32   multiple predicates: AND'd (whitespace-sep)
//   EventID:4624 OR EventID:1102 explicit OR between adjacent predicates
//
// Field names are matched case-insensitive against column.key OR column.label
// (with non-alphanumeric chars stripped from the label, so "Event ID" matches
// "EventID"). Unknown fields are returned in `unknownFields` so the UI can
// hint at typos.
//
// Returns { predicate, unknownFields, isEmpty } where predicate accepts a
// row object and returns true/false. If the query is empty or only whitespace,
// isEmpty is true and predicate accepts everything.
function parseGlobalQuery(expr, columns) {
  const result = { predicate: () => true, unknownFields: [], isEmpty: true };
  if (!expr || !expr.trim()) return result;

  // Build a normalized lookup: lowercased field-token -> column.key.
  // Strip non-alphanumerics from labels so "Event ID" -> "eventid".
  const normalize = (s) => String(s).toLowerCase().replace(/[^a-z0-9]/g, '');
  const fieldMap = {};
  for (const c of columns) {
    fieldMap[normalize(c.key)] = c.key;
    if (c.label) fieldMap[normalize(c.label)] = c.key;
  }

  // Tokenize the query into predicates. A predicate is a run of non-space
  // chars (respecting quotes), OR the literal "OR" between two predicates.
  // We walk character-by-character so we don't split inside quoted strings.
  const rawTokens = [];
  let cur = '';
  let inQuote = false;
  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i];
    if (ch === '"') { cur += ch; inQuote = !inQuote; continue; }
    if (!inQuote && /\s/.test(ch)) {
      if (cur) { rawTokens.push(cur); cur = ''; }
      continue;
    }
    cur += ch;
  }
  if (cur) rawTokens.push(cur);
  if (rawTokens.length === 0) return result;

  // Now group tokens into AND-groups separated by OR. We accept "OR" or
  // "or" or "||" as the OR keyword.
  const isOr = (t) => t === 'OR' || t === 'or' || t === '||';
  const groups = [[]];   // groups[i] is an AND-list of predicates
  for (const t of rawTokens) {
    if (isOr(t)) {
      if (groups[groups.length - 1].length === 0) continue; // ignore leading OR
      groups.push([]);
      continue;
    }
    groups[groups.length - 1].push(t);
  }
  // Drop a trailing-empty OR group.
  while (groups.length && groups[groups.length - 1].length === 0) groups.pop();
  if (groups.length === 0) return result;

  // Compile each predicate token into a row-predicate.
  // Returns { fn(row) -> bool, unknown: bool, fieldKey: string | null }
  const unknownFields = [];
  const compileToken = (tok) => {
    // Find the FIRST unquoted colon. Everything before is the field,
    // everything after is the expression. If no colon, it's bare text.
    let colonIdx = -1;
    let q = false;
    for (let i = 0; i < tok.length; i++) {
      const ch = tok[i];
      if (ch === '"') { q = !q; continue; }
      if (ch === ':' && !q) { colonIdx = i; break; }
    }
    if (colonIdx < 0) {
      // Bare text: substring match across all values in the row.
      // Strip surrounding quotes if the whole token is quoted.
      let needle = tok;
      if (needle.startsWith('"') && needle.endsWith('"') && needle.length > 1) {
        needle = needle.slice(1, -1);
      }
      const lc = needle.toLowerCase();
      return {
        fn: (row) => Object.values(row).some(v => String(v).toLowerCase().includes(lc)),
        unknown: false,
      };
    }

    const fieldName = tok.slice(0, colonIdx).trim();
    let exprPart = tok.slice(colonIdx + 1);
    // Strip surrounding quotes on the expression part too (e.g. EventID:"4624,4625"
    // -- unusual, but keep symmetric with bare text handling).
    if (exprPart.startsWith('"') && exprPart.endsWith('"') && exprPart.length > 1) {
      exprPart = exprPart.slice(1, -1);
    }
    const colKey = fieldMap[normalize(fieldName)];
    if (!colKey) {
      // Unknown field: record it, but don't kill the whole query --
      // turn this predicate into a no-op (always-true) so the rest works.
      unknownFields.push(fieldName);
      return { fn: () => true, unknown: true };
    }
    const colPred = parseColumnFilter(exprPart);
    if (!colPred) return { fn: () => true, unknown: false };
    return {
      fn: (row) => colPred(row[colKey]),
      unknown: false,
      fieldKey: colKey,
    };
  };

  // Build the final predicate: OR over groups, AND within each group.
  const groupPreds = groups.map(g => g.map(compileToken));
  const predicate = (row) => {
    for (const group of groupPreds) {
      let allMatch = true;
      for (const p of group) {
        if (!p.fn(row)) { allMatch = false; break; }
      }
      if (allMatch) return true;
    }
    return false;
  };

  return {
    predicate,
    unknownFields: [...new Set(unknownFields)],
    isEmpty: false,
  };
}


function renderArtifactTab(tab) {
  const key = `${tab.hostId}|${tab.artifactId}`;
  const art = state.artifactCache[key];
  const host = state.hosts.find(h => h.id === tab.hostId);

  if (!art) {
    // kick off load
    api.artifact(tab.hostId, tab.artifactId).then(a => {
      state.artifactCache[key] = a;
      render();
    }).catch(e => toast('load failed: ' + e.message, true));
    return $('div', { class: 'empty' },
      $('div', { class: 'e-inner' },
        $('div', { class: 'e-icon' }, '⟳'),
        $('h3', null, 'Loading…'),
        $('p', null, `Parsing ${tab.artifactId} for ${tab.hostId}`),
      ),
    );
  }

  const ui = getTabState(state.activeTab);

  // Defensive defaults: an artifact with zero parsed rows comes back from
  // the server with rows=null in JSON (Go nil-slice serialization quirk).
  // Normalize on the cached object so every downstream renderer sees
  // arrays. Also coerce rowCount in case it's missing.
  if (!Array.isArray(art.rows))    art.rows = [];
  if (!Array.isArray(art.columns)) art.columns = [];
  if (typeof art.rowCount !== 'number') art.rowCount = art.rows.length;

  // apply filter chain
  let rows = art.rows.map((r, idx) => ({ r, idx }));

  // Global search bar: parse as a query expression. Bare text in the
  // bar still does the "match anywhere" thing analysts expect, but a
  // Field:expr predicate scopes to that column with the same syntax the
  // per-column inputs use (commas for OR, ! for NOT, >= for compare).
  // Whitespace between predicates means AND; the literal "OR" means OR.
  // Unknown field names are remembered for the UI hint.
  const queryResult = parseGlobalQuery(ui.filter, art.columns);
  ui._queryUnknownFields = queryResult.unknownFields;
  if (!queryResult.isEmpty) {
    rows = rows.filter(({ r }) => queryResult.predicate(r));
  }

  // Per-column filters: compile each non-empty column expression to a
  // predicate, then keep rows where EVERY active column filter passes
  // (AND across columns). Within one column expression, comma-separated
  // tokens are OR'd; ! tokens are negated. See parseColumnFilter.
  const colFilters = ui.colFilters || {};
  const activeColPreds = [];
  for (const c of art.columns) {
    const expr = colFilters[c.key];
    if (!expr) continue;
    const pred = parseColumnFilter(expr);
    if (pred) activeColPreds.push({ key: c.key, pred });
  }
  if (activeColPreds.length > 0) {
    rows = rows.filter(({ r }) => {
      for (const { key, pred } of activeColPreds) {
        if (!pred(r[key])) return false;
      }
      return true;
    });
  }

  if (ui.severities.size > 0) {
    rows = rows.filter(({ r }) => ui.severities.has(deriveSeverity(art.id, r)));
  }
  if (ui.markedOnly) {
    rows = rows.filter(({ r }) =>
      findMark(tab.hostId, tab.artifactId, rowKeyOf(r))
    );
  }
  if (ui.sortKey) {
    const dir = ui.sortDir === 'asc' ? 1 : -1;
    rows.sort((a, b) => {
      const av = a.r[ui.sortKey] || '';
      const bv = b.r[ui.sortKey] || '';
      const na = Number(av), nb = Number(bv);
      if (!isNaN(na) && !isNaN(nb) && av !== '' && bv !== '') return (na - nb) * dir;
      return String(av).localeCompare(String(bv)) * dir;
    });
  }

  // clamp selection
  if (ui.selectedRow >= rows.length) ui.selectedRow = rows.length - 1;
  if (ui.selectedRow < 0 && rows.length > 0) ui.selectedRow = 0;

  // Note: artifacts with zero rows are filtered out server-side during
  // discovery (see ingest.discoverHost) and reported in the case's
  // Empty_Artifacts.txt file. So this code path is unreachable from the
  // sidebar — but a stale tab from a prior session pointing at a now-empty
  // artifact would still land here. Guard with a tiny inline message just
  // in case, rather than crashing later in renderTable.
  if (art.rows.length === 0) {
    return $('div', { class: 'main', style: { display: 'contents' } },
      renderBreadcrumb(host, art, rows),
      $('div', { class: 'empty' },
        $('div', { class: 'e-inner' },
          $('div', { class: 'e-icon' }, '∅'),
          $('h3', null, 'Artifact is empty'),
          $('p', null,
            'See Empty_Artifacts.txt at the case root for details.'),
        ),
      ),
    );
  }

  // Stable key identifying which tab this scroll container belongs to,
  // so render() only restores scrollTop when rebuilding the same table.
  const tabKey = `${tab.kind}|${tab.hostId}|${tab.artifactId}`;
  const drawerH = loadDrawerHeight();
  return $('div', { class: 'main', style: { display: 'contents' } },
    renderBreadcrumb(host, art, rows),
    renderFilterBar(art, ui, rows.length),
    $('div', { class: 'table-wrap' },
      $('div', { class: 'table-scroll', 'data-tab-key': tabKey },
        renderTable(art, rows, ui, tab)),
      // Divider between table and drawer. Drag to resize the drawer.
      // When the drawer is closed the divider is hidden via CSS.
      $('div', {
        class: 'drawer-divider',
        title: 'drag to resize the detail drawer',
        onmousedown: beginDrawerResize,
      }),
      renderDrawer(art, rows, ui, tab, drawerH),
    ),
  );
}

function renderBreadcrumb(host, art, rows) {
  return $('div', { class: 'toolbar' },
    $('div', { class: 'crumbs' },
      $('span', { class: 'host link', onclick: () => openTab({
        kind: 'host-timeline', hostId: host.id, artifactId: '',
        label: `${host.name} · Timeline`,
      }) }, host.name),
      $('span', { class: 'sep' }, '/'),
      $('span', { class: 'cur' }, art.name),
    ),
    $('span', { class: 'tb-spacer' }),
    $('button', { class: 'btn' }, '🔖 Bookmark'),
    $('button', { class: 'btn' }, '📝 Note'),
    $('button', {
      class: 'btn',
      onclick: () => openExportPicker(art, host, rows),
    }, '⤓ Export'),
  );
}

function renderFilterBar(art, ui, visibleCount) {
  const updateFilter = debounce((v) => { ui.filter = v; render(); }, 150);
  const sevChips = ['crit', 'high', 'med', 'low', 'info'].map(s =>
    $('button', {
      class: 'chip' + (ui.severities.has(s) ? ' on' : ''),
      onclick: () => {
        if (ui.severities.has(s)) ui.severities.delete(s);
        else ui.severities.add(s);
        render();
      },
    },
      $('span', { class: 'sev-dot ' + s }),
      s.toUpperCase(),
    )
  );
  // Count of active per-column filters so we can show a clear chip only
  // when there's something to clear. ui.colFilters may be undefined on
  // very first render before getTabState initializes it.
  const activeColFilterCount = ui.colFilters
    ? Object.values(ui.colFilters).filter(v => v && v.length > 0).length
    : 0;

  // Unknown fields surfaced by the global query parser, if any. We show
  // them as a warning chip so analysts catch typos like "EvenID:4624"
  // without staring at empty results wondering what's wrong.
  const unknownFields = ui._queryUnknownFields || [];

  // Build a placeholder/tooltip hint using actual column labels from the
  // current artifact. The first non-timestamp column gives us a sensible
  // example field for the placeholder; the tooltip lists the first few
  // labels so analysts can see at a glance which names are valid.
  const labels = (art.columns || []).map(c => c.label).filter(Boolean);
  const sampleLabel = labels.find(l => !/time|date/i.test(l)) || labels[0] || 'Field';
  const labelHint = labels.slice(0, 6).join(', ') + (labels.length > 6 ? ', ...' : '');

  return $('div', { class: 'filter-bar' },
    $('div', { class: 'search-input' },
      $('span', { class: 'ico' }, '⌕'),
      $('input', {
        type: 'text',
        placeholder: `search ${art.name} (try ${sampleLabel}:value)`,
        title:
          'Search syntax (field names come from the column headers):\n' +
          '  ' + labelHint + '\n\n' +
          '  powershell                    bare text, matches anywhere\n' +
          `  ${sampleLabel}:4624                  field-scoped match\n` +
          `  ${sampleLabel}:4624,1102             OR within a column (comma)\n` +
          `  ${sampleLabel}:!4625                 NOT\n` +
          '  Size:>=1024                   comparisons (>, >=, <, <=, =)\n' +
          '  TimeCreated:>=2026-03-01      ISO dates work too\n' +
          `  ${sampleLabel}:4624 Path:system32    multiple predicates = AND\n` +
          `  ${sampleLabel}:4624 OR ${sampleLabel}:1102  explicit OR`,
        value: ui.filter,
        'data-focus-key': `art-filter-${state.activeTab}`,
        oninput: (e) => updateFilter(e.target.value),
      }),
      $('kbd', null, '⌘F'),
    ),
    art.id === 'hayabusa' && sevChips,
    $('button', {
      class: 'chip' + (ui.markedOnly ? ' on' : ''),
      onclick: () => { ui.markedOnly = !ui.markedOnly; render(); },
    }, '🚩', 'Marked only'),
    activeColFilterCount > 0 && $('button', {
      class: 'chip on',
      title: 'Clear all per-column filters',
      onclick: () => {
        ui.colFilters = {};
        ui.selectedRow = -1;
        render();
      },
    }, '✕ ', `${activeColFilterCount} column filter${activeColFilterCount === 1 ? '' : 's'}`),
    unknownFields.length > 0 && $('button', {
      class: 'chip warn',
      title: 'These field names in your query don\'t match any column.\nClick to clear the search.',
      onclick: () => { ui.filter = ''; render(); },
    }, '⚠ unknown field' + (unknownFields.length > 1 ? 's' : '') + ': ' + unknownFields.join(', ')),
    $('span', { class: 'tb-spacer' }),
    $('span', { style: { fontSize: '11px', color: 'var(--fg-3)' } },
      `${visibleCount.toLocaleString()} of ${art.rowCount.toLocaleString()}`),
    $('button', { class: 'icon-btn', title: 'columns' }, '⋮'),
    $('button', { class: 'icon-btn', title: 'sort' }, '⇅'),
  );
}

// Fixed row height in px. Must match .artifact-table tbody tr height in
// CSS -- the virtualization math depends on every row being this tall.
const ROW_H = 29;
// How many extra rows to render above/below the visible window, so fast
// scrolling doesn't flash blank space before the next repaint.
const ROW_BUFFER = 12;

function renderTable(art, rows, ui, tab) {
  const setSort = (k) => {
    if (ui.sortKey === k) ui.sortDir = ui.sortDir === 'asc' ? 'desc' : 'asc';
    else { ui.sortKey = k; ui.sortDir = 'asc'; }
    render();
  };

  // Per-artifact width overrides come from localStorage. Read once per
  // render so resizes from earlier sessions take effect; in-session
  // resizes mutate th.style.width directly and write back to storage
  // on mouseup, so they survive without a full re-render.
  const widthOverrides = loadColWidths(art.id);

  const tbody = $('tbody', { class: 'virt-body' });

  // Debounced filter updater shared by all per-column inputs.
  const updateColFilter = debounce((key, value) => {
    if (!ui.colFilters) ui.colFilters = {};
    if (value) ui.colFilters[key] = value;
    else delete ui.colFilters[key];
    // Reset selection so we don't end up on a now-hidden row.
    ui.selectedRow = -1;
    render();
  }, 200);

  // Build a header <th> for one column. The cell contains the column
  // label (click to sort), a small funnel toggle on the right that
  // expands/collapses the column's filter input, and -- when expanded --
  // the input itself directly below. The resize grip is the rightmost
  // 6px of the cell and overlays the toggle's right edge harmlessly.
  //
  // Putting the filter input INSIDE the th instead of a separate sticky
  // row means the input scrolls with the header (the thead is sticky) and
  // never overlaps data rows. Open/close state persists on ui.openFilterCols
  // so it survives sort/filter re-renders.
  const buildTh = (c) => {
    const w = effectiveColWidth(art.id, c, widthOverrides);
    const isOpen = ui.openFilterCols && ui.openFilterCols.has(c.key);
    const current = (ui.colFilters && ui.colFilters[c.key]) || '';
    const hasActive = current.length > 0;
    const focusKey = `colfilter-${state.activeTab}-${c.key}`;

    const th = $('th', {
      class: (isOpen ? 'filter-open' : '') + (hasActive ? ' filter-active' : ''),
      style: { width: w + 'px' },
      onclick: () => setSort(c.key),
    },
      // Label + sort indicator + funnel toggle live on a single flex row.
      $('div', { class: 'th-inner' },
        $('span', { class: 'th-label' }, c.label),
        ui.sortKey === c.key && $('span', { class: 'sort' }, ui.sortDir === 'asc' ? '▲' : '▼'),
        $('span', { class: 'th-spacer' }),
        // Funnel toggle. We mark active filters with a filled funnel so
        // analysts see at a glance which columns are filtering.
        $('span', {
          class: 'col-filter-toggle' + (isOpen ? ' open' : '') + (hasActive ? ' active' : ''),
          title: isOpen ? 'hide filter' : (hasActive ? 'filter is active -- click to edit' : 'show filter'),
          onclick: (e) => {
            e.stopPropagation();
            if (!ui.openFilterCols) ui.openFilterCols = new Set();
            if (ui.openFilterCols.has(c.key)) ui.openFilterCols.delete(c.key);
            else ui.openFilterCols.add(c.key);
            render();
          },
        }, hasActive ? '▼' : '▽'),
      ),
      // Filter input -- rendered inside the th but only when expanded.
      // The thead is sticky so this scrolls with the header, not the body.
      isOpen && $('input', {
        type: 'text',
        class: 'col-filter-input' + (hasActive ? ' active' : ''),
        placeholder: 'filter',
        value: current,
        title: 'comma=OR, !=NOT, >=N for compare, "..." literal',
        'data-focus-key': focusKey,
        onclick: (e) => e.stopPropagation(),
        // Keydown gives us a way to close the input with Escape without
        // having to click the toggle again.
        onkeydown: (e) => {
          if (e.key === 'Escape') {
            ui.openFilterCols.delete(c.key);
            render();
          }
        },
        oninput: (e) => updateColFilter(c.key, e.target.value),
      }),
      // Resize grip is still on the right edge of the cell.
      $('span', {
        class: 'col-grip',
        title: 'drag to resize column',
        onclick: (e) => e.stopPropagation(),
        onmousedown: (e) => beginColumnResize(e, th, c, art.id),
      }),
    );
    return th;
  };

  const table = $('table', { class: 'artifact-table' },
    $('thead', null,
      $('tr', { class: 'th-row' },
        $('th', { class: 'mark-col' }, ''),
        ...art.columns.map(buildTh),
      ),
    ),
    tbody,
  );

  // Build a single data row <tr>. visibleIdx is the row's position in the
  // (filtered/sorted) rows array -- used for selection + click handlers.
  const buildRow = (entry, visibleIdx) => {
    const { r } = entry;
    const rk = rowKeyOf(r);
    const mark = findMark(tab.hostId, tab.artifactId, rk);
    const isSel = visibleIdx === ui.selectedRow;
    return $('tr', {
      class: 'data-row' + (visibleIdx % 2 === 1 ? ' zebra' : '') +
        (isSel ? ' selected' : '') + (mark ? ' marked' : ''),
      style: { height: ROW_H + 'px' },
      onclick: () => {
        if (ui.selectedRow !== visibleIdx) {
          // Different row -> the cross-artifact pivot result was scoped
          // to the previous row, so wipe it. Otherwise the drawer would
          // confusingly show a panel for a row the user isn't looking at.
          ui.pivotResult = null;
          ui.pivotExpanded = new Set();
          ui.pivotShowAll = new Set();
        }
        ui.selectedRow = visibleIdx;
        render();
      },
    },
      $('td', { class: 'mark-cell' },
        $('span', {
          class: 'mark-btn' + (mark ? ' on' : ''),
          onclick: async (e) => {
            e.stopPropagation();
            await toggleMark(tab.hostId, tab.artifactId, r);
          },
        }, '🚩'),
      ),
      ...art.columns.map(c => renderCell(r, c)),
    );
  };

  // Virtualized fill: given the scroll container, render only the rows in
  // (and near) the viewport. Two spacer <tr>s hold the off-screen height
  // so the scrollbar geometry stays correct.
  const colSpan = art.columns.length + 1;
  const fill = (scroller) => {
    const total = rows.length;
    const scrollTop = scroller.scrollTop;
    const viewH = scroller.clientHeight || 600;

    let first = Math.floor(scrollTop / ROW_H) - ROW_BUFFER;
    let last = Math.ceil((scrollTop + viewH) / ROW_H) + ROW_BUFFER;
    if (first < 0) first = 0;
    if (last > total) last = total;

    const topPad = first * ROW_H;
    const botPad = Math.max(0, (total - last) * ROW_H);

    // Rebuild tbody: spacer + window + spacer.
    tbody.textContent = '';
    if (topPad > 0) {
      tbody.appendChild($('tr', { class: 'virt-spacer', style: { height: topPad + 'px' } },
        $('td', { colspan: colSpan })));
    }
    for (let i = first; i < last; i++) {
      tbody.appendChild(buildRow(rows[i], i));
    }
    if (botPad > 0) {
      tbody.appendChild($('tr', { class: 'virt-spacer', style: { height: botPad + 'px' } },
        $('td', { colspan: colSpan })));
    }
  };

  // Stash the fill fn + row count on the table element so mountVirtualTable
  // (called after the table is in the DOM) can wire up the scroll handler.
  table._virtFill = fill;
  table._virtRowCount = rows.length;
  table._virtSelectedRow = ui.selectedRow;
  return table;
}

// mountVirtualTable wires the scroll handler for a virtualized artifact
// table. Called after render() has attached the DOM, because the math
// needs real clientHeight / scrollTop values.
//
// restoreScrollTop / restoreScrollTab carry the scroll position captured
// before the teardown. When the rebuilt table is the SAME tab, we restore
// that exact offset so clicking a row doesn't jump the viewport. When it's
// a different (or first-opened) tab, we instead scroll the selected row
// into view. restoreScrollLeft is preserved on same-tab too, so horizontal
// scroll position (after dragging columns wider than the viewport) sticks.
function mountVirtualTable(restoreScrollTop, restoreScrollTab, restoreScrollLeft) {
  const scroller = document.querySelector('.table-scroll');
  if (!scroller) return;
  const table = scroller.querySelector('table.artifact-table');
  if (!table || typeof table._virtFill !== 'function') return;

  const fill = table._virtFill;
  const tabKey = scroller.dataset.tabKey || null;
  const sameTab = restoreScrollTab != null && restoreScrollTab === tabKey;

  // First fill at the current scrollTop (0). This builds the spacer rows
  // sized for the FULL dataset, which establishes the real scrollable
  // height -- needed before we can set scrollTop accurately.
  fill(scroller);

  if (sameTab && typeof restoreScrollTop === 'number') {
    // Re-render of the same table -- restore the exact viewport offset.
    // The spacers now exist so the browser won't wrongly clamp this.
    scroller.scrollTop = restoreScrollTop;
    // Also restore horizontal scroll position, so re-renders don't snap
    // back to scrollLeft=0 when the table is wider than the viewport
    // (which happens after dragging columns wider).
    if (typeof restoreScrollLeft === 'number') {
      scroller.scrollLeft = restoreScrollLeft;
    }
  } else {
    // Different / freshly-opened tab: bring the selected row into view.
    const sel = table._virtSelectedRow;
    if (typeof sel === 'number' && sel >= 0) {
      const rowTop = sel * ROW_H;
      const rowBot = rowTop + ROW_H;
      const viewTop = scroller.scrollTop;
      const viewBot = viewTop + scroller.clientHeight;
      if (rowTop < viewTop) scroller.scrollTop = rowTop;
      else if (rowBot > viewBot) scroller.scrollTop = rowBot - scroller.clientHeight;
    }
  }

  // Second fill: now that scrollTop is at its final value, render the
  // correct row window for that position.
  fill(scroller);

  // Repaint on scroll. rAF-throttled so fast scrolling doesn't queue
  // dozens of fills per frame.
  let ticking = false;
  scroller.addEventListener('scroll', () => {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      fill(scroller);
      ticking = false;
    });
  });
}

// beginColumnResize handles a column-grip mousedown. It captures the
// starting x and width, then listens globally for mousemove (to size
// the column live) and mouseup (to commit the new width to localStorage).
// The header click handler is suppressed during the drag so releasing
// the grip doesn't accidentally fire a sort.
function beginColumnResize(ev, th, col, artifactId) {
  ev.preventDefault();
  ev.stopPropagation();
  const startX = ev.clientX;
  const startW = th.getBoundingClientRect().width;
  document.body.classList.add('col-resizing');
  let lastW = startW;

  const onMove = (e) => {
    const w = Math.max(COL_MIN, startW + (e.clientX - startX));
    lastW = w;
    th.style.width = w + 'px';
  };
  const onUp = () => {
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup', onUp);
    document.body.classList.remove('col-resizing');
    // Persist; the next render() pulls this back from localStorage.
    saveColWidth(artifactId, col.key, lastW);
    // With table-layout:fixed, the browser auto-reflows data cells when
    // a th's width changes, so no fill is strictly needed here. We
    // still trigger one as belt-and-braces -- cheap, and ensures any
    // truncation/overflow recalculation lands on the next frame.
    const scroller = document.querySelector('.table-scroll');
    if (scroller) {
      const table = scroller.querySelector('table.artifact-table');
      if (table && typeof table._virtFill === 'function') table._virtFill(scroller);
    }
  };
  document.addEventListener('mousemove', onMove);
  document.addEventListener('mouseup', onUp);
}

// beginDrawerResize handles a divider mousedown between the table and the
// detail drawer. Adjusts the drawer's height live, clamped to a sensible
// range, and persists the chosen height on mouseup.
function beginDrawerResize(ev) {
  ev.preventDefault();
  const wrap = document.querySelector('.table-wrap');
  const drawer = document.querySelector('.detail-drawer');
  if (!wrap || !drawer || drawer.classList.contains('closed')) return;

  const wrapRect = wrap.getBoundingClientRect();
  const startY = ev.clientY;
  const startH = drawer.getBoundingClientRect().height;
  const maxH = wrapRect.height * DRAWER_MAX_RATIO;
  document.body.classList.add('drawer-resizing');
  let lastH = startH;

  const onMove = (e) => {
    // Dragging UP grows the drawer; DOWN shrinks it.
    const dy = startY - e.clientY;
    const h = Math.min(maxH, Math.max(DRAWER_MIN, startH + dy));
    lastH = h;
    drawer.style.height = h + 'px';
  };
  const onUp = () => {
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup', onUp);
    document.body.classList.remove('drawer-resizing');
    saveDrawerHeight(lastH);
    // Trigger a virt re-fill since the scrollable area's clientHeight
    // changed -- different rows are now visible.
    const scroller = document.querySelector('.table-scroll');
    if (scroller) {
      const table = scroller.querySelector('table.artifact-table');
      if (table && typeof table._virtFill === 'function') table._virtFill(scroller);
    }
  };
  document.addEventListener('mousemove', onMove);
  document.addEventListener('mouseup', onUp);
}

function renderCell(row, col) {
  let v = row[col.key];
  if (v == null) v = '';
  let content;
  if (col.bool) {
    const yes = String(v).toLowerCase() === 'true';
    content = $('span', { class: yes ? 'bool-yes' : 'bool-no' }, yes ? '✓' : '·');
  } else if (col.sev) {
    const sev = String(v).toLowerCase();
    content = $('span', { class: 'sev-pill ' + (SEV_RANK[sev] != null ? sev : 'info') },
      v || 'info');
  } else if (col.format === 'bytes') {
    content = fmtBytes(v);
  } else if (col.truncHash) {
    content = truncateHash(v);
  } else {
    content = v;
  }
  return $('td', {
    class: (col.numeric ? 'num ' : '') + (col.mono ? 'mono-cell ' : ''),
    title: typeof content === 'string' ? content : (v || ''),
  }, content);
}

async function toggleMark(hostId, artifactId, row) {
  const rk = rowKeyOf(row);
  const id = markId(hostId, artifactId, rk);
  const existing = state.marks.find(m => m.id === id);
  try {
    if (existing) {
      await api.deleteMark(id);
      state.marks = state.marks.filter(m => m.id !== id);
    } else {
      const m = {
        id,
        hostId,
        artifactId,
        rowKey: rk,
        snapshot: row,
        ts: extractTimestamp(row),
        label: extractLabel(row),
        sev: deriveSeverity(artifactId, row),
        note: '',
        createdAt: new Date().toISOString(),
      };
      const saved = await api.saveMark(m);
      state.marks.push(saved);
    }
    render();
  } catch (e) {
    toast('mark error: ' + e.message, true);
  }
}

// ---------------------- drawer ----------------------

function renderDrawer(art, rows, ui, tab, drawerHeight) {
  const selected = rows[ui.selectedRow];
  if (!selected) return $('div');
  const row = selected.r;
  const rk = rowKeyOf(row);
  const mark = findMark(tab.hostId, tab.artifactId, rk);

  if (!ui.drawerOpen) {
    return $('div', { class: 'detail-drawer closed' },
      $('div', { class: 'detail-head' },
        $('span', null, '👁'),
        $('span', null, 'Row Detail'),
        $('span', { class: 'grow' }),
        $('button', {
          class: 'detail-toggle',
          onclick: () => { ui.drawerOpen = true; render(); },
        }, 'Expand ▲'),
      ),
    );
  }

  // Apply the persisted drawer height inline so the CSS rule (which has a
  // default of 280px) is overridden cleanly. Falls back to default if no
  // value was passed (e.g. legacy call sites).
  const heightStyle = (typeof drawerHeight === 'number' && drawerHeight > 0)
    ? { height: drawerHeight + 'px' }
    : {};
  return $('div', { class: 'detail-drawer', style: heightStyle },
    $('div', { class: 'detail-head' },
      $('span', null, '👁'),
      $('span', null, 'Row Detail'),
      $('span', { class: 'key' }, `row ${ui.selectedRow + 1} of ${rows.length}`),
      $('button', {
        class: 'btn ' + (mark ? 'primary' : ''),
        onclick: () => toggleMark(tab.hostId, tab.artifactId, row),
      }, mark ? '🚩 Marked' : 'Mark suspicious'),
      $('span', { class: 'grow' }),
      $('span', { style: { fontFamily: 'JetBrains Mono, monospace', textTransform: 'none', letterSpacing: 0 } },
        art.sourceFile ? art.sourceFile.split(/[\\/]/).pop() : art.name),
      $('button', {
        class: 'detail-toggle',
        onclick: () => { ui.drawerOpen = false; render(); },
      }, 'Collapse ▼'),
    ),
    $('div', { class: 'detail-col' },
      $('h4', null, 'Fields'),
      mark && renderMarkNoteBox(mark),
      renderRowKV(row, art),
    ),
    $('div', { class: 'detail-col' },
      $('h4', null, `Cross-Artifact Pivots · ${tab.hostId}`),
      renderPivots(row, tab.hostId, tab.artifactId, ui),
    ),
  );
}

function renderMarkNoteBox(mark) {
  return $('div', { class: 'mark-note-box' },
    $('div', { class: 'mark-note-head' }, '🚩 Analyst note'),
    $('textarea', {
      placeholder: 'Why is this suspicious?',
      'data-focus-key': `note-${mark.id}`,
      oninput: debounce(async (e) => {
        mark.note = e.target.value;
        try { await api.saveMark(mark); }
        catch (err) { toast('save note failed: ' + err.message, true); }
      }, 400),
    }, mark.note || ''),
  );
}

function renderRowKV(row, art) {
  const dl = $('dl', { class: 'kv-grid' });
  // Show every schema column first, in declared order, then any extra
  // fields the parser found in the CSV but that aren't in our schema.
  const seen = new Set();
  for (const c of art.columns) {
    const v = row[c.key];
    if (v == null || v === '') continue;
    seen.add(c.key);
    const dd = $('dd', null, c.format === 'bytes' ? fmtBytes(v) : String(v));
    if (c.mono) dd.style.fontFamily = 'JetBrains Mono, monospace';
    if (/Path|FullPath|LocalPath|KeyPath/.test(c.key)) dd.classList.add('path');
    if (/SHA1|Hash/.test(c.key)) dd.classList.add('hash');
    dl.appendChild($('dt', null, c.label));
    dl.appendChild(dd);
  }
  // Collect extras so we can show a separator only when there are some.
  const extras = [];
  for (const [k, v] of Object.entries(row)) {
    if (k.startsWith('__') || seen.has(k) || !v) continue;
    extras.push([k, v]);
  }
  if (extras.length > 0) {
    dl.appendChild($('div', { class: 'kv-group-sep' },
      `Additional fields (${extras.length})`));
    for (const [k, v] of extras) {
      const dd = $('dd', null, String(v));
      if (/Path|FullPath|LocalPath|KeyPath/.test(k)) dd.classList.add('path');
      if (/SHA1|Hash/.test(k)) dd.classList.add('hash');
      dl.appendChild($('dt', null, k));
      dl.appendChild(dd);
    }
  }
  return dl;
}

function renderPivots(row, hostId, currentArtId, ui) {
  // The pivots column has two sections:
  //   1. Pivot buttons -- one per pivotable field (hash/path/filename) in
  //      this row. Clicking loads every artifact on the host, runs the
  //      pivot, and shows match counts per artifact with click-to-jump.
  //   2. Time-window button -- builds a chronological merge of every
  //      row from every artifact within +/- N minutes of this row's
  //      primary timestamp. Opens as a new correlation tab.
  //
  // ui.pivotResult holds the most recent in-place pivot result so it
  // survives the row's drawer re-renders (e.g. when toggling marks).
  // ui.pivotBusy is true while the load + scan is in flight.

  const host = state.hosts.find(h => h.id === hostId);
  if (!host) return $('div');
  const currentArt = state.artifactCache[`${hostId}|${currentArtId}`];
  if (!currentArt) return $('div');

  const pivotFields = pivotFieldsForArtifact(currentArt)
    .map(({ col, kind }) => {
      const raw = row[col.key];
      if (raw == null || raw === '') return null;
      const normalized = normalizePivotValue(kind, raw);
      if (!normalized) return null;
      return { col, kind, raw: String(raw), normalized };
    })
    .filter(Boolean);

  // Primary timestamp for this row (used by the time-window button).
  const primaryTime = currentArt.primaryTime
    ? parseArtifactTime(row[currentArt.primaryTime])
    : null;

  const strip = $('div', { class: 'pivot-strip' });

  // --- pivot buttons ---
  strip.appendChild($('h4', { class: 'pivot-section-head' }, 'Pivot to other artifacts'));

  if (pivotFields.length === 0) {
    strip.appendChild($('div', { class: 'pivot-empty' },
      'No pivot fields (hash / path / filename) in this row.'));
  } else {
    const btnRow = $('div', { class: 'pivot-buttons' });
    for (const pf of pivotFields) {
      const label = pf.col.label || pf.col.key;
      btnRow.appendChild($('button', {
        class: 'pivot-btn',
        title: `Find this ${pf.kind} in other artifacts: ${pf.raw}`,
        disabled: ui.pivotBusy ? 'disabled' : false,
        onclick: async () => {
          ui.pivotBusy = true;
          ui.pivotResult = null;
          render();
          try {
            const loaded = await ensureAllArtifactsLoaded(hostId);
            const result = runPivot(hostId, pf.kind, pf.raw, loaded);
            // Filter out the current artifact -- of course the row
            // matches itself; surface only OTHER artifacts.
            result.byArtifact = result.byArtifact.filter(g => g.artifactId !== currentArtId);
            ui.pivotResult = {
              field: label,
              kind: pf.kind,
              needle: pf.raw,
              groups: result.byArtifact,
            };
          } catch (e) {
            toast('pivot failed: ' + (e.message || e), true);
          } finally {
            ui.pivotBusy = false;
            render();
          }
        },
      },
        $('span', { class: 'pivot-btn-kind' }, pf.kind),
        $('span', { class: 'pivot-btn-label' }, label),
        $('span', { class: 'pivot-btn-val' }, pf.raw.length > 28 ? pf.raw.slice(0, 25) + '...' : pf.raw),
      ));
    }
    strip.appendChild(btnRow);
  }

  // --- pivot result, if any ---
  // Guard against stale results: if the stored result was computed for a
  // value that no longer appears as a pivot field on the currently
  // selected row (e.g. the user filtered the table and a different row
  // got auto-selected), drop the result rather than showing matches
  // unrelated to what the analyst is now looking at.
  if (ui.pivotResult && pivotFields.length > 0) {
    const stillValid = pivotFields.some(pf =>
      pf.kind === ui.pivotResult.kind && pf.raw === ui.pivotResult.needle);
    if (!stillValid) {
      ui.pivotResult = null;
      ui.pivotExpanded = new Set();
      ui.pivotShowAll = new Set();
    }
  }

  if (ui.pivotBusy) {
    strip.appendChild($('div', { class: 'pivot-loading' }, 'Loading artifacts and searching...'));
  } else if (ui.pivotResult) {
    strip.appendChild(renderPivotResult(ui.pivotResult, hostId, ui));
  }

  // --- time-window section ---
  strip.appendChild($('h4', { class: 'pivot-section-head' }, 'Time window'));
  if (!primaryTime) {
    strip.appendChild($('div', { class: 'pivot-empty' },
      currentArt.primaryTime
        ? `No parseable timestamp in this row's ${currentArt.primaryTime} field.`
        : 'This artifact type has no canonical timestamp column.'));
  } else {
    const windowRow = $('div', { class: 'pivot-buttons' });
    for (const m of PIVOT_WINDOWS_MIN) {
      const label = m < 60 ? `\u00b1${m} min` : `\u00b1${m / 60} hr`;
      windowRow.appendChild($('button', {
        class: 'pivot-btn time-btn',
        title: `Show all rows from all artifacts within ${label} of this event`,
        onclick: async () => {
          ui.pivotBusy = true;
          render();
          try {
            const loaded = await ensureAllArtifactsLoaded(hostId);
            const events = runTimeWindow(hostId, primaryTime, m, loaded);
            // Stash the result on a global slot keyed by anchor so a new
            // tab can pick it up. Then open the tab.
            const anchorIso = primaryTime.toISOString();
            const key = `${hostId}|${anchorIso}|${m}`;
            state.correlationCache = state.correlationCache || {};
            state.correlationCache[key] = {
              hostId,
              anchorIso,
              anchorLabel: row[currentArt.primaryTime] || anchorIso,
              windowMin: m,
              sourceArtifactId: currentArtId,
              events,
            };
            openTab({
              kind: 'correlation',
              hostId,
              artifactId: '',
              correlationKey: key,
              label: `${currentArt.icon || ''} ${row[currentArt.primaryTime] || ''} ${label}`.trim(),
            });
          } catch (e) {
            toast('time window failed: ' + (e.message || e), true);
          } finally {
            ui.pivotBusy = false;
            render();
          }
        },
      }, label));
    }
    strip.appendChild(windowRow);
    strip.appendChild($('div', { class: 'pivot-anchor-hint' },
      `Anchored at ${row[currentArt.primaryTime]}`));
  }

  return strip;
}

// rowContextChips returns the array of {label, val} chip data for a row
// based on the artifact's declared ContextFields. Returns [] if the
// artifact has no ContextFields or none of those fields are populated
// in this row. Pure function -- no DOM. Callers wrap the chips in
// whatever surrounding layout they need (pivot result rows, correlation
// events, etc).
function rowContextChips(row, art, truncAt) {
  const TRUNC = truncAt || 120;
  const fields = (art && art.contextFields) || [];
  if (fields.length === 0) return [];
  const chips = [];
  for (const key of fields) {
    const raw = row[key];
    if (raw == null || raw === '') continue;
    let val = String(raw).replace(/\s+/g, ' ').trim();
    if (val.length > TRUNC) val = val.slice(0, TRUNC) + '\u2026';
    // Find the column's friendly label, fall back to the raw key if the
    // column isn't in the artifact's schema (an "extra" CSV field).
    let label = key;
    if (art && art.columns) {
      const col = art.columns.find(c => c.key === key);
      if (col && col.label) label = col.label;
    }
    chips.push({ label, val });
  }
  return chips;
}

// renderContextChips wraps chip data into a DOM span. Used by both the
// pivot result rows and the correlation event view.
function renderContextChips(chips) {
  const box = $('span', { class: 'pivot-row-chips' });
  for (const c of chips) {
    box.appendChild($('span', { class: 'pivot-chip' },
      $('span', { class: 'pivot-chip-k' }, c.label),
      $('span', { class: 'pivot-chip-v' }, c.val),
    ));
  }
  return box;
}

// renderPivotRowPreview renders one row inside a pivot result group with
// just enough context for an analyst to decide whether to drill in.
// Layout: timestamp on the left, then a series of "key=value" chips
// for each ContextField declared on the artifact type. Long values
// (descriptions, payloads, RECmd ValueData) are truncated to ~120 chars.
// If the artifact has no ContextFields declared, we fall back to the
// generic extractLabel for compatibility with any new artifact types
// that haven't been curated yet.
function renderPivotRowPreview(row, art) {
  // Resolve timestamp: prefer the artifact's declared PrimaryTime field,
  // fall back to the generic extractor.
  let ts = '';
  if (art && art.primaryTime && row[art.primaryTime]) {
    ts = String(row[art.primaryTime]);
  } else {
    ts = extractTimestamp(row) || '';
  }
  // Trim sub-second precision down to seconds for compact display --
  // EZ Tools emits 7-digit fractional seconds which is more precision
  // than this preview needs.
  ts = ts.replace(/(\d{2}:\d{2}:\d{2})\.\d+/, '$1');

  const chips = rowContextChips(row, art);

  // Build the row element. Timestamp first, then chips, then a fallback
  // label if no chips materialised (artifact has no declared context or
  // none of those columns had values in this row).
  const el = $('div', { class: 'pivot-row' },
    $('span', { class: 'pivot-row-when' }, ts || '\u2014'),
  );
  if (chips.length > 0) {
    el.appendChild(renderContextChips(chips));
  } else {
    // No context fields hit -- show the generic extractLabel as a
    // last-resort hint of what this row contains.
    el.appendChild($('span', { class: 'pivot-row-what' }, extractLabel(row) || '\u2014'));
  }
  return el;
}

// renderPivotResult shows the result panel for an in-place pivot.
// Per the design choice, this is top-50-with-show-all per artifact group.
// Each group is collapsible; the row count is shown alongside the
// artifact name.
function renderPivotResult(result, hostId, ui) {
  const wrap = $('div', { class: 'pivot-result' });
  wrap.appendChild($('div', { class: 'pivot-result-head' },
    $('span', null, `Matches for `),
    $('span', { class: 'pivot-result-kind' }, result.kind),
    $('span', null, ` `),
    $('span', { class: 'pivot-result-needle' }, result.needle),
    $('span', { class: 'grow' }),
    $('button', {
      class: 'linkbtn',
      onclick: () => { ui.pivotResult = null; render(); },
    }, 'clear'),
  ));

  if (result.groups.length === 0) {
    wrap.appendChild($('div', { class: 'pivot-empty' },
      'No matches in other artifacts on this host.'));
    return wrap;
  }

  ui.pivotExpanded = ui.pivotExpanded || new Set();
  ui.pivotShowAll = ui.pivotShowAll || new Set();

  for (const group of result.groups) {
    const expanded = ui.pivotExpanded.has(group.artifactId);
    const showAll = ui.pivotShowAll.has(group.artifactId);
    const TOP_N = 50;
    const visible = showAll ? group.matches : group.matches.slice(0, TOP_N);
    const overflow = group.matches.length - visible.length;

    const groupEl = $('div', { class: 'pivot-group' });
    groupEl.appendChild($('div', {
      class: 'pivot-group-head',
      onclick: () => {
        if (ui.pivotExpanded.has(group.artifactId)) ui.pivotExpanded.delete(group.artifactId);
        else ui.pivotExpanded.add(group.artifactId);
        render();
      },
    },
      $('span', { class: 'pivot-group-caret' }, expanded ? '\u25BC' : '\u25B6'),
      $('span', { class: 'pivot-group-icon' }, group.icon),
      $('span', { class: 'pivot-group-name' }, group.name),
      $('span', { class: 'pivot-group-count' }, `${group.matches.length} match${group.matches.length === 1 ? '' : 'es'}`),
      $('span', { class: 'grow' }),
      $('button', {
        class: 'linkbtn',
        onclick: (e) => {
          e.stopPropagation();
          // Jump to that artifact with the value pre-filled as a column
          // filter on a compatible pivot field. For hash, only match hash
          // columns. For path/filename, match either (mirrors the
          // interplay in runPivot).
          const targetArt = state.artifactCache[`${hostId}|${group.artifactId}`];
          if (!targetArt) return;
          const compatibleKinds = result.kind === 'hash'
            ? ['hash']
            : ['path', 'filename'];
          // Prefer a column matching the SAME kind as the source, fall
          // back to the cross-kind option. This puts the filter on a
          // FullPath column (when pivoting from a path) instead of a
          // FileName column when both are available.
          const targetCol =
            (targetArt.columns || []).find(c => pivotKindFor(c.key) === result.kind) ||
            (targetArt.columns || []).find(c => compatibleKinds.includes(pivotKindFor(c.key)));
          openTab({
            kind: 'artifact',
            hostId,
            artifactId: group.artifactId,
            label: `${state.hosts.find(h => h.id === hostId).name} \u00b7 ${targetArt.name}`,
          });
          // Pre-fill a column filter on the target tab so the user lands
          // already filtered. When the source was a path but the target
          // column is filename-kind, use the basename so the filter still
          // matches; otherwise use the full needle.
          setTimeout(() => {
            const ta = getTabState(state.activeTab);
            if (!ta.colFilters) ta.colFilters = {};
            if (targetCol) {
              const targetKind = pivotKindFor(targetCol.key);
              let filterVal = result.needle;
              if (result.kind === 'path' && targetKind === 'filename') {
                // Strip down to basename so the short-form column matches.
                filterVal = normalizePivotValue('filename', result.needle);
              }
              ta.colFilters[targetCol.key] = `"${filterVal}"`;
              if (!ta.openFilterCols) ta.openFilterCols = new Set();
              ta.openFilterCols.add(targetCol.key);
            } else {
              ta.filter = result.needle;
            }
            render();
          }, 0);
        },
      }, 'open \u2192'),
    ));

    if (expanded) {
      // Pull the actual artifact so we can use its primaryTime + the
      // declared ContextFields for per-row context. Fallback is generic
      // extractLabel if the artifact declared no context fields.
      const targetArt = state.artifactCache[`${hostId}|${group.artifactId}`];
      const list = $('div', { class: 'pivot-group-list' });
      for (const r of visible) {
        list.appendChild(renderPivotRowPreview(r, targetArt));
      }
      if (overflow > 0) {
        list.appendChild($('button', {
          class: 'pivot-show-all',
          onclick: (e) => {
            e.stopPropagation();
            ui.pivotShowAll.add(group.artifactId);
            render();
          },
        }, `Show all ${group.matches.length} matches (${overflow} more)`));
      }
      groupEl.appendChild(list);
    }
    wrap.appendChild(groupEl);
  }
  return wrap;
}

// ---------------------- cross-artifact correlation ----------------------
//
// Two related features live here:
//
//   PIVOT: from a row in artifact A, find every row in artifacts B..N on
//   the same host whose value in a pivot field (hash, path, filename)
//   matches. Triggered from the row drawer; opens a side panel listing
//   match counts per artifact with a click-to-jump action that pre-fills
//   that artifact's per-column filter.
//
//   TIME WINDOW: from a row in artifact A with a known timestamp, build
//   a merged chronological list of every row from every artifact whose
//   primary timestamp falls within +/- N minutes. Opens a new tab.
//
// Both features need every artifact on the host loaded, which means
// firing /api/artifact requests for any not yet cached. We do this
// lazily at correlation-trigger time (not at host-open) so a casual
// host-glance stays fast.

const PIVOT_WINDOWS_MIN = [1, 5, 15, 60, 360];   // selectable +/-N minute options
const DEFAULT_PIVOT_WINDOW_MIN = 5;

// pivotKindFor returns 'hash' | 'path' | 'filename' | null for a column,
// based on its key name. Used to mark which row-drawer fields are
// clickable for cross-artifact pivots.
//
// The classification is suffix/contains-based. Both "Path" and "ParentPath"
// are paths; both "FileName" and "OriginalFileName" are filenames. We
// distinguish them by checking "filename" patterns first so "filename"
// wins over "path" if both could apply (which can't happen with current
// EZ Tools column names anyway).
const pivotKindFor = (colKey) => {
  if (/^(sha1|md5|sha256|hash)$/i.test(colKey)) return 'hash';
  // The explicit path names (SourceFile, SourceFilename) are paths to the
  // raw source artifact on disk -- check before the generic filename$
  // pattern below, since "SourceFilename" ends with "filename" too.
  if (/^(sourcefile|sourcefilename)$/i.test(colKey)) return 'path';
  // Filename-like names: bare "FileName", "OriginalFileName",
  // "ExecutableName". These are short basenames, not full paths.
  if (/(filename|executablename)$/i.test(colKey)) return 'filename';
  // Anything else ending in "path".
  if (/path$/i.test(colKey)) return 'path';
  return null;
};

// normalizePivotValue prepares a raw cell value for cross-artifact match.
// For hashes: lowercase + strip non-hex. For paths: lowercase, strip the
// kernel/global prefixes \??\ and \\?\, and normalize / -> \. Keeps the
// comparison tolerant of cosmetic format differences across tools.
const normalizePivotValue = (kind, raw) => {
  if (raw == null) return '';
  let s = String(raw).trim();
  if (!s) return '';
  if (kind === 'hash') {
    return s.toLowerCase().replace(/[^0-9a-f]/g, '');
  }
  if (kind === 'path' || kind === 'filename') {
    // Strip the kernel/NT-style \??\ prefix and the UNC-style \\?\ prefix.
    // These appear in different DFIR sources (registry vs Win32 APIs)
    // for the same underlying file; stripping makes matches portable.
    s = s.replace(/^\\\?\?\\/, '');     // leading \??\
    s = s.replace(/^\\\\\?\\/, '');     // leading \\?\
    s = s.replace(/\//g, '\\');
    s = s.toLowerCase();
    if (kind === 'filename') {
      const idx = s.lastIndexOf('\\');
      if (idx >= 0) s = s.slice(idx + 1);
    }
    return s;
  }
  return s.toLowerCase();
};

// pivotFieldsForArtifact scans an artifact's columns and returns those
// whose keys identify a pivotable kind. The drawer shows pivot affordances
// only for these.
const pivotFieldsForArtifact = (art) => {
  if (!art || !art.columns) return [];
  const out = [];
  for (const c of art.columns) {
    const kind = pivotKindFor(c.key);
    if (kind) out.push({ col: c, kind });
  }
  return out;
};

// ensureAllArtifactsLoaded fires /api/artifact for every artifact on the
// host that isn't already in state.artifactCache. Returns a Promise that
// resolves to an array of {artifactId, art} once all are loaded (or
// failed). Failures are tolerated -- the artifact is simply omitted from
// the correlation result -- so one bad CSV doesn't break the feature.
async function ensureAllArtifactsLoaded(hostId) {
  const host = state.hosts.find(h => h.id === hostId);
  if (!host) return [];
  const summaries = host.artifacts || [];
  const pending = [];
  for (const s of summaries) {
    const key = `${hostId}|${s.id}`;
    if (state.artifactCache[key]) continue;
    pending.push(
      api.artifact(hostId, s.id)
        .then(a => { state.artifactCache[key] = a; })
        .catch(e => {
          console.warn(`correlation: failed to load ${s.id} for ${hostId}:`, e);
        })
    );
  }
  if (pending.length > 0) {
    toast(`loading ${pending.length} artifact(s) for correlation\u2026`);
    await Promise.all(pending);
  }
  // Return what we now have, in stable order.
  return summaries
    .map(s => ({ artifactId: s.id, art: state.artifactCache[`${hostId}|${s.id}`] }))
    .filter(x => x.art);
}

// runPivot searches every loaded artifact on the host for rows whose
// pivot-eligible columns contain a value matching `needle`.
// Returns { kind, needle, byArtifact: [{ artifactId, name, matches: [rows] }] }.
// "matches" is the row objects themselves (not row indices) so callers
// can render previews directly.
//
// Kind interplay:
//   * 'hash'     -- strict equality only. Different hash algos must not
//                   cross-match. Only columns of hash-kind are scanned.
//   * 'path'     -- scans path-kind AND filename-kind columns. A short
//                   filename like "powershell.exe" in Prefetch DOES match
//                   a path needle "C:\Windows\System32\powershell.exe"
//                   because they reference the same executable.
//   * 'filename' -- scans both kinds too. Path-kind cells are reduced to
//                   their basename for the comparison.
//
// This is the right behavior for DFIR pivots: an analyst clicking a hash
// wants only same-hash matches, but an analyst clicking a path or filename
// wants every artifact that references that file, regardless of whether
// the referencing artifact stored a full path or just the basename.
function runPivot(hostId, kind, needle, loaded) {
  const normalizedNeedle = normalizePivotValue(kind, needle);
  if (!normalizedNeedle) return { kind, needle, byArtifact: [] };

  // For path/filename, also derive the bare basename of the needle. Used
  // for matching short-form columns (Prefetch ExecutableName, etc).
  let needleBasename = '';
  if (kind === 'path' || kind === 'filename') {
    needleBasename = normalizePivotValue('filename', needle);
  }

  const byArtifact = [];
  for (const { artifactId, art } of loaded) {
    if (!art.rows || !art.rows.length) continue;

    // Build the candidate column set. For hash, strict. For path/filename,
    // include both kinds so we can compare across short and long forms.
    const candidateCols = [];
    for (const c of (art.columns || [])) {
      const colKind = pivotKindFor(c.key);
      if (kind === 'hash' && colKind === 'hash') {
        candidateCols.push({ key: c.key, colKind });
      } else if ((kind === 'path' || kind === 'filename') &&
                 (colKind === 'path' || colKind === 'filename')) {
        candidateCols.push({ key: c.key, colKind });
      }
    }
    if (candidateCols.length === 0) continue;

    const matches = [];
    for (const r of art.rows) {
      for (const { key, colKind } of candidateCols) {
        const raw = r[key];
        if (raw == null || raw === '') continue;
        // Normalize the cell using its OWN kind, not the needle's. This
        // is what makes a path-kind cell like "C:\Windows\foo.exe"
        // comparable to a filename-kind needle: we normalize once for
        // path semantics, then derive the basename for the cross-form
        // comparison below.
        const cellAsPath = normalizePivotValue('path', raw);
        const cellBasename = normalizePivotValue('filename', raw);

        let hit = false;
        if (kind === 'hash') {
          if (cellAsPath === normalizedNeedle) hit = true; // path-norm of a hex string == lowercased hex string
        } else {
          // Equal-full-path match.
          if (cellAsPath === normalizedNeedle) hit = true;
          // Path needle ends with the cell's basename or vice versa.
          else if (needleBasename && cellBasename === needleBasename) hit = true;
          // Path needle contains the cell's path as a final component.
          else if (cellAsPath && normalizedNeedle.endsWith('\\' + cellAsPath)) hit = true;
          // Cell contains the path needle as a final component.
          else if (cellAsPath.endsWith('\\' + normalizedNeedle)) hit = true;
        }
        if (hit) { matches.push(r); break; }
      }
    }

    if (matches.length > 0) {
      const host = state.hosts.find(h => h.id === hostId);
      const summary = ((host && host.artifacts) || [])
        .find(a => a.id === artifactId);
      byArtifact.push({
        artifactId,
        name: summary ? summary.name : artifactId,
        icon: summary ? summary.icon : '?',
        matches,
      });
    }
  }
  return { kind, needle, byArtifact };
}

// parseArtifactTime tries to parse a row's primary-time value into a
// JS Date. Handles the common EZ Tools / Hayabusa format
// "YYYY-MM-DD HH:MM:SS.fff" -- ISO compatible once a "T" replaces the
// space. Returns null on parse failure so callers can skip that row.
function parseArtifactTime(value) {
  if (!value) return null;
  const s = String(value).trim();
  if (!s) return null;
  // Try as-is first, then with T substitution.
  let d = new Date(s);
  if (isNaN(d.getTime())) {
    d = new Date(s.replace(' ', 'T'));
  }
  if (isNaN(d.getTime())) return null;
  return d;
}

// runTimeWindow finds all rows from all loaded artifacts whose primary
// timestamp falls within [anchor - window, anchor + window] minutes.
// Anchored on the (already-parsed) Date `anchorTime`. Returns a flat
// chronological array of { artifactId, name, icon, time, row }.
function runTimeWindow(hostId, anchorTime, windowMin, loaded) {
  const lo = new Date(anchorTime.getTime() - windowMin * 60 * 1000);
  const hi = new Date(anchorTime.getTime() + windowMin * 60 * 1000);
  const events = [];
  const host = state.hosts.find(h => h.id === hostId);
  const artifactSummaries = (host && host.artifacts) || [];
  for (const { artifactId, art } of loaded) {
    const primary = art.primaryTime;
    if (!primary) continue;
    if (!art.rows || !art.rows.length) continue;
    const summary = artifactSummaries.find(a => a.id === artifactId);
    const name = summary ? summary.name : artifactId;
    const icon = summary ? summary.icon : '?';
    for (const r of art.rows) {
      const t = parseArtifactTime(r[primary]);
      if (!t) continue;
      if (t < lo || t > hi) continue;
      events.push({ artifactId, name, icon, time: t, row: r });
    }
  }
  events.sort((a, b) => a.time - b.time);
  return events;
}

// renderCorrelation displays the time-window correlation tab: a merged
// chronological list of every event from every artifact on the host
// whose primary timestamp falls within the window. Events are grouped
// visually by artifact (color-coded icon prefix) but sorted by time.
function renderCorrelation(tab) {
  const cache = (state.correlationCache && state.correlationCache[tab.correlationKey]) || null;
  if (!cache) {
    return $('main', { class: 'main' },
      renderEmpty('Correlation expired',
        'This time-window view\'s data was discarded. Open the source row and re-run the correlation.'));
  }

  const host = state.hosts.find(h => h.id === cache.hostId);
  const hostName = host ? host.name : cache.hostId;
  const ui = getTabState(state.activeTab);
  ui.corrArtifactFilter = ui.corrArtifactFilter || new Set();

  const artIds = [...new Set(cache.events.map(e => e.artifactId))];
  let events = cache.events;
  if (ui.corrArtifactFilter.size > 0) {
    events = events.filter(e => ui.corrArtifactFilter.has(e.artifactId));
  }

  return $('main', { class: 'main' },
    $('div', { class: 'toolbar' },
      $('div', { class: 'crumbs' },
        $('span', { class: 'host link', onclick: () => openTab({
          kind: 'host-overview', hostId: cache.hostId, artifactId: '',
          label: `${hostName} \u00b7 Overview`,
        }) }, hostName),
        $('span', { class: 'sep' }, '/'),
        $('span', { class: 'cur' }, 'Time Window'),
      ),
    ),
    $('div', { class: 'filter-bar' },
      $('span', { class: 'corr-anchor' },
        $('strong', null, 'Anchor: '),
        cache.anchorLabel || cache.anchorIso,
        $('span', { class: 'corr-window' }, ` \u00b1${cache.windowMin < 60 ? cache.windowMin + ' min' : (cache.windowMin / 60) + ' hr'}`),
      ),
      $('span', { class: 'tb-spacer' }),
      ...artIds.map(aid => {
        const summary = (host && host.artifacts || []).find(a => a.id === aid);
        const label = summary ? summary.name : aid;
        const on = ui.corrArtifactFilter.has(aid);
        return $('button', {
          class: 'chip' + (on ? ' on' : ''),
          onclick: () => {
            if (on) ui.corrArtifactFilter.delete(aid);
            else ui.corrArtifactFilter.add(aid);
            render();
          },
        }, summary ? summary.icon + ' ' : '', label);
      }),
      $('span', { style: { fontSize: '11px', color: 'var(--fg-3)', marginLeft: '8px' } },
        `${events.length} of ${cache.events.length} events`),
    ),
    $('div', { class: 'corr-body', 'data-tab-key': `correlation|${cache.hostId}|${tab.correlationKey}` },
      events.length === 0
        ? $('div', { class: 'tl-empty' },
            $('div', { class: 'ico' }, '\u2300'),
            $('h3', null, 'No events in window'),
            $('p', null, 'Try a larger window from the source row.'),
          )
        : renderCorrelationList(events, cache),
    ),
  );
}

function renderCorrelationList(events, cache) {
  const list = $('div', { class: 'corr-list' });
  const anchorMs = new Date(cache.anchorIso).getTime();
  for (const ev of events) {
    const isAnchor = ev.artifactId === cache.sourceArtifactId && Math.abs(ev.time.getTime() - anchorMs) < 1000;
    const deltaSec = Math.round((ev.time.getTime() - anchorMs) / 1000);
    const deltaLabel = deltaSec === 0 ? '0s'
                     : Math.abs(deltaSec) < 60 ? `${deltaSec > 0 ? '+' : ''}${deltaSec}s`
                     : Math.abs(deltaSec) < 3600 ? `${deltaSec > 0 ? '+' : ''}${Math.round(deltaSec / 60)}m`
                     : `${deltaSec > 0 ? '+' : ''}${(deltaSec / 3600).toFixed(1)}h`;

    // Look up the source artifact so we can build per-row context chips
    // using its declared ContextFields. Same logic as the pivot result
    // groups: declared fields produce key=value chips, fallback to
    // extractLabel when nothing's declared or populated.
    const art = state.artifactCache[`${cache.hostId}|${ev.artifactId}`];
    const chips = rowContextChips(ev.row, art);
    const whatCell = chips.length > 0
      ? renderContextChips(chips)
      : $('span', { class: 'corr-what' }, extractLabel(ev.row) || '\u2014');

    list.appendChild($('div', { class: 'corr-event' + (isAnchor ? ' anchor' : '') },
      $('span', { class: 'corr-when' }, ev.time.toISOString().replace('T', ' ').replace('Z', '')),
      $('span', { class: 'corr-delta' }, deltaLabel),
      $('span', { class: 'corr-art' }, ev.icon, ' ', ev.name),
      whatCell,
      $('button', {
        class: 'linkbtn',
        onclick: () => openTab({
          kind: 'artifact',
          hostId: cache.hostId,
          artifactId: ev.artifactId,
          label: `${state.hosts.find(h => h.id === cache.hostId).name} \u00b7 ${ev.name}`,
        }),
      }, 'open \u2192'),
    ));
  }
  return list;
}


// renderHostOverview shows the host's identity (KPI strip across the top)
// followed by a grid of clickable artifact tiles. This is the landing
// page when the analyst clicks a host in the sidebar without selecting
// a specific artifact.
function renderHostOverview(hostId) {
  const host = state.hosts.find(h => h.id === hostId);
  if (!host) {
    return renderEmpty('Host not found', `No host with id ${hostId}`);
  }

  const arts = host.artifacts || [];
  const totalRows = arts.reduce((s, a) => s + (a.rowCount || 0), 0);

  // Find the Hayabusa artifact for the "alerts" KPI. Hayabusa has its own
  // artifact id "hayabusa"; alertCount on it is the count of severity-tagged
  // rows. We sum alertCount across ALL artifacts for the "across all
  // artifacts" caption.
  const totalAlerts = arts.reduce((s, a) => s + (a.alertCount || 0), 0);

  // Role string for the second KPI. Prefer explicit fields, fall back to tag.
  let roleText = host.role
    || (host.tag === 'DC' ? 'Domain Controller' : 'Workstation');
  const osText = host.os || '';

  // Triage start: pretty-format ISO timestamp if present, else fall back.
  const triageStart = host.triageStart
    ? formatTriageStart(host.triageStart)
    : '(not recorded)';
  const triageSub = host.triageStart
    ? 'from host.json' : 'set triageStart in host.json to populate';

  return $('div', { class: 'main host-page', style: { display: 'contents' } },
    // breadcrumb (host name, current = Overview)
    $('div', { class: 'toolbar' },
      $('div', { class: 'crumbs' },
        $('span', { class: 'cur' }, host.name),
        $('span', { class: 'sep' }, '/'),
        $('span', { class: 'cur' }, 'Overview'),
      ),
    ),

    // Scrollable body wrapping the KPI strip + artifact grid.
    $('div', { class: 'host-page-body' },
      // KPI strip
      $('div', { class: 'host-overview' },
        $('div', { class: 'host-kpi' },
          $('div', { class: 'kpi-ico' }, '🖥'),
          $('div', { class: 'kpi-label' }, 'Hostname'),
          $('div', { class: 'kpi-value' }, host.name),
          host.fqdn && $('div', { class: 'kpi-sub' }, host.fqdn),
        ),
        $('div', { class: 'host-kpi' },
          $('div', { class: 'kpi-ico' }, '🛡'),
          $('div', { class: 'kpi-label' }, 'Role · OS'),
          $('div', { class: 'kpi-value' }, roleText),
          osText && $('div', { class: 'kpi-sub' }, osText),
        ),
        $('div', { class: 'host-kpi' },
          $('div', { class: 'kpi-ico' }, '📄'),
          $('div', { class: 'kpi-label' }, 'Artifacts loaded'),
          $('div', { class: 'kpi-value' }, String(arts.length)),
          $('div', { class: 'kpi-sub' }, `${totalRows.toLocaleString()} rows total`),
        ),
        $('div', { class: 'host-kpi' + (totalAlerts > 0 ? ' alert' : '') },
          $('div', { class: 'kpi-ico' }, '🔔'),
          $('div', { class: 'kpi-label' }, 'Hayabusa alerts'),
          $('div', { class: 'kpi-value' }, String(totalAlerts)),
          $('div', { class: 'kpi-sub' }, 'across all artifacts'),
        ),
        $('div', { class: 'host-kpi' },
          $('div', { class: 'kpi-ico' }, '⏱'),
          $('div', { class: 'kpi-label' }, 'Triage started'),
          $('div', { class: 'kpi-value' }, triageStart),
          $('div', { class: 'kpi-sub' }, triageSub),
        ),
      ),

      // artifact tile grid
      $('h3', null, 'Available artifacts'),
      arts.length === 0
        ? $('div', { class: 'empty' },
            $('div', { class: 'e-inner' },
              $('div', { class: 'e-icon' }, '∅'),
              $('h3', null, 'No artifacts loaded for this host'),
              $('p', null,
                'The host folder contains no recognized CSVs, or every CSV was empty. ' +
                'See Empty_Artifacts.txt at the case root.'),
            ),
          )
        : $('div', { class: 'art-card-grid' },
            ...arts.map(a => $('div', {
              class: 'art-card',
              onclick: () => openTab({
                kind: 'artifact', hostId: host.id, artifactId: a.id,
                label: `${host.name} · ${a.name}`,
              }),
            },
              $('div', { class: 'ac-head' },
                $('div', { class: 'ac-icon' }, a.icon || '·'),
                $('div', null,
                  $('div', { class: 'ac-name' }, a.name),
                  $('div', { class: 'ac-sub' }, `${a.tool || ''} · ${shortenSource(a.sourceFile)}`),
                ),
              ),
              $('div', { class: 'ac-foot' },
                $('span', null, `${(a.rowCount || 0).toLocaleString()} rows`),
                a.alertCount > 0 && $('span', { class: 'ac-alert' },
                  '⚠ ', `${a.alertCount} alerts`),
              ),
            )),
          ),
    ),
  );
}

// formatTriageStart turns an ISO 8601 timestamp into the compact display
// used in the KPI strip (e.g. "2025-11-08 06:00 UTC"). Falls back to the
// raw string if parsing fails.
function formatTriageStart(iso) {
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
           `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
  } catch {
    return iso;
  }
}

// shortenSource returns just the filename component of an artifact path
// for the tile sub-label, so cards don't show 200-character absolute paths.
function shortenSource(p) {
  if (!p) return '';
  const winSep = p.lastIndexOf('\\');
  const unixSep = p.lastIndexOf('/');
  const i = Math.max(winSep, unixSep);
  return i >= 0 ? p.slice(i + 1) : p;
}

// ---------------------- timeline view ----------------------

function renderTimeline(hostId) {
  const ui = getTabState(state.activeTab);
  let events = state.marks.filter(m => !hostId || m.hostId === hostId);

  // search
  const q = ui.tlSearch.toLowerCase();
  if (q) {
    events = events.filter(m =>
      (m.label || '').toLowerCase().includes(q) ||
      (m.note || '').toLowerCase().includes(q));
  }
  if (ui.tlSeverities.size > 0) {
    events = events.filter(m => ui.tlSeverities.has(m.sev));
  }
  if (!hostId && ui.tlHostFilter.size > 0) {
    events = events.filter(m => ui.tlHostFilter.has(m.hostId));
  }
  events.sort((a, b) => {
    const c = (a.ts || '').localeCompare(b.ts || '');
    return ui.tlSort === 'asc' ? c : -c;
  });

  // severity counts (off the full marks list scoped to host)
  const baseScoped = state.marks.filter(m => !hostId || m.hostId === hostId);
  const sevCounts = { crit: 0, high: 0, med: 0, low: 0, info: 0 };
  for (const m of baseScoped) sevCounts[m.sev] = (sevCounts[m.sev] || 0) + 1;

  // span
  let span = '—';
  let firstTs = '', lastTs = '';
  if (baseScoped.length) {
    const sorted = baseScoped.slice().sort((a, b) => (a.ts || '').localeCompare(b.ts || ''));
    firstTs = sorted[0].ts;
    lastTs = sorted[sorted.length - 1].ts;
    span = `${baseScoped.length} events`;
  }

  // hosts involved (global scope only)
  const hostsInvolved = new Set(baseScoped.map(m => m.hostId));

  const sevChips = ['crit', 'high', 'med', 'low', 'info'].map(s =>
    $('button', {
      class: 'chip' + (ui.tlSeverities.has(s) ? ' on' : ''),
      onclick: () => {
        if (ui.tlSeverities.has(s)) ui.tlSeverities.delete(s);
        else ui.tlSeverities.add(s);
        render();
      },
    },
      $('span', { class: 'sev-dot ' + s }),
      `${s.toUpperCase()} ${sevCounts[s] || 0}`,
    )
  );

  const hostChips = !hostId ? state.hosts.map(h =>
    $('button', {
      class: 'chip' + (ui.tlHostFilter.has(h.id) ? ' on' : ''),
      onclick: () => {
        if (ui.tlHostFilter.has(h.id)) ui.tlHostFilter.delete(h.id);
        else ui.tlHostFilter.add(h.id);
        render();
      },
    }, h.name)
  ) : [];

  return $('div', { class: 'timeline-view' },
    $('div', { class: 'toolbar' },
      $('div', { class: 'crumbs' },
        $('span', null, hostId ? 'Hosts' : 'Investigation'),
        $('span', { class: 'sep' }, '/'),
        hostId
          ? $('span', { class: 'host' }, (state.hosts.find(h => h.id === hostId) || {}).name)
          : $('span', { class: 'cur' }, 'Global Timeline'),
        hostId && $('span', { class: 'sep' }, '/'),
        hostId && $('span', { class: 'cur' }, 'Timeline'),
      ),
    ),
    $('div', { class: 'tl-toolbar' },
      $('div', { class: 'search-input' },
        $('span', { class: 'ico' }, '⌕'),
        $('input', {
          type: 'text',
          placeholder: 'search marked events',
          value: ui.tlSearch,
          'data-focus-key': `tl-search-${state.activeTab}`,
          oninput: debounce((e) => { ui.tlSearch = e.target.value; render(); }, 150),
        }),
      ),
      ...sevChips,
      ...hostChips,
      $('span', { class: 'tb-spacer' }),
      $('button', {
        class: 'btn',
        onclick: () => { ui.tlSort = ui.tlSort === 'asc' ? 'desc' : 'asc'; render(); },
      }, ui.tlSort === 'asc' ? '↑ Oldest' : '↓ Newest'),
      $('button', {
        class: 'btn',
        onclick: (e) => {
          const host = hostId ? state.hosts.find(h => h.id === hostId) : null;
          const scope = host ? host.name : 'global';
          showExportMenu(e.currentTarget, (fmt) =>
            exportTimelineEvents(events, scope, fmt));
        },
      }, '⤓ Export'),
    ),
    $('div', { class: 'tl-kpi-row' },
      $('div', { class: 'tl-kpi' },
        $('span', { class: 'label' }, 'Marked events'),
        $('span', { class: 'value' }, baseScoped.length),
        $('span', { class: 'sub' }, hostId ? 'this host' : 'all hosts'),
      ),
      $('div', { class: 'tl-kpi' },
        $('span', { class: 'label' }, 'By severity'),
        $('div', { class: 'sev-line' },
          $('span', null, $('span', { class: 'sev-dot crit' }), sevCounts.crit),
          $('span', null, $('span', { class: 'sev-dot high' }), sevCounts.high),
          $('span', null, $('span', { class: 'sev-dot med' }), sevCounts.med),
          $('span', null, $('span', { class: 'sev-dot low' }), sevCounts.low),
          $('span', null, $('span', { class: 'sev-dot info' }), sevCounts.info),
        ),
      ),
      $('div', { class: 'tl-kpi' },
        $('span', { class: 'label' }, 'Time span'),
        $('span', { class: 'value', style: { fontSize: '14px' } }, span),
        $('span', { class: 'sub' }, firstTs && lastTs ? `${firstTs} → ${lastTs}` : '—'),
      ),
      !hostId && $('div', { class: 'tl-kpi' },
        $('span', { class: 'label' }, 'Hosts involved'),
        $('span', { class: 'value' }, hostsInvolved.size),
      ),
    ),
    $('div', { class: 'tl-body', 'data-tab-key': `${hostId ? 'host-timeline' : 'global-timeline'}|${hostId}|` },
      events.length === 0
        ? $('div', { class: 'tl-empty' },
            $('div', { class: 'ico' }, '🚩'),
            $('h3', null, hostId ? `No marked events for ${(state.hosts.find(h => h.id === hostId) || {}).name}` : 'No marked events yet'),
            $('p', null, 'Open an artifact, then click the flag on a suspicious row to add it here.'),
          )
        : renderTimelineGroups(events, ui, hostId),
    ),
  );
}

function renderTimelineGroups(events, ui, scopeHostId) {
  // group by date (YYYY-MM-DD), preserving sort order
  const groups = new Map();
  for (const e of events) {
    const date = (e.ts || '').slice(0, 10) || '(no date)';
    if (!groups.has(date)) groups.set(date, []);
    groups.get(date).push(e);
  }
  return [...groups.entries()].map(([date, arr]) =>
    $('div', { class: 'tl-group' },
      $('div', { class: 'tl-date' }, date),
      $('div', { class: 'tl-rail' }, ...arr.map(e => renderTimelineEvent(e, ui, scopeHostId))),
    )
  );
}

function renderTimelineEvent(e, ui, scopeHostId) {
  const expanded = ui.expandedEvents.has(e.id);
  const time = (e.ts || '').slice(11, 19);
  const host = state.hosts.find(h => h.id === e.hostId);
  return $('div', { class: 'tl-event sev-' + e.sev },
    $('div', { class: 'tl-dot' }),
    $('div', { class: 'tl-time' },
      $('div', null, time),
      $('div', { style: { fontSize: '10px', color: 'var(--fg-faint)' } },
        (e.ts || '').slice(0, 10)),
    ),
    $('div', { class: 'tl-card' },
      $('div', { class: 'tl-card-head' },
        $('span', { class: 'sev-pill ' + e.sev }, e.sev),
        !scopeHostId && host && $('span', {
          class: 'tl-host-chip',
          onclick: () => openTab({
            kind: 'host-timeline', hostId: host.id, artifactId: '',
            label: `${host.name} · Timeline`,
          }),
        }, '🖥 ' + host.name),
        $('span', {
          class: 'tl-art-chip',
          onclick: () => openTab({
            kind: 'artifact', hostId: e.hostId, artifactId: e.artifactId,
            label: `${(host || {}).name || e.hostId} · ${e.artifactId}`,
          }),
        }, e.artifactId),
        $('span', { class: 'grow' }),
        $('button', {
          class: 'tl-trash',
          title: 'remove mark',
          onclick: async () => {
            try {
              await api.deleteMark(e.id);
              state.marks = state.marks.filter(m => m.id !== e.id);
              render();
            } catch (err) { toast('delete failed: ' + err.message, true); }
          },
        }, '🗑'),
      ),
      $('div', { class: 'tl-label' }, e.label || '(no label)'),
      e.note && $('div', { class: 'tl-note' }, e.note),
      $('div', { class: 'tl-card-foot' },
        $('button', {
          class: 'link-btn',
          onclick: () => {
            if (expanded) ui.expandedEvents.delete(e.id);
            else ui.expandedEvents.add(e.id);
            render();
          },
        }, expanded ? '▾ Hide fields' : '▸ Show fields'),
        $('button', {
          class: 'link-btn',
          onclick: () => openTab({
            kind: 'artifact', hostId: e.hostId, artifactId: e.artifactId,
            label: `${(host || {}).name || e.hostId} · ${e.artifactId}`,
          }),
        }, '↗ Open in ' + e.artifactId),
      ),
      expanded && renderEventExpand(e),
    ),
  );
}

function renderEventExpand(e) {
  const dl = $('dl', { class: 'kv-grid' });
  for (const [k, v] of Object.entries(e.snapshot || {})) {
    if (k.startsWith('__') || !v) continue;
    dl.appendChild($('dt', null, k));
    dl.appendChild($('dd', null, String(v)));
  }
  return $('div', { class: 'tl-expand' },
    $('textarea', {
      class: 'tl-note-input',
      placeholder: 'note',
      'data-focus-key': `tl-note-${e.id}`,
      oninput: debounce(async (ev) => {
        e.note = ev.target.value;
        try { await api.saveMark(e); }
        catch (err) { toast('save failed: ' + err.message, true); }
      }, 400),
    }, e.note || ''),
    dl,
  );
}

function exportTimeline_DEPRECATED() {
  // superseded by exportTimelineEvents + showExportMenu
}

// ---------------------- start ----------------------

bootstrap();
