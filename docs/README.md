# `/docs/` — GitHub Pages site

This folder is served as the project's GitHub Pages site at
`https://<user>.github.io/<repo>/`.

## Files

| File | Purpose |
|---|---|
| `index.html` | Landing page (hero, features, artifact list, install) |
| `demo.html`  | Self-contained interactive UI walkthrough |
| `.nojekyll`  | Empty marker file. Disables Jekyll processing so the HTML is served as-is. |
| `README.md`  | This file — not served by Pages. |

## Enabling Pages

In the repo's GitHub settings:

1. **Settings** → **Pages**
2. **Source**: "Deploy from a branch"
3. **Branch**: `main` (or your default branch)
4. **Folder**: `/docs`
5. Save

The site goes live within a minute or two. Subsequent commits to
`/docs/` auto-deploy.

## Keeping in sync with the app

The landing page and demo both **lift CSS variables and class names
verbatim** from the real Douglas styles in
`cmd/artifact-review/static/`. Specifically:

- **Theme tokens** (`--bg`, `--accent`, `--ok`, etc.) — match the
  "velociraptor" theme in `themes.css`. If a theme variable is added
  to the real app, mirror it here.
- **Host overview classes** (`.ho-*`, `.host-ov-*`) — match the chunk
  starting at "Host overview — briefing layout" in `extras.css`.
- **Wizard classes** (`.pp-*`) — match the chunk starting at
  "v0.13.0 — preprocess wizard" in `extras.css`.

When you redesign the real app, propagate the relevant changes here.
There's no automatic syncing; the duplication is deliberate so the
Pages site can be a self-contained single-file demo with no build
step.

## Editing locally

Just open `index.html` or `demo.html` in a browser. No build tools
needed. The CSS is inlined in each file.

## What's not here

- Analytics. The site is dependency-free; we don't load any third-party
  scripts. If you want page-view counts, add them yourself.
- Sitemap, robots.txt. The site is small enough that search engines
  will find it; no need to manage these.
- A 404 page. GitHub Pages falls back to its default 404, which is
  fine.
