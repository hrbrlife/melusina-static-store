# Melusina App Bazaar — Publish Quality Control

Comprehensive checklist for verifying any app before publishing to the Melusina App Bazaar.
**Every item must pass** before an SPK is accepted into the store.

---

## 0. Standardized App Directory Layout

Every app repo must follow this structure on its `publish` branch. The app slug directory
(e.g. `bureau/`, `ai-lagoon/`) is the **single source of truth** for all metadata,
icons, screenshots, and the packaged SPK.

```
<repo>/
├── README.md                      # Repo-level readme
├── author.pgp.pub                 # Publisher's PGP public key
├── .gitignore
└── <app-slug>/                    # e.g. bureau/, ai-lagoon/, botmother/
    ├── metadata.json              # ★ MASTER metadata file (single source of truth)
    ├── description.md             # Full markdown description (referenced by metadata.json)
    ├── changelog.md               # Version history / release notes
    ├── icon.svg                   # App icon — MUST be designed SVG (not placeholder)
    ├── app.spk                    # Packaged Melusina app
    ├── metadata.json.asc          # GPG detached signature of metadata.json
    └── screenshots/               # App screenshots
        ├── 01-<descriptive>.png
        ├── 02-<descriptive>.png
        └── ...
```

### The Master Metadata File (`metadata.json`)

This is the **single source of truth** for all app information. The store build script,
the SPK package definition, and any other tooling must derive their data from this file.
It lives alongside the SPK and icon inside `<app-slug>/`.

**Do not** duplicate metadata across multiple files. The `sandstorm-pkgdef.capnp` in the
source repo should be templated or generated from `metadata.json` values during `make pack`.

---

## 1. `metadata.json` — Required Fields

Every field listed below must be present and correctly populated.

### Identity

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `appId` | string | Unique Melusina app ID from `sandstorm-pkgdef.capnp` | `"dwe1pv4ckrxjx3y45mjh166vxjm..."` |
| `packageId` | string | Melusina package ID (md5 hex, 32 chars) | `"e7c520e187750cefd629dcc8c93f98bd"` |
| `name` | string | Human-readable app name | `"Bureau"` |

- [ ] `appId` matches the value in `sandstorm-pkgdef.capnp`
- [ ] `packageId` matches the built SPK's package ID (`spk verify` output)
- [ ] `name` is the canonical app name (not the repo name or slug)

### Versioning

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `version` | string | Semver marketing version | `"2.0.15"` |
| `versionNumber` | integer | Monotonically increasing build number | `7` |

- [ ] `version` follows semver (`X.Y.Z`)
- [ ] `versionNumber` is strictly greater than any previously published value
- [ ] Both match the values in `sandstorm-pkgdef.capnp` (`appMarketingVersion` / `appVersion`)

### Description

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `shortDescription` | string | One-liner for cards (≤120 chars) | `"Sovereign Office Suite"` |
| `description` | string | Full markdown (or `""` to use `description.md`) | `""` |

- [ ] `shortDescription` is concise, compelling, ≤120 characters
- [ ] `description` is either a full markdown string OR empty string `""` (which triggers fallback to `description.md`)
- [ ] If using `description.md` fallback: that file exists alongside `metadata.json`
- [ ] Description covers: what the app does, key features, Pearl types, how to get started
- [ ] Description mentions **Pearl** (not "grain"), **Melusina** (not "Sandstorm"), **Grapple** (not "powerbox")

### Categories

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `categories` | string[] | One or more valid categories | `["Productivity", "Office"]` |

Valid categories (case-sensitive as displayed, matched case-insensitively):
`Productivity`, `Office`, `Social`, `Developer Tools`, `Communications`, `Finance`, `Media`, `Games`, `Other`

- [ ] At least one category assigned
- [ ] Categories accurately describe the app's function

### Author & Attribution

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `upstreamAuthor` | string | Original author / organization | `"Alexei Karpov"` |
| `author.name` | string | Publisher username | `"alexeikarp"` |
| `author.githubUsername` | string | GitHub handle | `"hrbrlife"` |
| `author.keybaseUsername` | string | Keybase handle (or `""`) | `""` |
| `author.twitterUsername` | string | Twitter/X handle (or `""`) | `""` |
| `author.picture` | string | Avatar URL (or `""`) | `""` |

- [ ] `author.name` is present and non-empty
- [ ] `author.githubUsername` is correct (used for profile links in store)
- [ ] `upstreamAuthor` correctly attributes the original developer

### Links

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `webLink` | string | Project website URL | `"https://hrbr.life"` |
| `codeLink` | string | Source code URL (or `""` for proprietary) | `"https://github.com/hrbrlife/..."` |

- [ ] `webLink` is a valid, publicly accessible URL
- [ ] `codeLink` points to the actual source repository (or is `""` if proprietary)

### Licensing & Open Source

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `isOpenSource` | boolean | Whether app is open source | `true` |

- [ ] Accurately reflects the actual license
- [ ] If `true`: repo contains `LICENSE` or `LICENSE.md` with OSI-approved license
- [ ] If `false`: no conflicting open-source license file exists

### Timestamps

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `createdAt` | integer | First publish date (ms since epoch) | `1708790400000` |

- [ ] Valid millisecond-precision Unix timestamp
- [ ] Represents the first publish date (not updated on subsequent releases)

### Screenshots

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `screenshots` | array | Screenshot references | `[{"url":"screenshots/01-inbox.png","caption":"Inbox view"}]` |

- [ ] **At least 3 screenshots** included
- [ ] Format: array of `{"url": "<relative-path>", "caption": "<description>"}` objects
  - Plain string arrays also accepted but object format preferred
- [ ] Screenshot files exist in `<app-slug>/screenshots/` directory
- [ ] Images are PNG, reasonable resolution (1280×800 or similar)
- [ ] Filenames are descriptive: `01-admin-dashboard.png`, not `screenshot1.png`
- [ ] Captions are meaningful: `"Admin dashboard with active cases"`, not `"screenshot"`
- [ ] Screenshots show **real app usage** — not blank/empty states or placeholder content
- [ ] No external URLs or broken paths in screenshot references

---

## 2. Icons — Full Pipeline

### Source Icon

- [ ] Designed SVG icon exists in `<app-slug>/icon.svg`
- [ ] Icon is a **full designed SVG** — not a text-on-gradient placeholder
- [ ] Icon file size is substantial (>10 KB for designed icons; placeholders are typically <2 KB)
- [ ] SVG renders correctly at all sizes (48px through 1024px)
- [ ] Visual design is distinctive and identifiable at small sizes

### Store Icon Pipeline

Icons must also be registered in the store's icon pipeline:

- [ ] Source SVG exists at `icons_split/<AppName>.svg` (in static_store repo)
- [ ] Corresponding PNG exists at `icons_split/<AppName>.png`
- [ ] App is listed in the `APPS` array in `generate_icon_sets.py`
- [ ] `python3 generate_icon_sets.py` successfully generates `app_icons/<AppName>/` with all 23 files:

| File | Size | Purpose |
|------|------|---------|
| `icon.svg` | — | Melusina universal icon |
| `favicon.ico` | 16+32+48 | Multi-resolution favicon |
| `favicon-16x16.png` | 16×16 | Small favicon |
| `favicon-32x32.png` | 32×32 | Standard favicon |
| `icon-48x48.png` | 48×48 | Android / web minimum |
| `icon-72x72.png` | 72×72 | Android |
| `icon-96x96.png` | 96×96 | Android |
| `icon-128x128.png` | 128×128 | Chrome Web Store |
| `icon-144x144.png` | 144×144 | Android |
| `icon-192x192.png` | 192×192 | PWA required |
| `icon-256x256.png` | 256×256 | High quality |
| `icon-384x384.png` | 384×384 | Android PWA |
| `icon-512x512.png` | 512×512 | PWA required / maskable |
| `icon-1024x1024.png` | 1024×1024 | App Store / high-res |
| `apple-touch-icon.png` | 180×180 | iOS default |
| `apple-touch-icon-76x76.png` | 76×76 | iPad |
| `apple-touch-icon-120x120.png` | 120×120 | iPhone retina |
| `apple-touch-icon-152x152.png` | 152×152 | iPad retina |
| `apple-touch-icon-167x167.png` | 167×167 | iPad Pro |
| `apple-touch-icon-180x180.png` | 180×180 | iPhone 6+ |
| `mstile-150x150.png` | 150×150 | Microsoft tile |
| `manifest.json` | — | PWA web app manifest |
| `html-head.html` | — | Copy-paste HTML link/meta tags |

- [ ] Icon in submodule publish branch (`<app-slug>/icon.svg`) matches `icons_split/<AppName>.svg`

---

## 3. Melusina Terminology Compliance

All metadata text, descriptions, changelogs, and in-app strings **must** use Melusina terminology.

| ❌ Do NOT use | ✅ Use instead | Context |
|---------------|---------------|---------|
| Sandstorm | **Melusina** | Platform name |
| grain | **Pearl** | Application instance / container |
| Grain | **Pearl** | (capitalized form) |
| powerbox | **Grapple** | Inter-Pearl capability exchange |
| Powerbox | **Grapple** | (capitalized form) |
| sandstorm.io | **melusina-os.org** | Platform website |
| Oasis | _(removed)_ | Not applicable to Melusina |
| app-index.sandstorm.io | **App Bazaar** | App store reference |

### Checked locations

- [ ] `metadata.json` — `shortDescription`, `description`
- [ ] `description.md` — full text
- [ ] `changelog.md` — all version entries
- [ ] `sandstorm-pkgdef.capnp` — `appTitle`, all `nounPhrase` values, `shortDescription`, `description`
- [ ] In-app HTML/templates — all user-visible strings
- [ ] README.md — repository description

**Automatic check command:**
```bash
grep -rniE '\bsandstorm\b|\bgrain\b|\bpowerbox\b|\boasis\b' \
  --include='*.md' --include='*.json' --include='*.capnp' \
  --include='*.html' --include='*.js' --include='*.go' \
  --include='*.py' --include='*.sh' \
  . | grep -vi 'sandstorm-pkgdef\|sandstorm-http-bridge\|sandstorm-manifest\|github\.com/sandstorm'
```
Matches from Sandstorm system binaries/paths (`sandstorm-http-bridge`, `sandstorm-manifest`,
`sandstorm-pkgdef.capnp`) are acceptable — these are internal runtime components.
User-visible text must use **Melusina**, **Pearl**, **Grapple** exclusively.

---

## 4. Build Pipeline — `make build`

`make build` compiles the application. **Nothing else.**

- [ ] Compiles all source code to production binaries
- [ ] Statically links binaries OR ensures all shared libraries are accounted for
- [ ] Bundles embedded assets (templates, static files, vendor JS/CSS)
- [ ] Output goes to a defined build directory
- [ ] **Does NOT** run `spk dev`, mount anything, or interact with Melusina runtime
- [ ] **Does NOT** run `spk pack` or produce an SPK
- [ ] **Does NOT** push, publish, or deploy anything
- [ ] Reproducible: clean checkout → `make build` produces identical results
- [ ] No stale artifacts from previous builds remain

---

## 5. Development Mode — `make dev`

`make dev` mounts the app for live development testing. **No build steps.**

### Contract

- [ ] **Does NOT** invoke `make build` — uses pre-built artifacts only
- [ ] Stops any existing bind mounts (unmounts `/opt/app` if currently mounted)
- [ ] Remounts the app directory to `/opt/app`
- [ ] Runs `spk dev` from the correct directory (where `sandstorm-pkgdef.capnp` lives)
- [ ] **Does NOT dismount on stop** — the mount persists until `make dev` is run again
- [ ] Only dismounts the previous mount when `make dev` is invoked a second time

### Verification

- [ ] App launches and is fully functional in development Pearl
- [ ] All Pearl types instantiate correctly
- [ ] Hot-reload is functional (file changes in mounted dir reflected in running app)
- [ ] Mount persists after `Ctrl+C` / stopping `spk dev`
- [ ] Running `make dev` again correctly cycles: unmount old → remount → `spk dev`

---

## 6. Packaging — `make pack`

`make pack` creates the distributable SPK. **No build or dev steps.**

### Contract

- [ ] **Does NOT** invoke `make build` — assumes build is already done
- [ ] **Does NOT** invoke `make dev` — no mounts, no spk dev
- [ ] Runs `spk pack` with correct output filename
- [ ] Applies correct versioning from `metadata.json`:
  - `appVersion` = `versionNumber`
  - `appMarketingVersion` = `version`
- [ ] SPK filename includes version: `<app-slug>-<version>.spk` or `app.spk`
- [ ] Runs `spk verify <output.spk>` and confirms it passes
- [ ] Output SPK is placed in a predictable location

### SPK Contents Verification

- [ ] `alwaysInclude` in `sandstorm-pkgdef.capnp` is comprehensive:
  - All app binaries and scripts
  - `sandstorm-manifest`
  - Launcher script (if applicable)
  - System symlinks: `bin`, `lib`, `lib64`
  - Required coreutils: `usr/bin/bash`, `usr/bin/cat`, etc.
  - Shared libraries: `libc.so.6`, `libpthread`, `libtinfo`, `libselinux`, `libpcre2`, `ld-linux-x86-64.so.2`
  - Timezone data: `etc/localtime`, `usr/share/zoneinfo/<zone>`
  - For Python/Node: interpreter, stdlib, `dist-packages`, SSL certs
- [ ] No extraneous files: no `.git/`, `node_modules/`, test fixtures, build tools
- [ ] `sourceMap.searchPath` paths resolve correctly

### SPK Size Sanity Check

| App type | Expected SPK size |
|----------|------------------|
| Go binary (embed.FS) | 5–25 MB |
| Go + static assets | 15–40 MB |
| Python/Node apps | 80–200 MB |

- [ ] No suspiciously large SPK (check for accidental inclusions)
- [ ] No suspiciously small SPK (check for missing dependencies)

---

## 7. Store Publishing — `make publish`

`make publish` prepares store metadata and publishes to the `publish` branch. **Nothing else.**

### Contract

- [ ] **Does NOT** build, dev, or pack — assumes SPK is ready
- [ ] Copies `app.spk` to `<app-slug>/app.spk` (if not already there)
- [ ] Copies `icon.svg` to `<app-slug>/icon.svg`
- [ ] Copies `screenshots/` directory
- [ ] Ensures `metadata.json` is complete and valid
- [ ] Generates `description.md` if needed (or validates it exists)
- [ ] Generates `metadata.json.asc` (GPG signature)
- [ ] Commits all files to the `publish` branch
- [ ] Pushes `publish` branch to remote

### Post-Publish Store Integration

After the app submodule is published, the store must be rebuilt:

```bash
cd static_store
make publish    # refreshes submodules → builds store → deploys to GitHub Pages
```

- [ ] App appears in the store listing with correct name and icon
- [ ] Detail page shows full description, screenshots, metadata
- [ ] Install button constructs correct URL
- [ ] Package URL returns HTTP 200 (not 404):
  - SPKs ≤95 MB: served from `dist-publish/packages/<packageId>`
  - SPKs >95 MB: served from GitHub Releases (`packages-v1` release)

---

## 8. CDN & External Dependencies

- [ ] **Zero CDN references** in any shipped HTML, JS, or CSS
- [ ] No `<script src="https://...">` or `<link href="https://...">` tags
- [ ] Specifically verify **none** of these appear:
  - `unpkg.com`
  - `cdn.jsdelivr.net`
  - `cdnjs.cloudflare.com`
  - `fonts.googleapis.com`
  - `fonts.gstatic.com`
  - `cdn.tailwindcss.com`
- [ ] All vendor libraries present locally in `static/vendor/` or equivalent
- [ ] Fonts self-hosted as `.woff2` with local `@font-face`
- [ ] MathJax/KaTeX (if used) loaded from local bundle

**Automatic check command:**
```bash
grep -rn 'https\?://' <app-build-dir>/ --include='*.html' --include='*.js' --include='*.css' \
  | grep -v 'localhost\|127\.0\.0\.1\|melusina\|data:'
```

---

## 9. Publisher Signature & Keys

- [ ] SPK is signed with the correct GPG key
- [ ] Signing key identity matches `author` in store listing
- [ ] `metadata.json.asc` is a valid detached signature of `metadata.json`
- [ ] `author.pgp.pub` exists at repo root with the publisher's public key
- [ ] `spk verify <file.spk>` passes
- [ ] `pgpSignature` field in capnp references correct signature path
- [ ] Key is not expired or expiring within 90 days

---

## 10. `sandstorm-pkgdef.capnp` Consistency

The capnp file in the **source repo** must be consistent with `metadata.json`.

| capnp field | Must match |
|-------------|-----------|
| `appTitle` | `metadata.json → name` |
| `appVersion` | `metadata.json → versionNumber` |
| `appMarketingVersion` | `metadata.json → version` |
| `shortDescription` | `metadata.json → shortDescription` |
| `categories` | `metadata.json → categories` |
| `author.name` | `metadata.json → author.name` |
| `website` | `metadata.json → webLink` |
| `codeUrl` | `metadata.json → codeLink` |

- [ ] All capnp metadata fields match their `metadata.json` counterparts
- [ ] `actions` (Pearl types) have correct `title`, `nounPhrase`, `command`
- [ ] `continueCommand` references a valid defined command
- [ ] `sourceMap.searchPath` resolves all needed paths
- [ ] `icons` (appGrid, grain, market, appMarket) are set
- [ ] All text uses Melusina terminology (Pearl, Grapple — not grain, powerbox)

---

## 11. Store Frontend Data

The store build script auto-generates `apps/index.json` from submodule metadata.
After a store build, the following must render correctly:

- [ ] App card: name, icon, short description, categories, author, price badge
- [ ] Detail page overview: full description (markdown rendered)
- [ ] Detail page screenshots: all images load, captions display
- [ ] Detail page sidebar: author, version, build number, deploy date, links
- [ ] Install flow: package URL resolves, install modal works
- [ ] Search: app appears when searching by name or description keywords

### Hardcoded Store Data (maintained in `src/main.jsx`)

These are keyed by `appId` and must be added for each new app:

- [ ] `APP_PRICES[appId]` — pricing info (pearl/month, sale flag, SOL disclaimer)
- [ ] `APP_VERSIONS[appId]` — at least one version entry with date and notes
- [ ] `APP_DOCS[appId]` — getting started documentation
- [ ] `APP_FAQ[appId]` — at least the template questions apply; add app-specific ones
- [ ] `APP_REVIEWS[appId]` — seed review(s)
- [ ] `APP_AUDITS[appId]` — AI audit results
- [ ] `APP_USP[appId]` — unique selling point badges (if applicable)
- [ ] `APP_FEES[appId]` — fee/pricing breakdown
- [ ] Connectivity badges — grapple/sidecar requirements declared if applicable

---

## 12. Final Verification — End-to-End

Run these steps in order on a clean checkout:

```bash
# 1. Build the app (source repo)
make build

# 2. Test in development (source repo)
make dev
# → verify app works in browser, all Pearl types, hot-reload
# → Ctrl+C to stop spk dev (mount persists)

# 3. Package (source repo)
make pack
# → spk verify passes

# 4. Publish app to publish branch (source repo)
make publish
# → publish branch has: metadata.json, icon.svg, app.spk, screenshots/, description.md

# 5. Rebuild store (static_store repo)
cd static_store && make publish
# → store deploys with new/updated app

# 6. Verify live store
# → App card visible in listing
# → Detail page loads all tabs
# → Screenshots render
# → Install URL returns HTTP 200
# → Terminology is correct (no Sandstorm/grain/powerbox references)
```

- [ ] All 6 steps complete without errors
- [ ] No regressions from previous published version
- [ ] Store page matches metadata exactly

---

## Quick Reference — `make` Target Contracts

| Target | Does | Does NOT |
|--------|------|----------|
| `make build` | Compile source → binaries + bundled assets | dev, pack, publish, mount, spk anything |
| `make dev` | Unmount old → remount `/opt/app` → `spk dev` | build, pack, publish, dismount on stop |
| `make pack` | `spk pack` → verify SPK → output `.spk` file | build, dev, publish |
| `make publish` | Prepare metadata + SPK → commit/push `publish` branch | build, dev, pack |

Each target is **standalone**. The developer runs them in sequence as needed.
No target invokes another — they compose manually, not automatically.

---

## Appendix A — Metadata Master File Principle

All app metadata originates from **one file**: `<app-slug>/metadata.json`.

```
metadata.json ──→ apps/index.json (via build-store.sh)
             ──→ sandstorm-pkgdef.capnp (via make pack templating)
             ──→ store frontend (via Vite build)
             ──→ SPK internal metadata
```

When updating any piece of metadata (name, version, description, categories),
**edit `metadata.json` only**. All downstream consumers derive from it.

If `sandstorm-pkgdef.capnp` has its own copy of fields like `appTitle` or
`shortDescription`, those should be generated or validated against `metadata.json`
during `make pack` — never edited independently.

---

## Appendix B — Terminology Grep One-Liner

Run from any app directory to catch terminology violations:

```bash
grep -rniE '\bsandstorm\b|\bgrain\b|\bpowerbox\b|\boasis\b' \
  --include='*.md' --include='*.json' --include='*.capnp' \
  --include='*.html' --include='*.js' --include='*.go' \
  --include='*.py' --include='*.sh' \
  . | grep -vi 'sandstorm-pkgdef\|sandstorm-http-bridge\|sandstorm-manifest\|github\.com/sandstorm'
```

Matches from Sandstorm system binaries/paths (`sandstorm-http-bridge`, `sandstorm-manifest`,
`sandstorm-pkgdef.capnp`) are acceptable — these are internal runtime components.
User-visible text must use **Melusina**, **Pearl**, **Grapple** exclusively.
