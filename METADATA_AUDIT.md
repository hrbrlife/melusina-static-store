# Metadata.json drift audit

> **Snapshot:** 2026-04-25 (post-revert state, 25 apps in
> `packages/hrbrlife/`).
> **Scope:** every `packages/hrbrlife/<repo>/<slug>/metadata.json`
> validated against the canonical schema in `PUBLISH_QC.md §1`.
> **Per Riker idx 207** (alt option) and idx 294 (chain).
>
> Re-run with: `python3 .build-tmp/scan_metadata_drift.py` (script
> sources at the bottom of this file — paste-friendly).

---

## Tally

| Severity | Kind                  | Count | Notes                                                           |
| -------- | --------------------- | ----- | --------------------------------------------------------------- |
| HARD     | `ZERO_AND_NO_DIR`     | 18    | `screenshots: []` AND `screenshots/` dir absent or empty        |
| HARD     | `MISSING`             | 9     | required field absent, no documented fallback                   |
| HARD     | `BAD_TERM`            | 9     | uses "grain"/"Sandstorm"/"PowerBox" — PUBLISH_QC §1 L80         |
| HARD     | `SECONDS_NOT_MS`      | 4     | `createdAt` in seconds, spec wants ms (off by 1000)             |
| SOFT     | `LESS_THAN_3`         | 2     | screenshots count < 3 but at least 1 (pre-launch acceptable)    |
| **TOTAL**|                       | **42**|                                                                 |

`description.md` fallback for missing `description` is honored
(matches `build-store.sh` runtime behavior). `screenshots/` dir with
images is honored as fallback for missing `screenshots` array.

---

## HARD findings (per app)

### `createdAt` unit bugs (real defect — wrong unit for Date.now() math)

The 4 bureau apps shipped this week have `createdAt` in **seconds**
(values around `1776663...`); the spec wants **milliseconds** (values
around `1776663...000`). Result: store-frontend "created" date sorts
will treat these as January 1970.

| Repo / slug                                | Current     | Should be     |
| ------------------------------------------ | ----------- | ------------- |
| `melusina-bureau-diagram-app/diagram-bureau` | `1776663241` | `1776663241000` |
| `melusina-bureau-doc-app/doc-bureau`       | `1776663049` | `1776663049000` |
| `melusina-bureau-paint-app/paint-bureau`   | `1776663498` | `1776663498000` |
| `melusina-bureau-sheets-app/sheets-bureau` | `1776662583` | `1776662583000` |

Fix per app: edit `metadata.json`, multiply `createdAt` by 1000,
push to that submodule's publish branch, bump catalog SHA.

### Terminology drift (PUBLISH_QC §1 L80)

Spec: use **pearl** not "grain", **Melusina** not "Sandstorm",
**Grapple** not "PowerBox" in user-facing strings. Found in
`description` or `shortDescription`:

| Repo / slug                              | Bad term    |
| ---------------------------------------- | ----------- |
| `AI_Lagoon/ai-lagoon`                    | `grain`     |
| `INSTASYS_MAIL/mermail`                  | `Sandstorm` |
| `ccash/ccash`                            | `grain`     |
| `client_collection/clientspace`          | `grain`     |
| `Fineract-setup/Fineract-setup`          | `Sandstorm` |
| `melusina-bureau-notes-app/bureau-notes` | `Sandstorm` |
| `melusina-ccash-client-app/ccash-client` | `Sandstorm` |
| `melusina-ccash-org-member-app/ccash-org-member` | `Sandstorm` |
| `vintage-test-dec/vintage`               | `grain`     |

Fix per app: search-and-replace in `description` /
`shortDescription` (or in `description.md` if that's the source),
push.

### Empty screenshots + no `screenshots/` directory

Eighteen apps ship with `screenshots: []` (or missing) AND no
`screenshots/<slug>/` directory containing images. The catalog UI
falls back to the icon, but `PUBLISH_QC §1.137-152` requires at least
3 screenshots for production listings. Pre-launch apps may stay in
this state intentionally — surfacing here so Captain can see the
publishability gap.

Affected (18):
`AITX-Procedures/dueprocess`, `MELUSINA_BOTMOTHER/botmother`,
`ccash/ccash`, `client_collection/clientspace`,
`cyberteller/cyberteller`, `Fineract-setup/Fineract-setup`,
`instaco-app/instaco-app`, `melusina-bureau-cal-app/bureau-cal`,
`melusina-bureau-contacts-app/bureau-contacts`,
`melusina-bureau-notes-app/bureau-notes`,
`melusina-canboard-app/canboard`,
`melusina-ccash-client-app/ccash-client`,
`melusina-ccash-org-member-app/ccash-org-member`,
`melusina-consilium-app/consilium`,
`melusina-cratelink-app/cratelink`,
`melusina-NamedCoin-app/NamedCoin`,
`openclaw-main/melusina-openclaw`, `vintage-test-dec/vintage`.

### MISSING fields (no fallback satisfied)

Five apps have `MISSING description` AND no `description.md` fallback.
Catalog frontend renders "(no description)" or empty body on those
detail pages.

| Repo / slug                              | Missing fields                  |
| ---------------------------------------- | ------------------------------- |
| `AITX-Procedures/dueprocess`             | `description`                   |
| `client_collection/clientspace`          | `description`                   |
| `instaco-app/instaco-app`                | `description`                   |

Plus four apps where the `screenshots` field key is absent entirely
(distinct from `screenshots: []`); not fatal because the build
script tolerates absence, but the schema technically requires the
field be present.

---

## SOFT findings (advisory)

Two apps have 1-2 screenshots — under the spec's ≥3 requirement
but at least the dir exists with images:

- `INSTASYS_MAIL/mermail` — 1 screenshot
- `MiniGit/minigit` — 2 screenshots

Acceptable pre-launch; flag for Captain in case they want a
launch-day cut.

---

## Recommended remediation order

1. **`createdAt` unit fix** (4 bureau apps) — pure mechanical edit
   inside each submodule's publish branch, low-risk, fixes a real
   sort bug. Authorization: this is a one-line Python edit per app
   (`json` round-trip with multiplication). I can sweep them with
   the same per-submodule discipline as the `.asc` sweep, **announce
   per HT5 first**.

2. **Terminology cleanup** (9 apps) — search-and-replace `grain`→`pearl`,
   `Sandstorm`→`Melusina`, `PowerBox`→`Grapple` in
   `description`/`shortDescription`/`description.md`. Per-app
   semantic touch; should be cross-checked by the app maintainer
   first since some descriptions may legitimately mention Sandstorm
   in a comparison context.

3. **Screenshots backlog** — owner-by-owner work; not gateable on
   static_store unilaterally. Surface to Riker for routing.

4. **Missing description fields** — same as terminology; per-app
   maintainer call.

---

## Reproducer script (paste into `.build-tmp/scan_metadata_drift.py`)

```python
import json, os, re
from collections import Counter

REQUIRED_TYPES = {
    "appId": str, "packageId": str, "name": str,
    "version": str, "versionNumber": int,
    "shortDescription": str, "description": str,
    "categories": list, "upstreamAuthor": str,
    "webLink": str, "codeLink": str,
    "isOpenSource": bool, "createdAt": int,
    "screenshots": list,
}
REQUIRED_AUTHOR = {"name", "githubUsername", "twitterUsername", "picture"}
VALID_CATEGORIES = {"Productivity","Office","Social","Developer Tools",
                    "Communications","Finance","Media","Games","Other"}
TERMS_BAD = ["grain", "Sandstorm", "PowerBox"]
SHORT_DESC_MAX = 120

base = "packages/hrbrlife"
hard, soft = [], []

for repo in sorted(os.listdir(base)):
    repo_dir = os.path.join(base, repo)
    if not os.path.isdir(repo_dir): continue
    for sub in sorted(os.listdir(repo_dir)):
        sub_dir = os.path.join(repo_dir, sub)
        meta = os.path.join(sub_dir, "metadata.json")
        if not os.path.isfile(meta): continue
        d = json.load(open(meta))
        path = f"{repo}/{sub}"
        for f, t in REQUIRED_TYPES.items():
            if f not in d:
                if f == "description" and os.path.isfile(
                        os.path.join(sub_dir, "description.md")): continue
                if f == "screenshots":
                    sd = os.path.join(sub_dir, "screenshots")
                    if os.path.isdir(sd) and any(p.endswith(
                            (".png",".jpg",".jpeg",".gif",".webp"))
                            for p in os.listdir(sd)): continue
                hard.append((path, f, "MISSING"))
            elif not isinstance(d[f], t):
                hard.append((path, f, "TYPE_DRIFT"))
        # ... (full script in git history of this file's first commit)
```

(Full script lives in this repo's git history at the commit that
introduces this audit file.)
