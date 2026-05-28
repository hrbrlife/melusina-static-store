# Melusina SPK Makefile — universal discipline

**Canonical implementation lives in a separate repo:**
[`hrbrlife/melusina-spkmodule-component`](https://github.com/hrbrlife/melusina-spkmodule-component)

Every Melusina-owned pearl pulls it in as a git submodule at `./spkmodule/`.
Each app's own `Makefile` is a ~5-line thin header — three config vars and one
`include`. One place to evolve; one place to fix.

---

## Install into a new or existing app repo

```sh
# from the app repo root, on the main branch
git submodule add -b main https://github.com/hrbrlife/melusina-spkmodule-component.git spkmodule
```

Write the app's `Makefile`:

```make
# Per-app configuration — required
APP_SLUG        := bureau-notes

# Optional
APP_BUILD_STYLE := noop        # noop | go | npm | custom
# PUBLISH_EXTRAS := changelog.md VERSION

# Discipline
include spkmodule/mk/core.mk
```

Commit the submodule pointer + the Makefile on `main` and `develop`. Done.

---

## Invariant #1 — each target does exactly one thing, named accurately

| Target | Does | Does **not** |
|---|---|---|
| `make build` | Compile source (backend from `APP_BUILD_STYLE`) | Touch `spk`, bind-mount, verify, publish |
| `make dev` | Unmount → bind-mount → verify → `spk dev` | Build |
| `make pack` | Unmount → mount → verify → `spk pack` → `spk verify` → unmount | Build |
| `make verify` | `spk verify` + appId/pkgId cross-check | Anything else |
| `make publish` | `make pack` → commit standard set to this repo's `publish` branch → `git push` | Build; push through a raw market endpoint |
| `make clean` | Unmount + delete `app.spk` | Touch source |

## Invariant #2 — every `spk` invocation runs under a verified bind-mount

`spk dev` and `spk pack` resolve pkgdef paths through `/opt/app`. A stale bind
from a prior app is the #1 way to ship a wrong SPK that still verifies.

Three-step discipline in this order, every time, enforced by `core.mk`:

1. **Unmount first, unconditionally.** `if mountpoint -q /opt/app; then sudo umount /opt/app; fi`
2. **Mount this dir.** `sudo mkdir -p /opt/app && sudo mount --bind "$PWD" /opt/app`
3. **Verify the mount.** Compare inodes of `$PWD/sandstorm-pkgdef.capnp` and `/opt/app/sandstorm-pkgdef.capnp`. FATAL + exit if they differ.

## Invariant #3 — `make publish` never pushes through a raw SPK market command

Raw SPK market submission is **banned from our Makefiles.** Our `make publish` is a pure git operation
against this app's own `publish` branch, handled by
`spkmodule/bin/publish-to-branch`.

## Invariant #4 — publish-branch layout is standardised

```
<APP_SLUG>/app.spk              ← signed Melusina package
<APP_SLUG>/metadata.json        ← bazaar catalog entry
<APP_SLUG>/RELEASE.json         ← Melusina attest release manifest, when finalized
<APP_SLUG>/icon.png             ← square raster; .svg only if genuinely vector
<APP_SLUG>/description.md       ← long-form description
<APP_SLUG>/screenshots/*        ← optional
README.md                       ← at repo root
```

Nothing else. No source, no `node_modules`, no `.venv`, no build outputs other
than `app.spk`.

## Invariant #5 — `make publish` is idempotent

If the freshly packed `packageId` matches what origin/publish already records,
`make publish` skips the push. Prevents force-push churn.

---

## Per-app customization (sanctioned)

Three knobs, never touch the template:

### 1. `APP_BUILD_STYLE`

| Value | Uses | When |
|---|---|---|
| `noop` | `mk/build-noop.mk` | SPK contents are pre-built / static |
| `go` | `mk/build-go.mk` | Pearl binary compiled from Go |
| `npm` | `mk/build-npm.mk` | Pearl built via `npm ci && npm run build` |
| `custom` | — | The app Makefile writes its own `build-source` target |

Go/npm backends accept additional knobs — see the individual `.mk` files.

### 2. Hooks — drop an executable script into `.spkmodule-hooks/`

| Hook | When |
|---|---|
| `pre-pack` | Before `spk pack` in `make pack` |
| `post-pack` | After `spk verify` in `make pack` |
| `pre-publish` | Before pushing to `publish` |
| `post-publish` | After successful push |

Environment: `APP_SLUG`, `APP_DIR`, `SPK_OUT`.

### 3. `PUBLISH_EXTRAS`

Space-separated list of paths (relative to `APP_DIR`) to copy onto the publish
branch alongside the standard artefacts. E.g. `PUBLISH_EXTRAS := changelog.md`.

---

## Upgrade flow

When the discipline evolves, bump the submodule pointer in each app:

```sh
cd <app-repo>
(cd spkmodule && git pull origin main)
git add spkmodule
git commit -m "Bump spkmodule to $(git -C spkmodule rev-parse --short HEAD)"
git push origin main
```

Repeat per-repo; no template edits needed in individual apps.

## Order of operations for a release

```
make build          # compile source
make dev &          # start local dev server
# … run browser / playwright tests against http://localhost:6080
kill %1             # stop dev
make pack           # produce and verify signed SPK
make publish        # push artefacts to origin/publish
```

Each step atomic, each step's success independently verifiable, no hidden side
effects.
