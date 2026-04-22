# Sandstorm-app Makefile — universal discipline

**Applies to every Sandstorm/Melusina app's own Makefile** (per-app repos
like `melusina_bureau_notes_app`, `ccash_go_htmx`, etc.). Does **not**
apply to the top-level static-store repo's Makefile, which plays a
different role (aggregator + publisher of the bazaar).

See `sandstorm-app-makefile.template.mk` for the canonical implementation.

---

## Invariant #1 — each target does exactly one thing, named accurately

| Target | Does | Does **not** |
|---|---|---|
| `make build` | Compile source artefacts only | Touch `spk`, bind-mount, verify, publish |
| `make dev` | Unmount → bind-mount → verify → `spk dev` | Build source, pack, verify SPK, publish |
| `make pack` | Unmount → mount → verify mount → `spk pack` → `spk verify` → unmount | Build source, run dev, publish |
| `make verify` | `spk verify` + `gpg --verify` + appId/packageId cross-check | Anything else |
| `make publish` | `make pack` → commit the standard set to this repo's `publish` branch → `git push` | Build, publish to Sandstorm app-market, push anything else |
| `make clean` | Unmount + delete `app.spk` | Touch source, touch publish branch |

If a target's name doesn't describe the action, the target doesn't do
that action. `make build` that silently packs is a lie. `make publish`
that skips verify is worse than a lie.

## Invariant #2 — every `spk` invocation runs under a verified bind-mount

`spk dev` and `spk pack` resolve package-def paths through `/opt/app`. A
stale bind from a prior app is the #1 way to ship a wrong SPK that still
verifies.

Three-step discipline in this order, every time:

1. **Unmount first, unconditionally.** `if mountpoint -q /opt/app; then
   sudo umount /opt/app; fi`
2. **Mount this dir.** `sudo mkdir -p /opt/app && sudo mount --bind "$PWD" /opt/app`
3. **Verify the mount.** Compare inodes of `$PWD/sandstorm-pkgdef.capnp`
   and `/opt/app/sandstorm-pkgdef.capnp`. FATAL + exit if they differ.

The verify step is non-negotiable. It is the only way to prove that the
next `spk` invocation sees the tree we think it does.

## Invariant #3 — `make publish` never pushes to the Sandstorm app-market

`spk publish` is an external command (pushes to apps.sandstorm.io or an
equivalent index). It is **banned from our Makefiles.** Our `make
publish` is a pure git operation against this app's own `publish` branch.
The static-store repo consumes these `publish` branches via submodule
references; no external index is involved.

## Invariant #4 — the `publish` branch layout is standardised

```
<slug>/app.spk              ← signed Sandstorm package
<slug>/metadata.json        ← bazaar catalog entry
<slug>/metadata.json.asc    ← GPG-detached signature over metadata.json
<slug>/icon.png             ← square raster; .svg only if genuinely vector
<slug>/description.md       ← long-form bazaar description
<slug>/screenshots/*.png    ← optional
README.md                   ← at repo root
```

Nothing else is permitted on `publish`. No source, no node_modules, no
.venv, no build outputs other than `app.spk`. `main` and `develop` carry
source; `publish` carries only what the bazaar reads.

## Invariant #5 — `make publish` is idempotent

If the freshly packed `app.spk` has the same `packageId` as what
`origin/publish/<slug>/metadata.json` already records, `make publish`
skips the push. This prevents force-push churn when the same state is
republished.

## Nuances

- **sudo-less environments** (CI, rootless Docker): the mount step fails
  with a clear message. Caller must arrange that `/opt/app` is already
  bound (e.g. `docker run --mount type=bind,src=$PWD,dst=/opt/app`). The
  *verify* step still runs and catches misconfigurations.
- **Parallel invocations:** every mount-touching target uses `flock` on
  `/tmp/melusina-spk-mount.lock`. Two `make pack` calls serialise; they
  don't race on `/opt/app`.
- **Ctrl-C during `make dev`:** the dev target traps `INT TERM EXIT` and
  unmounts before returning control.
- **`make test` (per-app, not in template):** if an app has browser
  tests, `make test` should: start `make dev` in the background, poll a
  health endpoint, run playwright against `http://localhost:6080/<grain>`,
  kill dev. Apps may opt-in with `publish: test pack` to make browser-test
  success a hard prerequisite of publish. The template leaves this out
  because it's app-specific.

## Order of operations for a release

```
make build          # compile source
make dev &          # start Sandstorm dev server (kept running)
make test           # optional — browser/integration tests
kill %1             # stop dev
make pack           # produce the signed SPK + verify it
make publish        # push artefacts to this app's publish branch
```

Each step is atomic. Each step's success is independently verifiable. No
step hides side effects from another step.

## Retrofit guide for existing apps

If an existing app's Makefile pre-dates this doctrine:

1. Copy `sandstorm-app-makefile.template.mk` → `Makefile` (backup the
   existing as `Makefile.old` first).
2. Fill the three `REPLACE_ME_*` vars at the top.
3. Override `build-source` with the app's actual build step.
4. Commit to `main` and `develop`.
5. Do **not** commit to `publish` — that branch is artefact-only.
