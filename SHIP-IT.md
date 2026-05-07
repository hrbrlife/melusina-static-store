# Static Store ship-it runbook

The fast 7-min-loop ceremony: detect committed source changes app-by-app, ship
each, force-push the catalog. Designed for hands-off operation; the work is
done by `scripts/ship-changes.sh` — this doc explains what it does and why.

---

## TL;DR

```bash
# from /home/user/Desktop/static_store
./scripts/ship-changes.sh
```

That's it. The script:

1. Walks every catalog submodule under `packages/<author>/<repo>/`.
2. Resolves each to its source repo on this host (alias map + Desktop sibling).
3. Skips if there's nothing to ship (`HEAD == origin/publish`).
4. For each app with new commits: `make build && make pack && make publish`
   in the source repo. The Makefile (via `spkmodule/mk/core.mk`) picks the
   right signing mode automatically.
5. After per-app pushes, runs `make refresh` + `MELUSINA_PUBLISH_AUTHORITATIVE=1
   make publish` in the static_store to force-push the catalog to gh-pages.

No `make dev`. No post-deploy verification. ~30 s per ship, ~2 min for catalog.

---

## What "shippable" means

An app is shippable when its source-repo `HEAD` is ahead of `origin/publish`:

```bash
git -C $SRC fetch -q origin publish
git -C $SRC rev-list --count origin/publish..HEAD
```

If that count > 0, there are committed source changes that haven't been packed
into a new SPK on the publish branch. The script ships those.

Uncommitted working-tree changes are NOT shipped — the operator has to commit
them first. (`git status --porcelain` is informational only.)

---

## Per-app ceremony — what `make publish` actually runs

The shared discipline lives in `spkmodule/mk/core.mk` (a submodule of every
spkmodule-using app). The script invokes only the public targets:

| Target | What it does |
|--------|--------------|
| `make build` | Run the build backend (`noop` / `go` / `npm` / `custom`). Does NOT touch mounts or SPKs. |
| `make pack`  | Acquire `/tmp/melusina-spk-mount.lock`, unmount any stale `/opt/app`, bind-mount `$APP_DIR → /opt/app`, verify inode match, run pre-pack hooks + capability check, `spk pack $SPK_OUT`, `spk verify` (strict on Pearl, plain otherwise), unmount on exit. |
| `make publish` | Branch on `APP_PEARL_ENABLED`. See below. |

### `make dev` is intentionally skipped

`make dev` runs `spk dev` interactively and is meant for human grain-testing.
The mount discipline `make pack` needs is built into `pack` itself
(core.mk:148-190) — it does its own `_unmount → mount → spk pack → unmount`
under a flock. So `dev` before `pack` is redundant for automation. Skipping
it is the single biggest speed win in this loop.

### Pearl vs offline-stub: `make publish` decides

```
APP_PEARL_ENABLED=yes  (default)
├── state.json present (proposal executed)        → finalize-release + push
├── RELEASE.json has real authorSig + PDA + ts    → push
└── neither                                       → propose-release (phase A) → exit

APP_PEARL_ENABLED=no
└── verify deployer manifest pin → release-json-stub → push
```

**Pearl two-phase ceremony.** First `make publish` submits a Squads
`vaultTransactionCreate` + `proposalCreate` for the ReleaseEntry on Solana
devnet, then exits. Cosigners approve via Squads UI (or `pearl-batch-submit.sh`
which approves with `licensee-signer-1.json` + `licensee-signer-2.json`
and executes). Next loop tick (or any subsequent `make publish`) sees the
executed proposal, fetches the on-chain `author_sig`, rewrites RELEASE.json,
re-packs, and force-pushes to `origin/publish`. The script doesn't need to
distinguish — it just runs `make publish` and the Makefile handles it.

**Offline-stub.** `release-json-stub` synthesises a schema-valid RELEASE.json
deterministically from SPK + metadata. No on-chain hop. 26/34 of today's
catalog uses this lane.

### Credentials / keypairs already on this host

- Foundation release signer: `/home/user/Desktop/Melusina/test-wallets-NEW/foundation.json`
- Squads multisig members: `/home/user/Desktop/Melusina/test-wallets/licensee-signer-{1..4}.json`
- Squads multisig PDA: `9X5ECjTMTtjJNY3DZ7xKuuN2nRWasDbc6FqbmZG4iWse` (devnet, 2-of-4)
- Pearl tool binary: `/home/user/Desktop/melusina-attestdeployer-tool/melusina-pearl-tool`

Pearl phase A and phase B work end-to-end on devnet — `pearl-onchain-submit.js`
is fully functional, not stubbed (lines 138-246 actually `sendTransaction`).

### What lands on each app's `origin/publish`

```
publish/<APP_SLUG>/
├── app.spk                  # the package
├── metadata.json            # bazaar catalog entry
├── RELEASE.json             # attestation (real Pearl OR offline stub)
├── icon.png | icon.svg
├── description.md           # optional
├── capabilities.json        # optional
└── screenshots/             # optional
```

Force-push, orphan branch. No history of older versions in the publish branch.

---

## Catalog rebuild — what happens after per-app pushes

```bash
cd /home/user/Desktop/static_store
make refresh                                         # bump submodule pointers
MELUSINA_PUBLISH_AUTHORITATIVE=1 make publish        # refresh + build + plan + apply
```

`make publish` chains:

1. **refresh** — fetch each submodule's tracked branch (default `publish`),
   stage updated pointers in main.
2. **build** — `build-store.sh --no-refresh`: validates every
   `metadata.json` + `RELEASE.json`, copies icons (md5-named) and SPKs (large
   ones >100 MiB get uploaded to GitHub Releases tag `packages-v1`), writes
   `apps/index.json`, runs `vite build`, packages Sandstorm binary updates.
   Output: `dist-publish/`.
3. **plan** — preflight gates (live-catalog diff vs main, manifest cross-check,
   icon QC, pre-push announce). Stages `dist-publish/` to a `/tmp` worktree
   and writes a marker. Aborts on catalog shrink unless
   `MELUSINA_PUBLISH_SHRINK_OK=1`.
4. **apply** — orphan commit on `publish` branch, force-push. gh-pages serves
   the new tree at `https://hrbrlife.github.io/melusina-static-store/` within
   a minute.

### Env vars

- `MELUSINA_PUBLISH_AUTHORITATIVE=1` — required for plan + apply (gate against
  accidental publish from dev mirrors).
- `MELUSINA_PUBLISH_SHRINK_OK=1` — allow catalog shrink (preflight bypass).
- `MELUSINA_PUBLISH_ALLOW_MANIFEST_DRIFT=1` — allow SPK-hash drift vs deployer
  manifest (during reseat).
- `MELUSINA_PUBLISH_ALLOW_ICON_QC_WARN=1` — allow icon issues (during backfill).
- `MELUSINA_SKIP_BUNDLE_UPDATE=1` — skip Sandstorm tarball packaging
  (when `../sandstorm/` keyring not on this host).

### No GitHub Actions deploy

`.github/workflows/build-smoke.yml` only runs `build-store.sh --dry-run` on
PRs (validation, no deploy). The `publish` branch is updated only via manual
`make apply` — deliberately human-gated.

---

## Apps that won't ship from this host

The 24 catalog submodules split as follows. The script silently `[SKIP]`s the
ones with no source on disk; flagged here so you know not to wait for them.

**Has source + Makefile + spkmodule (the happy path, 8 apps):**

- `MELUSINA_BOTMOTHER` → `/home/user/Desktop/melusina_botmother`
- `AITX-Procedures` → `/home/user/Desktop/DueProcess`
- `client_collection` → `/home/user/Desktop/client_collection`
- `ccash` → `/home/user/Desktop/ccash_go_htmx`
- `openclaw-main` → `/home/user/Desktop/Clawberg`
- `instaco-app` → `/home/user/Desktop/instaco.app`
- `melusina-namedcoin-app` → `/home/user/Desktop/namedcoin-work/melusina-namedcoin-app`
- `pr_ninja` → `/home/user/Desktop/pr_ninja`

**Has source, bespoke Makefile (no spkmodule, but still ships via `make publish`, 4 apps):**

- `melusina-bureau-doc-app` → `/home/user/Desktop/store-rebuild/melusina-bureau-doc-app`
- `melusina-bureau-diagram-app` → `/home/user/Desktop/store-rebuild/melusina-bureau-diagram-app`
- `melusina-bureau-paint-app` → `/home/user/Desktop/store-rebuild/melusina-bureau-paint-app`
- `melusina-bureau-sheets-app` → `/home/user/Desktop/store-rebuild/melusina-bureau-sheets-app`

**No source on disk (8 apps — won't ship from this host):**

- `melusina-bureau-notes-app`
- `melusina-bureau-cal-app`
- `melusina-bureau-contacts-app`
- `melusina-consilium-app`
- `melusina-canboard-app`
- `melusina-cratelink-app`
- `melusina-ccash-client-app`
- `melusina-ccash-org-member-app`

**No source Makefile (won't ship — publish-branch only or static, 4 apps):**

- `INSTASYS_MAIL`, `MiniGit`, `Melusina`, `melusina-galactic-council`, `shell_tester`

If you ever need to ship one of the missing-source apps, drop a single
absolute path into `packages/<author>/<repo>/.source-repo` and the script's
resolver picks it up first.

---

## Failure modes the script handles

| Symptom | Meaning | Action |
|---------|---------|--------|
| `[SKIP] foo: no source repo` | Source not on this host | None — by design |
| `[SKIP] foo: HEAD == origin/publish` | Nothing committed to ship | None — quiet pass |
| `[FAIL] foo: ship failed (see .build-tmp/ship-foo-*.log)` | `make build/pack/publish` non-zero | Read the log; common causes: stale mount (rerun fixes it), spk verify drift (re-pack), Pearl phase A network blip (next tick retries) |
| Catalog rebuild fails on preflight shrink | Live catalog has more apps than local | Set `MELUSINA_PUBLISH_SHRINK_OK=1` only if intentional |

Per-app failures don't stop other apps. The script returns non-zero only if
any app failed OR the catalog rebuild failed.

---

## What the script does NOT do (by design)

- **No `make dev`** — `pack` does its own mount; dev would just slow the loop.
- **No post-deploy store verification** — gh-pages is consistent within a
  minute and the preflight already cross-checked the catalog.
- **No version bump** — operator does that in the source commit. The script
  ships what's committed.
- **No icon QC pass on the source repo** — done globally in `make plan`.
- **No automatic Squads approval** — Pearl phase A waits for cosigners. The
  script ships phase B on the next tick once approved.

---

## Files

- `scripts/ship-changes.sh` — the loop (this runbook).
- `scripts/publish-apps.sh` — the heavyweight equivalent (calls
  `publish-app-full.sh` per app, includes version bump + manifest sync).
  Use when you want the full ceremony, not the fast loop.
- `scripts/publish-app-full.sh` — single-app pipeline: pre-flight + bump + pack
  + ceremony + push + manifest update + sync + plan + apply. Heavyweight.
- `Makefile` — catalog targets (`refresh` / `build` / `plan` / `apply` /
  `publish` / `doctor` / `preflight`).
- `build-store.sh` — the catalog assembler (validate metadata, copy icons +
  SPKs, write `apps/index.json`, run vite, package binary updates).
- `spkmodule/mk/core.mk` (per app) — the build/pack/publish discipline.
- `spkmodule/mk/pearl.mk` (per app) — Squads ceremony (propose / finalize).
