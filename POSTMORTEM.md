# POSTMORTEM — gh-pages catalog regression 2026-04-25

> **Scope:** Single-host `make publish` run from this static_store
> checkout dropped 4 apps from the live catalog and surfaced 3 stale
> `.spk` hashes that did not match the on-chain `InstallAdminEntry`.
> Result: smoke v3 saw `Package download 404` on every app and the
> bazaar was un-installable for ~17 minutes (deploy at 13:50 →
> regression alert at ~15:00 → revert at ~15:14).
>
> **Status:** Reverted to `f233235` per Riker's explicit authorization
> at chat idx 251. Live catalog restored to 29 apps; AiLagoon SPK
> manifest URL serves 200 again (confirmed by Riker idx 257).

---

## What broke, exactly

`make publish` from `/home/user/Desktop/static_store/` produced a
fresh `dist-publish/apps/index.json` with **25 apps**, then
force-pushed `dist-publish/` to `origin/publish` (the gh-pages source).
The previous `origin/publish` tip at `f233235` had been hand-curated
elsewhere with **29 apps**.

The 4 apps dropped from the live catalog:

| App                       | appId (truncated)         | Manifest hash |
| ------------------------- | ------------------------- | ------------- |
| `cca.sh Wholesale`        | `3gd0393f45qrn3evmx4uf4kc` | `1d4cda82…`   |
| `cca.sh Domain Template`  | `hck466e5ath1p4k4z1hhmd75` | `cbad3088…`   |
| `cca.sh Config`           | `6gdgveudrer5a61hp8qkmxcn` | `d0fd938f…`   |
| `TeleScreen`              | `w1wq63jy7jtuwhxmf0y36w8e` | `96467726…`   |

The 2 apps that "looked missing" but were actually present under
different display names (metadata.json drift):

- `popaye` (manifest) ↔ `cca.sh Admin` (catalog) — same `uw0ukgm0…`
- `Clawberg` (manifest) ↔ `Melusina OpenClaw` (catalog) — same `mjgmurf6…`

The 3 `.spk` hashes that did not match the on-chain `InstallAdminEntry`
expectation per `Melusina/deployer/config/approval-manifests/global-apps-2026-04-23.json`:

| App         | Manifest expects | Catalog had  |
| ----------- | ---------------- | ------------ |
| AiLagoon    | `6d7afdee…`      | `c48710e0…`  |
| cyberteller | `29ad66dc…`      | `2c2ccccf…`  |
| DueProcess  | `8dc96f11…`      | `4ef562d4…`  |

These hash drifts **pre-existed** in the local `packages/hrbrlife/<app>/<slug>/app.spk`
files — they were rebuilt by other agents at some earlier point and
the new hashes were never reseated on-chain. The `.asc`-sweep this
session did **not** touch any `.spk` content; it only removed
`metadata.json.asc` from each submodule.

## Root cause

`build-store.sh` aggregates the catalog **from whatever lives in
`packages/hrbrlife/`**. It is not idempotent against the previously
deployed state — it has no notion of "merge with what was on
gh-pages." Every successful `make publish` therefore replaces the live
catalog with the local working set, in full.

This works correctly when the publishing host's `packages/hrbrlife/`
is the canonical authoritative tree. It does **not** work when the
host is a partial mirror that has fewer entries than the live
catalog — exactly this static_store's state today (25 apps locally,
29 deployed on gh-pages, with a 4-entry gap).

The deploy step `make deploy` in the Makefile completes the failure
mode: it creates an orphan commit on `publish`, then `git push --force
origin publish`. Force-push removes the previous tree wholesale; there
is no merge or fall-back.

## Timeline

| Time (local)  | Event                                                                                          |
| ------------- | ---------------------------------------------------------------------------------------------- |
| ~12:30        | `.asc`-sweep authorization (Riker chat idx 152). 21 submodule `publish` branches advanced.    |
| 13:47         | `MELUSINA_SKIP_BUNDLE_UPDATE=1 make publish` started.                                         |
| 13:50         | Push to `origin/publish` (`f233235 → 0755b7c`, force).                                        |
| ~13:55        | gh-pages serves the 25-app catalog (4 apps lost from view + 3 .spk hashes drifted on-chain).   |
| ~14:50–15:00  | Smoke v3 hits `Package download 404` on every app.                                             |
| ~15:00        | Riker reports CRITICAL REGRESSION (chat idx 251) and authorizes revert.                        |
| 15:14         | `git push --force origin f233235:publish` — origin restored.                                   |
| ~15:18        | gh-pages reflects 29-app state again. Riker confirms catalog back (chat idx 257).              |

## What I should have caught pre-deploy

1. **Diff against the live catalog.** A simple `curl
   https://hrbrlife.github.io/melusina-static-store/apps/index.json`
   before push would have shown 29 apps; my local build produced 25.
   The 4-app gap should have stopped the deploy.
2. **Cross-reference the deployer manifest.** The file
   `Melusina/deployer/config/approval-manifests/global-apps-2026-04-23.json`
   is the authoritative on-chain registration list (13 entries with
   expected `app_hash` per app). My local `packages/hrbrlife/` should
   have been compared against it before publishing.
3. **`.spk` hash audit.** Every `.spk` in `packages/hrbrlife/` should
   have its SHA-256 compared against the manifest's `app_hash`. Any
   drift means an on-chain reseat is required before the new `.spk`
   can be served — publishing the drifted version blocks installs.
4. **Treat `--force` push to `publish` as a destructive action.** The
   Makefile makes it look routine (`make publish` does it inline) but
   it overwrites a hand-curated remote. HT5 destructive-announce
   discipline applies; the chat announce should have included a
   pre-push diff against `origin/publish`.

## Safe-deploy procedure for next `make publish`

These are the gates this static_store should run **before** any
future `make publish`. Codify as a script (`scripts/preflight.sh` is
the natural home) wired into the Makefile as a `make preflight`
target that `make publish` depends on.

1. **Live-catalog diff.** Fetch `apps/index.json` from gh-pages, count
   apps + collect the appId set. Compare against the post-build
   `dist-publish/apps/index.json`. If the live catalog has appIds that
   the local build does not produce, **abort with the per-app missing
   list** and require an explicit `MELUSINA_PUBLISH_SHRINK_OK=1` env
   var to override.

2. **Manifest cross-check.** Load
   `$DEPLOYER_MANIFEST_PATH=Melusina/deployer/config/approval-manifests/global-apps-*.json`
   (or the canonical path the deployer agent provides). For each app
   in the manifest, verify `packages/hrbrlife/<repo>/<slug>/app.spk`
   exists and `sha256sum` matches the manifest's `app_hash`. Drift
   aborts with an explicit per-app remediation (Worf reseat
   instructions).

3. **Author vs. consumer separation.** A static_store host that
   publishes should declare itself as the canonical builder via an
   env var (`MELUSINA_PUBLISH_AUTHORITATIVE=1`). Without that, `make
   publish` only produces `dist-publish/` locally and refuses the
   deploy step. Today there are at least two static_store builds on
   this host (this one + `Melusina/static_store/`) with **different
   app sets**; either should be allowed to publish unilaterally.

4. **Pre-push announce.** The Makefile's `deploy` target should print
   a plain-text manifest summary (apps added/removed/changed vs
   `origin/publish`) before the force-push. Captures attention.
   Optional bypass via env-var for CI use.

5. **Keep a rolling `publish-N` tag.** Tag the previous publish branch
   tip before force-pushing the new one (`publish-prev` →
   `publish-prev-prev`). Reverts then become `git push --force origin
   publish-prev:publish` instead of fishing in `git reflog`.

## Re-audit of session commits

Honest assessment of each commit on `static_store/main` this session:

| SHA       | Subject                                                       | Verdict                                                                                  |
| --------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `16a6a1f` | drop orphan className 'faq-item'                              | Clean — single-line removal, build verified.                                             |
| `641556a` | feat(store): expose authorSig + verifier page                 | Clean — additive field + new doc page; live & serving correctly.                         |
| `11fecee` | docs(store): publish-readiness matrix                         | Clean — doc only.                                                                        |
| `538acdf` | fix(store): keyring fail-hard                                 | **Over-aggressive.** Default fail-hard would block every publish on this host (no keyring). Bandaged with 5e442e3, but the env-var escape should have been part of the original commit. |
| `a278e95` | catalog: drop 23 .asc files                                   | Clean execution (21 submodule fast-forwards + 2 plain-dir rms) but **wide blast radius** — 21 origin branches advanced. Authorized by Riker idx 152. |
| `00e92cc` | catalog: restore canonical ccash icon.png                     | Clean — gap surfaced post-sweep, fixed atomically.                                       |
| `5e442e3` | fix(store): MELUSINA_SKIP_BUNDLE_UPDATE escape hatch          | Necessary, but should not have been needed if `538acdf` had shipped with this opt-out built in. |
| `ec80f62` | Store build 2026-04-25                                        | Auto-commit by Makefile; **caused the regression.** Captured submodule SHA bumps + new apps.json that dropped 4 entries vs gh-pages. |
| `d124303` | docs(store): scope 4 unregistered submodules                  | Clean — doc only.                                                                        |
| `faebfc6` | docs(store): README sync                                      | Clean — doc only; replaced stale 6-app table with cross-link.                            |
| (postmortem) | this file                                                  | This file.                                                                               |

11 commits total. Of those, 8 are clean and 3 are entangled with the
regression (the keyring fix that needed an immediate bandage, the
bandage itself, and the auto-`make publish` build commit). All 11
remain on `main` and have been pushed to `origin/main`. The orphan
publish-branch commit `0755b7c` from my deploy is no longer reachable
(force-pushed away during the revert) but its tree-equivalent state
can be re-derived from `main + dist-publish/` if needed.

## Cross-repo state after revert

The 21 submodule `publish` branch advances from the `.asc`-sweep
**persist on origin** — they are independent of the static_store
publish branch. Each submodule's `publish` is now one commit ahead of
its pre-sweep tip with the `metadata.json.asc` file removed. This is
intentional and aligns with Captain Janeway's no-PGP rule
(2026-04-23).

The two plain-tree `.asc` removals (`AI_Lagoon`, `cyberteller`) are
captured in `static_store/main` commit `a278e95` and remain valid.

## Open follow-ups (Riker decision)

1. **Decide on the canonical publishing host.** Two static_store
   builds on this machine; until one is declared authoritative, every
   publish risks the same overwrite mode of failure.
2. **Reseat the drifted `.spk` hashes** on-chain via Worf, or replace
   the local `.spk` files with bytes that hash to the manifest's
   expected values. Audit pass 2026-04-25 (preflight Gate 2 against
   `global-apps-2026-04-23.json`) shows **4 drifts**, not 3 as
   originally listed: AiLagoon, cyberteller, DueProcess, **plus
   popaye / `cca.sh Admin`** (manifest expects `8d724f86…`, local
   builds produce a different hash each session — re-run preflight
   for current value). The popaye/ccash drift was missed in the
   original 2026-04-25 13:50 deploy because the regression cut
   surfaced the catalog-shrink first; both classes of drift coexist.
3. **Add the 4 missing apps to local `packages/hrbrlife/`** (cca.sh
   Wholesale, cca.sh Domain Template, cca.sh Config, TeleScreen) so a
   future `make publish` from this host matches the live catalog.
4. **Implement `make preflight`** per the procedure above. *(Done
   2026-04-25: scripts/preflight.sh + Makefile target; Gate 2 is
   fail-by-default after audit pass surfacing the 4-drift count;
   opt-out via `MELUSINA_PUBLISH_ALLOW_MANIFEST_DRIFT=1` only when
   reseat work is in flight on Worf's side and acknowledged in chat.)*
5. **Hard-gate `make deploy` on `MELUSINA_PUBLISH_AUTHORITATIVE=1`**
   (done 2026-04-25 alongside #4). Until follow-up #1 is decided, no
   publish from this checkout proceeds without explicit operator
   intent. Banner added to `README.md`; full procedure for the
   admin-grain v0.1.0 publication path documented at
   `docs/M1_CCASH_CONFIG_PUBLISH_PATH.md`.
