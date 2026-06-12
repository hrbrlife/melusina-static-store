# Store Sync — Fix Progress & Refined Architecture

**Branch:** `fix/store-sync-mega-killlist` · **Snapshot:** tag `pre-megafix-snapshot-2026-06-12`
**Source of work:** `STORE-SYNC-MEGA-KILL-LIST.md` (35 items). **Live tracker:** this file.
**Owner directive (2026-06-12):** *Fix ALL completely across all apps; retain current
test wallets/app-ids/keys in the central `melusina-os-devtesting` repo, to be rotated &
deleted at graduation.*

## Refined target — the two-stage contract

> **Stage A — app-authoritative publish.** Each app publishes *itself*, fully and
> correctly, and **commits** every output: SPK, `version`/`versionNumber`/`marketingVersion`,
> a **real-signed** `RELEASE.json` (ceremony with the central `core-app-team` test keys —
> never a forged stub), `metadata.json`, capabilities/permissions, screenshots, icon,
> dates, changelog. The **app repo is the single source of truth for its own meta + attestation.**
>
> **Stage B — store as pure regenerator.** `make publish` rebuilds the catalog as a
> **pure function of committed app state** — pulls all committed submodule tips, authors
> nothing, signs nothing, mutates no app meta. Deterministic ⇒ drift is structurally impossible.

Every other writer is deleted or demoted to a read-only wrapper. One `flock` serialises
the single deploy path. Build runs on **committed state only** and **fails closed** on any
stub / hash / version / meta mismatch.

## Meta-sync matrix (must be identical across the whole cycle)

Flow: **app repo (committed) → SPK → RELEASE.json → catalog index → published store → on-chain**

| Field(s) | Owner (Stage A) | Store rule (Stage B) | Gate |
|----------|-----------------|----------------------|------|
| `version` / `versionNumber` / `marketingVersion` | app (one bump site) | copy verbatim | fail if index≠RELEASE≠pkgdef; no regression vs live |
| `packageId` / `sha256` | spk pack | `sha256(app.spk)` recomputed | fail if `appHash≠sha256(spk)` or `packageId≠SPK` |
| `RELEASE.json` (authorSig, multisigPda, threshold, `signedAtUnix`) | ceremony (real ed25519, core-app-team 3-of-4) | copy verbatim | fail on `offline-*`/stub/threshold<2/empty sig |
| `createdAt` / `updatedAt` | app (`updatedAt`=`signedAtUnix`) | copy; never SPK mtime | fail if derived from mtime |
| `capabilities` / `permissionVocabulary` / `roles` / `domains` ("grapple"?) | app pkgdef/metadata | copy verbatim | fail if index missing what metadata declares |
| `screenshots` / `imageId` (icon) | app repo (committed assets) | copy assets to `screenshots/<appId>/` | fail if referenced asset absent |
| `name` / `shortDescription` / `description` / `categories` / `tier` / `license` | app metadata | copy verbatim | fail if blank |
| `MasterNftMint` (on-chain mint) | ceremony | read case-insensitively | fail if metadata has mint but index empty |
| `changelog` (new) | app `changelog.md` | emit into index | warn if missing |

> **"grapple" decoded:** `build-store.sh:492` defines an 8-axis `capabilities.json` profile
> whose first axis is literally **"Grapple & Sidecars"** (then Encryption / Roles / Blockchains /
> Static-Publishing / HTTP-Out / Incoming-API). So GRAPPLE = the Grapple & Sidecars capability
> axis. Currently `capabilities.json` is *optional* (line 494); the meta-sync goal requires it
> committed per app and synced into the index. Tracked as a Phase-4 per-app deliverable.

## Phase status

- [x] **Phase 0** — safety branch + snapshot tag; central repo identified (`melusina-os-devtesting` @ `/home/user/Desktop/Melusina/test-wallets`).
- [x] **Phase 1 — P0 security** (commit `7d2f5c92`)
  - [x] K24 signer → `127.0.0.1:3848` (was `0.0.0.0`); pipeline-independent; restarted.
  - [x] K25 unbind `packages/hrbrlife/Melusina`; unique secrets → central `graduation-rotate/` + `GRADUATION.md`.
  - [x] K26/K09 `admin-server.py` fail-closed (no token ⇒ refuse start), `_check_auth` deny-by-default, CORS de-wildcarded.
- [~] **Phase 2 — kill forgery + build-store gates** (commit pending)
  - [x] K28 collapse `build-store`→symlink of `build-store.sh` (were byte-identical).
  - [x] K02 delete store-side `release-json-stub-fallback`; gate `publish-app-full.sh` stub paths behind `MELUSINA_ATTEST_OFFLINE` (fail-closed).
  - [x] K03 fix vacuous `startswith(('offline-',''))`→`'offline-'`; fail-closed reject of 1-of-1 quorum / offline-* PDA; empty authorSig now FAILs.
  - [x] K16 reject `schemaVersion=1` offline stub fail-closed. Probe: **8 apps** correctly flagged (welcome-pearl, vintage, sheets-bureau, popaye, mlsna-admin, gitpearl, creeper, cca-sh-domain-template); ~35 on-chain pass.
  - [x] **K13 CORRECTED** — real SPK-integrity binding is `packageId==sha256(app.spk)[:32]` (empirically **43/43 green**); flipped Step 5c WARN→FAIL (escape `MELUSINA_ALLOW_PACKAGEID_DRIFT=1`). The "34/43 appHash mismatch" was a *verifier-doc recipe error* (appHash is a pearl dir-tree hash, not raw-spk), NOT 34 corrupt apps.
  - [x] K14 version-drift gate (RELEASE.version must match metadata.version|marketingVersion).
  - [x] K15 `MasterNftMint` read case-insensitively in index assembly + drift check (17 apps used lowercase).
  - [ ] K17 correct `verifier/index.html` recipe (check `packageId==sha256(spk)[:32]`; appHash via dir-tree/on-chain). **NEXT.**
  - [ ] K04 mtime dates: resolved structurally by rejecting stubs (only stubs set signedAtUnix=mtime); real-signed apps carry real dates. Verify post-resign.
  - [ ] K27 the 3 `author.pgp.pub` live in app submodules → handled with per-app commits in Phase 4.
- [ ] **Phase 3 — de-dup writers + locking** — K06 one RELEASE.json writer; K07 quarantine `pearl-ceremony.sh`; K08 real `flock`; K10/K11 ship-loop gates; K12 one Squads identity; K19 non-destructive refresh; K20 single entry point; K21 additive apply.
- [ ] **Phase 4 — per-app Stage-A (all apps)** — K05/K18/K22 commit real attestations across the 20 dirty submodules; re-sign every app (real ceremony); K01 restore popaye; K31 quarantine do-not-reintroduce + riker builds; K27 per-app PGP; K23 changelog.
- [ ] **Phase 5 — regenerate, verify green, deploy** — build from committed; assert meta-sync matrix 43/43; no shrink vs live; then gated `make apply` (publish→gh-pages) + on-chain. Rollback armed via `publish-prev`.
- [ ] **Phase 6 — docs + hygiene** — K29 admin-store partition; K30 doc reconciliation; K32 gh-pages skew; K33 worktrees/stashes; K34 update-channel; K35 runtime-authz separate bucket.

## Notes / open confirmations
- "grapple" interpretation (above) — confirm.
- Prod deploy + on-chain submission gated on a green verified build (outward-facing). Pilot real-signing on one app before fanning out (Squads transactionIndex is serial — no parallel ceremonies).
- No key rotation now (owner: retain test identities centrally; rotate at graduation per `GRADUATION.md`).
