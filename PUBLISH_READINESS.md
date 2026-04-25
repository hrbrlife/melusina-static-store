# Catalog Publish-Readiness Matrix

> **Snapshot:** 2026-04-25 (static_store @ main, post-`641556a`).
> **Source of truth:** filesystem scan of `packages/hrbrlife/` + `.gitmodules` + `src/apps.json`.
> **Greenfield rule:** the only trust root is `RELEASE.json` checked against
> the on-chain Solana ReleaseEntry. Legacy detached PGP signatures
> (`metadata.json.asc`) are rejected at `build-store.sh:352`.
>
> Re-run with: `python3 .build-tmp/scan_publish_readiness.py` (script lives
> below — paste-friendly). Or just rerun the inline scanner in `build-store.sh
> --dry-run` and read the FAIL/OK lines.

---

## Tally

| State                                      | Count |
| ------------------------------------------ | ----- |
| Apps with full per-app metadata.json       | 25    |
| Have RELEASE.json (Solana attest payload)  | 25    |
| Have legacy `metadata.json.asc` (BLOCKER)  | 23    |
| Have `app.spk` on disk                     | 25    |
| Listed in catalog `src/apps.json`          | 25    |
| **Publishable today** (RELEASE + no .asc)  | **2** |
| Blocked only by `.asc` removal             | 23    |
| No RELEASE.json                            | 0     |
| Empty submodule dirs (placeholder)         | 2     |
| Submodule path NOT in `.gitmodules`        | 4     |

**Bottom line:** every app has finalized attestation; 23 of 25 are one
`.asc` removal away from publishing.

---

## Per-app matrix

Columns: `mod` = registered in `.gitmodules`; `rel` = RELEASE.json present;
`asc` = legacy `metadata.json.asc` present (BLOCKER — must die);
`spk` = `app.spk` packaged on disk; `cat` = listed in `src/apps.json`.

| Repo                              | Slug              | mod | rel | asc | spk | cat | Version | appId (truncated)       | Status |
| --------------------------------- | ----------------- | --- | --- | --- | --- | --- | ------- | ----------------------- | ------ |
| AITX-Procedures                   | dueprocess        | Y   | Y   | **Y** | Y | Y | 0.1.0  | wvgj30uhk0ec4hqsyyu… | drop .asc |
| AI_Lagoon                         | ai-lagoon         | **n** | Y | **Y** | Y | Y | 0.7.0  | v4ywsgcuc6wgqvjre99… | register submodule + drop .asc |
| INSTASYS_MAIL                     | mermail           | Y   | Y   | **Y** | Y | Y | 0.4.6  | wfy0c4706yw6rp70t4a… | drop .asc |
| MELUSINA_BOTMOTHER                | botmother         | Y   | Y   | **Y** | Y | Y | 1.0.9  | xjdtxcy392qtrf317py… | drop .asc |
| Melusina                          | (none)            | Y   | n   | n   | n   | n   | —       | —                       | placeholder dir, no app — investigate or remove |
| MiniGit                           | minigit           | Y   | Y   | **Y** | Y | Y | 0.2.0  | pe3k6wapfczy7797n8x… | drop .asc |
| ccash                             | ccash             | Y   | Y   | **Y** | Y | Y | 0.2.0  | uw0ukgm06584v9ggjqq… | drop .asc |
| client_collection                 | clientspace       | Y   | Y   | **Y** | Y | Y | 0.1.0  | kcemn7du4wnacu6uh4a… | drop .asc |
| cyberteller                       | cyberteller       | **n** | Y | **Y** | Y | Y | 0.1.0  | vpj1c0z55jtgtrsv61p… | register submodule + drop .asc |
| fineract-setup                    | fineract-setup    | **n** | Y | n | Y | Y | 0.2.0  | 7htu16dens78fcfkc7u… | register submodule (publishable now) |
| instaco-app                       | instaco-app       | Y   | Y   | **Y** | Y | Y | 0.1.0  | u1rf3x62sw2fk87ayxr… | drop .asc |
| melusina-bureau-cal-app           | bureau-cal        | Y   | Y   | **Y** | Y | Y | 0.1.0  | p0wjp099ry06x0shap6… | drop .asc |
| melusina-bureau-contacts-app      | bureau-contacts   | Y   | Y   | **Y** | Y | Y | 0.1.0  | trymnqgywrmc3pskv61… | drop .asc |
| melusina-bureau-diagram-app       | diagram-bureau    | Y   | Y   | **Y** | Y | Y | 1.0.4  | sexh707e9gpems03ae8… | drop .asc |
| melusina-bureau-doc-app           | doc-bureau        | Y   | Y   | **Y** | Y | Y | 1.0.4  | v38a293urgrhgpppr5q… | drop .asc |
| melusina-bureau-notes-app         | bureau-notes      | Y   | Y   | **Y** | Y | Y | 0.1.0  | pywzhp2ajsmpj1zttsm… | drop .asc |
| melusina-bureau-paint-app         | paint-bureau      | Y   | Y   | **Y** | Y | Y | 1.0.4  | q4332kctv72tw70z8cg… | drop .asc |
| melusina-bureau-sheets-app        | sheets-bureau     | Y   | Y   | **Y** | Y | Y | 1.0.7  | fz7r56h1kr79g4v65cg… | drop .asc |
| melusina-canboard-app             | canboard          | Y   | Y   | **Y** | Y | Y | 0.1.0  | 30k1u80j35a4w3cgg9k… | drop .asc |
| melusina-ccash-client-app         | ccash-client      | Y   | Y   | **Y** | Y | Y | 0.1.0  | fa9m63d4e5x5aqvnu8x… | drop .asc |
| melusina-ccash-org-member-app     | ccash-org-member  | Y   | Y   | **Y** | Y | Y | 0.1.0  | g5kzmttt0092pw3mrqg… | drop .asc |
| melusina-consilium-app            | consilium         | Y   | Y   | **Y** | Y | Y | 0.1.0  | pjqare81cxtxjz411js… | drop .asc |
| melusina-cratelink-app            | cratelink         | Y   | Y   | **Y** | Y | Y | 0.1.0  | ztxjck2pk8ecy6mxchr… | drop .asc |
| melusina-galactic-council         | (none)            | Y   | n   | n   | n   | n   | —       | —                       | placeholder dir, no app — investigate or remove |
| melusina-namedcoin-app            | namedcoin         | Y   | Y   | **Y** | Y | Y | 0.1.0  | 8kea8reanvm5cw7awrx… | drop .asc |
| openclaw-main                     | melusina-openclaw | Y   | Y   | **Y** | Y | Y | 0.1.0  | mjgmurff66jn7m1xtr6… | drop .asc |
| vintage-test-dec                  | vintage           | **n** | Y | n | Y | Y | 1.0.0  | yea96s13pj9d7ugxzju… | register submodule (publishable now) |

---

## Publishable today (no work needed)

These two pass `validate_release_attestation` cleanly and have valid `app.spk`:

- `fineract-setup/fineract-setup/` — v0.2.0
- `vintage-test-dec/vintage/` — v1.0.0

Both already shipped via commit `607c024 catalog: publish fineract Setup +
Vintage Remote Desktop`. Minor follow-up: register both as submodules in
`.gitmodules` so the catalog can refresh them via `git submodule update
--remote`.

---

## Blocked: 23 apps carrying legacy `metadata.json.asc`

The PGP detached signature is an explicit no-go per Captain Janeway
2026-04-23 (zero PGP surface anywhere in pack/publish; release gating
via Solana ReleaseEntry / Squads multisig). `build-store.sh:352-356`
already enforces rejection — these apps fail the validate gate.

**Remediation per app** (uniform): inside each submodule's publish
branch, `git rm <slug>/metadata.json.asc`, commit, push; then in the
catalog repo, bump the submodule SHA pointer. Each `.asc` removal is a
one-line atomic commit in its own submodule repo.

The list of 23 affected apps is the matrix above with `asc=Y`. None
have other blockers — `RELEASE.json` exists and is valid in every
case, `app.spk` is on disk, the apps.json catalog already has the
entry. The single batch-of-23 cleanup unlocks the entire bazaar.

This is a destructive cross-repo change. **Do not execute before
announcing in chat with the full path list per HT5** and obtaining
either Riker handoff to a sweep agent or explicit Captain Imperative.

---

## Off-catalog: Cyberteller Config

Ref: hunt at `static_store-hunt-d78349f6` (chat idx 131). Cyberteller
Config 0.0.1 (`appId 3z8v9rsdkj4xn4exfvq9arqax90g6h9r1q2vp36d91ef7g07ce10`)
is **NOT in this matrix** because it has never been added to the
catalog. The seated v3 PDA `8qPobpFsJ9nExpjCYEMTAXpPPGfe2Cpv74gSQUuWSiBK`
expects SPK hash `d78349f6…` but the on-disk SPK at
`/home/user/Desktop/melusina_cybertellerconfig_app/cybertellerconfig.spk`
hashes to `ae40f0d3…` (rebuilt 2026-04-24 03:18). Either Worf reseats
the v3 PDA against the current binary, or a deterministic-build pipeline
reproduces `d78349f6…`. After that, scaffold the catalog entry.

The same likely applies to `melusina_ccashconfig_app` (cca.sh Config,
v0.0.1 scaffold, appId `6gdgveudrer5a61hp8qkmxcn89wyce5uq1mg92ud40ugr2uj7mz0`,
expected hash `d0fd938f…` per approval manifest) — it is also absent
from this catalog by design. cca.sh Config publication is gated on
ccash AdminGate landing per `MVP_INTEGRATION_KILL_LIST.md §2.2`;
Cyberteller Config publication is gated on Worf reseat.

---

## Placeholder directories

`packages/hrbrlife/Melusina/` and `packages/hrbrlife/melusina-galactic-council/`
are registered submodules in `.gitmodules` but contain no app metadata
on the publish branch. Either they predate a rename, or they're
reserved for future apps. **Action:** Riker decides — either remove
them from `.gitmodules` (cleaning the catalog tree) or leave them
parked for the eventual app to land.

---

## Submodule registration gaps

Four directories with valid app content are NOT registered in
`.gitmodules`:

- `AI_Lagoon` (ai-lagoon v0.7.0) — listed in catalog but submodule
  unregistered → `git submodule update --remote` cannot refresh it.
- `cyberteller` (cyberteller v0.1.0) — same.
- `fineract-setup` (fineract-setup v0.2.0) — same. **Publishable**.
- `vintage-test-dec` (vintage v1.0.0) — same. **Publishable**.

Quick fix per directory: `git submodule add <upstream-url>
packages/hrbrlife/<repo>` from the static_store root. This wires the
repo for future `make refresh` operations without touching submodule
contents.

---

## Recommended execution order

1. **Register the 4 unregistered submodules** (mechanical, low-risk —
   small claim, ~10 min).
2. **Drop the 23 `.asc` files** as a single coordinated sweep (announced
   per HT5, executed across 23 submodule repos + 1 catalog SHA bump
   commit). After this, the bazaar publishes 25/25 with one
   `make refresh && ./build-store.sh` run.
3. **Decide placeholder dirs** (`Melusina`, `melusina-galactic-council`)
   — Riker call.
4. **Companion config apps** (cyberteller-config, ccash-config) follow
   their respective unblockers (Worf reseat / AdminGate landing); not
   on this matrix's critical path.

This file is the snapshot — re-run the scanner after any of the above
to refresh.
