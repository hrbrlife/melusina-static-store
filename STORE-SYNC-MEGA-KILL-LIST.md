# Store Sync — Mega Kill List

**Date:** 2026-06-12

**Diagnosis.** Published apps fall out of sync because there is no single driver. At least a dozen scripts — `build-store.sh`, `ship-changes.sh`, `publish-app-full.sh`, `stage-into-catalog.sh`, four-plus RELEASE.json generators, the rollback API, and out-of-repo per-app hooks — each write the same artifacts (per-app `RELEASE.json`, the on-chain attestation, version, `updatedAt`, the index, and the `gh-pages` branch) with divergent recipes and no enforced mutual exclusion. The only mutex, `.publish.lock`, is an empty file (0 bytes, mtime Jun 10) honored by nothing in-repo. Last-writer-wins, so a stub overwrites a real signature, a refresh discards an uncommitted real attestation, and an orphan force-push reverts another lane's deploy. Three things are corrupting production right now: (1) the untracked `scripts/release-json-stub-fallback` regenerates RELEASE.json as a fake 1-of-1 `offline-*` stub that has already clobbered popaye's real 3-of-4 Squads attestation on committed `main` and threatens namedcoin's real v0.1.9 (which exists only as uncommitted working-tree state); (2) a root-owned `offline-sign-server` listens unauthenticated on `0.0.0.0:3848` and will sign+submit Solana transactions as any of 37 wallets for any LAN caller; (3) the `packages/hrbrlife/Melusina` submodule tracks live secrets — program keypair, foundation/keyholder wallets, publisher SECRETS, and a "solflare recovery" seed phrase — inside the clone-reachable catalog tree. The verifier-facing integrity gate is also broken: 34/43 published apps fail the store's own `sha256(spk)==appHash` recipe because `build-store.sh` never asserts it, and on-chain verification was gutted out entirely. The one structural fix: collapse to a single publish entry point with one writer per artifact, a real `flock` on every force-push site, and a fail-closed stub/hash/version gate — demoting all other lanes to read-only or deleting them.

## At a glance

| Priority | Count | Items |
|----------|-------|-------|
| **P0** | 8 | K01, K02, K03, K04, K05, K13, K24, K25 |
| **P1** | 17 | K06, K07, K08, K09, K10, K11, K12, K14, K15, K16, K17, K18, K19, K20, K21, K22, K26 |
| **P2** | 7 | K23, K27, K28, K29, K31, K32, K33 |
| **P3** | 3 | K30, K34, K35 |

*(35 kill items total, distributed 8 / 17 / 7 / 3. Counts reflect the assigned `priority` field on each kill item.)*

> **The single most important structural fix:** collapse to **one publish entry point** (`make publish`) with **one writer per artifact**, a **real `flock` on every force-push site**, and a **fail-closed stub/hash/version gate** — every other lane becomes a read-only wrapper or is deleted.

## Root causes

| RC | Name | Spawns |
|----|------|--------|
| **RC1** | Multi-writer free-for-all on the publish surface with no enforced lock | K06, K07, K08, K09, K10, K11, K20, K21 |
| **RC2** | The offline-stub RELEASE.json generator forges signatures, PDAs and dates and is no longer gated | K01, K02, K03, K04, K05, K12 |
| **RC3** | No publish-time integrity gate binds the SPK, the attestation, the version and the index | K13, K14, K15, K16, K17 |
| **RC4** | Catalog is built from dirty uncommitted working trees and destructive refresh discards real state | K18, K19, K22, K23 |
| **RC5** | Security-critical signing/key material exposed in the publish host and tree | K24, K25, K26, K27 |
| **RC6** | Forked/duplicated tooling and fragmented entry-point doctrine guarantee drift | K28, K29, K30, K31 |
| **RC7** | Latent/abandoned publish debris and dead client-side verification (orthogonal hygiene) | K32, K33, K34, K35 |

**RC1 — Multi-writer free-for-all.** At least four scripts write each per-app catalog RELEASE.json with divergent field recipes, and at least five paths force-push `publish`/`gh-pages`. The only mutex, `.publish.lock`, is honored only by the externally-hosted per-app hooks and referenced by zero in-repo scripts. Last-writer-wins silently determines the on-disk manifest and the live CDN tree, and a rollback can race a forward publish — the mechanism behind the recurring signature/version/date/index drift.

**RC2 — Forged, ungated stubs.** `scripts/release-json-stub-fallback` emits a fake 1-of-1 `offline-*` attestation: hex `sha256` dressed as `authorSig`, `offline-*` PDAs, and `signedAtUnix` sourced from `os.path.getmtime(spk)` (line 102). On-chain verification (`melusina-pearl-tool verify-release`) and the `MELUSINA_ATTEST_REJECT_STUBS` gate were removed/never wired, and the embedded stub-detector at `build-store.sh:788` uses `startswith(('offline-',''))`, which is vacuously true. Stubs publish as authoritative, overwrite real attestations on version bumps, and re-stamp release dates on every rebuild.

**RC3 — No integrity gate.** `build-store.sh` copies RELEASE.json verbatim and never recomputes `sha256(app.spk)==appHash` (34/43 fail), never compares signed vs published version (6 disagree), reads `MasterNftMint` case-sensitively (17 lose their mint), and demotes packageId drift to WARN-only. Existing preflight gates are bypassed by the automation via hardcoded `MELUSINA_PUBLISH_AUTHORITATIVE=1` + `ALLOW_MANIFEST_DRIFT=1`.

**RC4 — Dirty-tree publishing + destructive refresh.** 20 submodules carry uncommitted RELEASE.json/metadata/changelog edits on detached HEADs; `build-store.sh` reads committed state for the index but copies working-tree files for SPK/attest, and every refresh path (`git checkout FETCH_HEAD` / `reset --hard origin/publish`) discards locally-regenerated-but-unpushed real attestations. namedcoin's real v0.1.9 exists in no commit — one refresh regresses it to a v0.1.4 stub. `versionNumber` gaps (MLSNA 57→60, namedcoin 7→11) prove releases shipped from working trees and were never committed.

**RC5 — Exposed signing/key material.** A root-owned `offline-sign-server` listens unauthenticated on `0.0.0.0:3848` and signs+submits as any of 37 wallets for any LAN client; the admin rollback HTTP API force-pushes the live branch unauthenticated by default. The `packages/hrbrlife/Melusina` submodule tracks the program keypair, foundation/keyholder wallets, publisher init/update/revoke SECRETS, a `.pem`, and a "solflare recovery" seed phrase inside the clone-reachable catalog tree, plus residual PGP keyrings/pubs that violate the zero-PGP policy.

**RC6 — Forked tooling, fragmented doctrine.** `build-store` and `build-store.sh` are byte-identical twins that must be patched in lockstep; a second catalog (`store-rebuild/melusina-admin-store`) publishes overlapping apps at conflicting versions; three docs (README/PUBLISH_QC, SHIP-IT, GREENFIELD) describe different entry points and contradict each other on auto-bump; the stub generator has 5+ copies across Desktop. No declared canonical driver means every actor can cite a rule for its own path.

**RC7 — Abandoned debris + dead client verification (orthogonal hygiene).** Abandoned worktrees (`/tmp/store-wt` orphan publish chain, `/tmp/ghp` hot-patching gh-pages today), 641 dangling commits, 17 stashes, an empty update channel and split-brain `latest.json`(build4)/`manifest.json`(build13), an orphan `ccashconfig` binary on gh-pages, and a separate cluster of runtime/update-client failures (squads-watcher restart loop, update-checker 203/EXEC, authzsign down) that are structurally outside the store-publish path and must not pad it.

## Kill list

Action badges: `[FIX]` `[KILL]` `[CONSOLIDATE]` `[QUARANTINE]` `[INVESTIGATE]`. Verdicts: **CONFIRMED**, **PARTIAL**.

---

### P0 — stop the bleeding

---

**K01** · `[FIX]` · **Restore popaye's real 3-of-4 Squads attestation clobbered by an offline stub on committed main** — `CONFIRMED`

- **Target:** `packages/hrbrlife/ccash_go_htmx/popaye/RELEASE.json` (and `dist-publish/attest/uw0ukgm0.../RELEASE.json`)
- **Rationale:** A real on-chain 3-of-4 multisig attestation was overwritten by a fake 1-of-1 stub, and that stub is the live published authz record — an active production authz downgrade.
- **Evidence:** `git show 120ec006` removed `authorSig` base64 `PY7R4YSd...`, `multisigPda 4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V` (threshold 3/4), `releaseEntryPda DwbG4Nx5...` and replaced them with `offline-*` PDAs, hex sig, threshold=1. On disk now: version `0.3.114`, `multisigPda None`, threshold `1`, `signedAtUnix 1781109855 == app.spk mtime 1781109855` exactly.
- **Remediation:** Restore the 3-of-4 record from `120ec006^` (real 0.3.110 attestation) or re-run the Pearl ceremony to attest 0.3.114 on the `4sPNmdcSz...` Squads; commit the real RELEASE.json; rebuild and republish. Do **not** ship the committed stub.
- **Depends on:** K02, K13

---

**K02** · `[KILL]` · **Delete/quarantine the untracked offline-stub RELEASE.json generator that forges signatures and PDAs** — `CONFIRMED`

- **Target:** `scripts/release-json-stub-fallback` (untracked) + the 4 other copies hunted by `stage-into-catalog.sh:27-39` and `ship-changes.sh:391-394`
- **Rationale:** The single mechanism that synthesizes schema-valid FAKE attestations (hex `sha256` "sig", `offline-*` PDAs, 1-of-1 quorum) and clobbers real on-chain records; already scheduled for deletion (`SHIP-IT.md:50`) and resurrected.
- **Evidence:** On disk, line 102 `signed_at = int(os.path.getmtime(spk))`; `offline-*` markers; invoked by `publish-app-full.sh:221/238-261` and `stage-into-catalog.sh:118`; 8/43 published apps carry `offline-*` stubs.
- **Remediation:** Delete `scripts/release-json-stub-fallback` and the sibling copies; remove its invocation from `publish-app-full.sh` and `stage-into-catalog.sh`. If an interim offline mode is unavoidable, make stub output FAIL the publish gate (K03) rather than ship as authoritative.
- **Depends on:** —

---

**K03** · `[FIX]` · **Make the publish lane fail-closed on stub attestations; fix the vacuously-true stub detector** — `CONFIRMED`

- **Target:** `build-store.sh:788` (and identical `build-store:788`); wire `MELUSINA_ATTEST_REJECT_STUBS` default-on in the publish lane
- **Rationale:** The stub-rejection backstop the generator's own header relies on does not exist in `build-store.sh`, and the one detector branch is broken, so every stub passes as "ok".
- **Evidence:** grep for `REJECT_STUBS`/`pearl-tool`/`verify-release` in `build-store.sh` = 0; line 788 `attest.get('releaseEntryPda','').startswith(('offline-', ''))` is always true because of the empty string in the tuple; `build-store.sh:259` prints ok for offline-stub.
- **Remediation:** Remove the `''` from `startswith(('offline-',''))`; add a gate that FAILS the build when any RELEASE.json has an `offline-*` PDA, non-base64 `authorSig`, or `quorumPolicy.threshold<2`, unless `MELUSINA_ATTEST_OFFLINE` is explicitly set; default `MELUSINA_ATTEST_REJECT_STUBS=1` in plan/apply.
- **Depends on:** —

---

**K04** · `[FIX]` · **Stop sourcing `signedAtUnix` from SPK mtime in the stub generator (defeats the 536547ba fix at the source)** — `CONFIRMED`

- **Target:** `scripts/release-json-stub-fallback:102`
- **Rationale:** Commit `536547ba` fixed the consumer (build-store prefers `signedAtUnix` over mtime) but the stub producer sets `signedAtUnix = SPK mtime`, so for stub apps the "authoritative" date *is* the mtime the fix tried to eliminate — re-stamped on every rebuild.
- **Evidence:** Line 102 `getmtime(spk)`; popaye `signedAtUnix 1781109855 == app.spk mtime` exactly; 4/8 stubs currently equal live mtime. `536547ba` changed only `build-store`/`build-store.sh`/`src/apps.json`, never the stub.
- **Remediation:** If the stub survives K02 in any form, derive `signedAtUnix` from metadata `createdAt` or the SPK source git-commit time, or omit it so build-store falls through to its git/createdAt chain. Preferred: delete the stub (K02) entirely.
- **Depends on:** K02

---

**K05** · `[FIX]` · **Commit namedcoin's real on-chain v0.1.9 attestation before any refresh destroys it** — `CONFIRMED`

- **Target:** submodule `packages/hrbrlife/melusina-namedcoin-app` (`namedcoin/RELEASE.json`, `app.spk`, `metadata.json`) + parent gitlink
- **Rationale:** The genuine 3-of-4 v0.1.9 release exists in **no commit anywhere** — only as uncommitted working-tree state. One `git checkout FETCH_HEAD` / `reset --hard` regresses published source to a v0.1.4 offline stub.
- **Evidence:** ` M namedcoin/RELEASE.json`, WT version `0.1.9` threshold `3` with real PDA `GkQyVCfPkn5...`; `git log --all -S0.1.9` returns nothing; `signedAtUnix 1780890814 != SPK mtime` (+12s, a real signing event).
- **Remediation:** Commit the working-tree v0.1.9 RELEASE.json/SPK/metadata into the submodule, bump the parent submodule pointer, then rebuild. Do the same triage for `MLSNA_token` (do **not** bless either current state — obtain a real signature) and the other 19 dirty submodules.
- **Depends on:** K18

---

**K13** · `[FIX]` · **Gate the build on `sha256(app.spk)==appHash`; 34/43 apps currently fail the store's own verifier recipe** — `CONFIRMED`

- **Target:** `build-store.sh` publish gate (alongside the Step 5b consistency assertion ~`:755-830`); regenerate the 34 stale RELEASE.json
- **Rationale:** `build-store.sh` writes the SPK and copies RELEASE.json without ever asserting `appHash` matches the published bytes; with offline stubs there is no on-chain oracle, so this local hash check is the *only* integrity gate — and 34 apps fail it, making them unverifiable/uninstallable per the documented recipe.
- **Evidence:** Full recompute over all 43 apps: PASS=9, FAIL=34, MISSING=0 — not a wrong-field artifact (the 9 PASS apps have `sha256(raw spk)==appHash` exactly; `verifier/index.html:99` documents the raw-spk recipe). build-store copies SPK at `:655-677` without verifying.
- **Remediation:** At publish time recompute `sha256(app.spk)` and FAIL unless it equals `RELEASE.json.appHash`. Regenerate the 34 stale RELEASE.json so `appHash` binds to the shipped SPK; QUARANTINE the 34 from publish until fixed.
- **Depends on:** K06

---

**K24** · `[FIX]` · **Stop/relock the unauthenticated root-owned offline-sign-server on `0.0.0.0:3848`** — `CONFIRMED`

- **Target:** systemd `melusina-offline-sign.service`, `/opt/Melusina/deployer/scripts/offline-sign-server.mjs`
- **Rationale:** A root process binds `0.0.0.0:3848` with no auth and will sign+submit Solana txns as any of 37 wallets (caller-chosen identity, incl. foundation/keyholder) for any LAN client — it can mint the very on-chain authz/release signatures the catalog depends on.
- **Evidence:** `ss` shows `LISTEN 0.0.0.0:3848`; no auth primitives in the 684-line source; `/sign` and `/sign-and-submit` accept caller `identity`; CORS `*`; non-loopback reachability empirically confirmed; 37 wallets under `/opt/Melusina/test-wallets`.
- **Remediation:** `systemctl stop`+`disable` now; set `SIGN_HOST=127.0.0.1`; add per-caller bearer/shared-secret auth with constant-time compare; remove wildcard CORS; remove/gate caller-supplied identity; add a host firewall DROP on tcp/3848 from non-loopback; rotate any non-throwaway wallet exposed during the window.
- **Depends on:** —

---

**K25** · `[KILL]` · **Remove the secret-bearing Melusina submodule from the catalog tree and rotate the leaked keys** — `CONFIRMED`

- **Target:** `.gitmodules` entry `packages/hrbrlife/Melusina` (lines 13-16) + gitlink; upstream `hrbrlife/Melusina` HEAD `5c6c7c2`
- **Rationale:** The submodule (pinned to a full monorepo branch) tracks live `program-keypair.json`, foundation-master/keyholder wallets, publisher init/update/revoke SECRETS, a `.pem`, and a "solflare recovery" seed phrase inside the clone-reachable catalog source tree that `build-store.sh` walks.
- **Evidence:** Tracked in submodule: `melusina_solana_dev-license/keys/program-keypair.json`, `test-wallets/foundation-master.json` + `keyholder-1..5.json`, `deployer/incus-server-setup/publisher-SECRETS.json` + `solana-wallets-SECRETS.json`, `MelusinaOSinstaler.pem`, "solflare recovery".
- **Remediation:** Treat all as compromised: ROTATE/REVOKE the program keypair, publisher init/update/revoke authority keys, and the solflare wallet (move funds, retire seed). Remove the `.gitmodules` binding and gitlink; purge from upstream history (filter-repo/BFG) **after** rotation. Replace with an empty placeholder if still needed.
- **Depends on:** —

---

### P1 — de-duplicate writers, restore gates

---

**K06** · `[CONSOLIDATE]` · **Collapse the four+ RELEASE.json writers to ONE writer per catalog file** — `CONFIRMED`

- **Target:** `scripts/stage-into-catalog.sh:118`, `scripts/pearl-app-ceremony.sh:334`, `scripts/pearl-ceremony.sh:57/100`, `scripts/welcome-pearl-ceremony.sh`, `scripts/release-json-stub-fallback`
- **Rationale:** Four independently-authored drivers own the write of the same `packages/hrbrlife/<repo>/<slug>/RELEASE.json` with divergent recipes and no lock; the last to run determines the manifest — the core recurring-drift mechanism.
- **Evidence:** Same-path overwrite within one `publish-app-full` run (stage at `:334` then ceremony at `:344` to the same `$CAT_PATH`); recipes disagree (stub `offline-*` + mtime; ceremony `signedAtUnix=0` then finalize; pearl-ceremony hardcodes pending-finalize + a *different* vault `5Smc...`/multisig `9X5E...`).
- **Remediation:** Make exactly one promote-to-catalog helper write `$PKG/RELEASE.json`, invoked once at the end of the single publish entry point. Ceremony drivers emit only to `/tmp OUTPUT_DIR`. Flip `COPY_TO_CATALOG` default to `0` in `pearl-app-ceremony.sh:63` so it cannot silently overwrite.
- **Depends on:** K02

---

**K07** · `[QUARANTINE]` · **Quarantine `pearl-ceremony.sh` — a callerless bulk re-signer that writes the catalog path directly with a conflicting vault/multisig** — `CONFIRMED`

- **Target:** `scripts/pearl-ceremony.sh`
- **Rationale:** It writes RELEASE.json into *every* catalog dir in one run with no `/tmp` staging and no COPY gate, using a different Squads vault/multisig than the canonical core-app-team Squads and a "pending-finalize" PDA — a single invocation explains fleet-wide signature clobbering.
- **Evidence:** Zero callers (grep); writes `$ROOT/<repo>/<slug>/RELEASE.json` directly; hardcoded `VAULT=5SmcSBsuaa...`, `MULTISIG=9X5ECjTM...` (disagrees with core-app-team `4sPNmdcSz.../3jfN9rcS...`).
- **Remediation:** Move `scripts/pearl-ceremony.sh` out of `scripts/` (or gate behind an explicit OUT-dir-only mode); reconcile to the single core-app-team Squads config before any reuse.
- **Depends on:** K06

---

**K08** · `[FIX]` · **Put a real `flock` around every publish/gh-pages force-push site** — `CONFIRMED`

- **Target:** `Makefile:303` + `Makefile:309`, `scripts/_rollback.py:272`, `scripts/sync-catalog.sh:93-94`, plus the external post-publish hooks
- **Rationale:** The `.publish.lock` mutex is voluntary and only the externally-hosted per-app hooks honor it; `make apply`, the rollback HTTP API, `rollback-all.sh`, and `sync-catalog --deploy` force-push with no lock, so a hook-driven deploy and an operator/API rollback race to force-push the same branch.
- **Evidence:** `.publish.lock` is 0 bytes (Jun 10); `grep flock|publish.lock` across `Makefile`/`admin-server.py`/`_rollback.py`/`sync-catalog.sh`/`ship-changes.sh` = none; `Makefile:290-302` is only an optimistic remote-drift gate (TOCTOU-racy, not on the gh-pages push).
- **Remediation:** Add `scripts/with-publish-lock.sh` that acquires `flock -w 600 200` on `.publish.lock`; wrap `Makefile apply` (303+309), `_rollback.py rollback_full_catalog`, and `sync-catalog.sh` plan/apply in it so all writers serialize against the hooks.
- **Depends on:** —

---

**K09** · `[CONSOLIDATE]` · **Demote the admin rollback HTTP API and rollback CLIs to lock-respecting, gated paths** — `CONFIRMED`

- **Target:** `scripts/admin-server.py:130-169`, `scripts/_rollback.py:271-274`, `scripts/rollback-all.sh`, `scripts/rollback-app.sh`
- **Rationale:** A second runtime controller force-pushes the live publish branch outside the build's drift gate and outside any lock, and is unauthenticated when `MELUSINA_ADMIN_TOKEN` is unset; a rollback during a forward publish re-clobbers state.
- **Evidence:** `_rollback.py:272` `git push --force origin publish-prev:publish` reached via `POST /admin/rollback/full` and `rollback-all.sh`; `admin-server.py` auth optional (`_check_auth` True when unset), CORS `*`.
- **Remediation:** Route all rollbacks through the same flock (K08) and the Makefile remote-drift gate; require `MELUSINA_ADMIN_TOKEN` (fail-closed) and remove wildcard CORS; bind admin-server to `127.0.0.1` only.
- **Depends on:** K08

---

**K10** · `[FIX]` · **Stop the automation from hardcoding the safety-gate overrides on every tick** — `PARTIAL`

- **Target:** `scripts/ship-changes.sh:264`, `:418-419`, `:422-423`
- **Rationale:** `ship-changes.sh` permanently sets `MELUSINA_PUBLISH_AUTHORITATIVE=1` and `MELUSINA_PUBLISH_ALLOW_MANIFEST_DRIFT=1`, disabling the on-chain-hash/manifest-drift safeguard (the exact check that catches authz/signature desync) on the automated path.
- **Evidence:** Lines verified; in-code rationale at `:250-255` ("pre-pack hook auto-bumps on every pack … manifest pin no longer matches"). Note: `ship-changes.sh` does **not** itself force-push (delegates to Makefile) and has no `checkout FETCH_HEAD` — corrected from wave-1.
- **Remediation:** Gate the overrides behind an explicit opt-in flag rather than always-on; require manifest drift to be re-reconciled (re-ceremony / reseat) rather than waved through; keep the manifest-drift gate fail-by-default on the loop.
- **Depends on:** K28

---

**K11** · `[FIX]` · **Assert no unpushed commits before `ship-changes` hard-resets shipped submodules** — `PARTIAL`

- **Target:** `scripts/ship-changes.sh:362`, `:370` (`git reset --hard origin/publish`)
- **Rationale:** The hard-reset to `origin/publish` discards any locally-regenerated-but-unpushed real RELEASE.json when the upstream publish push lagged or failed — the data-loss window for real attestations.
- **Evidence:** Line 362 `git fetch origin publish && git reset --hard origin/publish`; no `git checkout FETCH_HEAD` exists (wave-1 overstated). Loss window is the lagged-push case.
- **Remediation:** Before reset, assert `git rev-list origin/publish..HEAD` is empty (no unpushed commits ahead) and abort/skip otherwise, so a locally-regenerated attestation is never silently discarded.
- **Depends on:** —

---

**K12** · `[CONSOLIDATE]` · **Consolidate to ONE Squads ceremony identity (core-app-team 3-of-4) and one appHash recipe** — `CONFIRMED`

- **Target:** `scripts/pearl-app-ceremony.sh` (core-app-team `4sPNmdcSz...`), `scripts/pearl-ceremony.sh` (foundation `9X5E.../5Smc...`), `pearl-batch-submit.sh` signers
- **Rationale:** Two ceremony generations sign with different keys, multisigs and vaults, and two appHash recipes (SPK-bytes vs dir-tree) can never agree, so `quorumPolicy`/vault fields and `appHash` disagree across apps and with the verifier's single-trust-root claim.
- **Evidence:** `pearl-app-ceremony` uses `4sPNmdcSz.../3jfN9rcS...` 3-of-4; `pearl-ceremony` uses `9X5ECjTM.../5SmcSBsuaa...` 2-of-4; stub uses SPK-sha256 while ceremony uses `pearl-tool compute-app-hash` dir-tree.
- **Remediation:** Declare core-app-team 3-of-4 (`4sPNmdcSz...`) as the only authority; retire `pearl-ceremony.sh`/`welcome-pearl-ceremony.sh` signing config; standardize `appHash` to the recipe the verifier documents and that build-store will assert (K13).
- **Depends on:** K07, K13

---

**K14** · `[FIX]` · **Gate the build on signed-version == published-version (6 apps disagree)** — `CONFIRMED`

- **Target:** `build-store.sh` `EMBEDDED_KEYS` list (~`:767`) which omits `version`
- **Rationale:** The drift assertion compares attest fields but not `version`, so an app can publish a newer version attested by an older signature (stale attestation reused for a newer package).
- **Evidence:** cca.sh Wholesale index `0.2.4` vs RELEASE `0.1.0`; cca.sh Config `0.0.24` vs `0.0.22`; cca.sh Organization `0.1.3` vs `0.1.0`; BLOOM `1.0.2-kb6` vs `0.1.0`; MerMail `0.4.8` vs `0.4.7`; Vintage Remote Desktop has no version field at all.
- **Remediation:** Add `version` to the publish-time cross-check and FAIL when `index.version != RELEASE.json.version`; require a fresh ceremony when the version changes rather than reusing the old attestation.
- **Depends on:** K13

---

**K15** · `[FIX]` · **Read `MasterNftMint` case-insensitively; 17 apps silently lose their real on-chain mint in the index** — `PARTIAL`

- **Target:** `build-store.sh:483` (`release.get('MasterNftMint','')`), also `:768` and `scripts/catalog-doctor.sh:154`
- **Rationale:** 17 RELEASE.json files use lowercase `masterNftMint` (15 carry the real mint `B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe`) while build-store reads only uppercase, so the index publishes an empty mint — the catalog lacks the on-chain lookup key for genuinely-attested apps.
- **Evidence:** Count is 17 not 16; in-repo generators all emit UPPERCASE (the wave-1 "generators disagree" framing is inverted) — the lowercase files come from the older Pearl on-chain ceremony. 17 index entries have `attest.MasterNftMint==''`.
- **Remediation:** Change reads to `release.get('MasterNftMint') or release.get('masterNftMint') or ''` at `build-store.sh:483/:768` and `catalog-doctor.sh:154`; canonicalize the schema to one casing and back-fill the 17 files; add a doctor check that fails when index mint is empty but RELEASE.json has a mint under any casing.
- **Depends on:** K06

---

**K16** · `[FIX]` · **Reject unsigned/legacy RELEASE.json schema variants at publish (Vintage Remote Desktop ships with NO attestation)** — `CONFIRMED`

- **Target:** `build-store.sh` `validate_release_attestation` (~`:183-269`, `:520` blesses `schemaVersion=1`)
- **Rationale:** Three incompatible RELEASE.json schemas coexist; build-store blesses `schemaVersion=1` "mode: offline" with no version/releaseHash/authorSig/quorum, so a fully unsigned app ships and its index attest block is all empty strings.
- **Evidence:** `dist-publish/attest/yea96s13.../RELEASE.json` has no signature fields; `build-store.sh:520` prints ok for `schemaVersion=1`.
- **Remediation:** Require a single canonical schema (`melusina-release-v1` with non-empty base64 `authorSig` and `threshold>=2`) and FAIL on `schemaVersion=1`/empty-attest unless explicitly waived; re-attest Vintage Remote Desktop.
- **Depends on:** K03

---

**K17** · `[FIX]` · **Restore the on-chain RELEASE.json verification gutted out of `build-store.sh` (or amend the docs that claim it runs)** — `CONFIRMED`

- **Target:** `build-store.sh` `validate_release_attestation` (~`:183-265`)
- **Rationale:** On-chain verification (`melusina-pearl-tool verify-release`) and the `MELUSINA_ATTEST_OFFLINE`/`REJECT_STUBS` env handling were removed; the validator is now pure schema `jq`, so nothing ties a published attestation to the chain — while README/PEARL-FLEET/MELUSINA-ATTEST-KILL-LIST still document it as mandatory.
- **Evidence:** grep for `pearl-tool`/`verify-release`/`ATTEST_OFFLINE`/`REJECT_STUBS` in `build-store.sh` = 0; `HANDOFF.md:344` self-documents "verify_release call site bypasses the env check".
- **Remediation:** Re-invoke `melusina-pearl-tool verify-release` in `validate_release_attestation` and honor `MELUSINA_ATTEST_OFFLINE`/`REJECT_STUBS`, **or** formally amend `README.md:113/142/147` + `MELUSINA-ATTEST-KILL-LIST.md:832` to stop claiming a verification that does not run. Pair with K13 so local `sha256` binding is enforced regardless.
- **Depends on:** K13

---

**K18** · `[FIX]` · **Stop publishing from dirty uncommitted submodule working trees; require committed state** — `CONFIRMED`

- **Target:** `build-store.sh` (reads committed index but copies working-tree SPK/attest); 20 dirty submodules
- **Rationale:** The catalog is assembled from dirty trees so staged real bumps are silently dropped (popaye v56 stall) while uncommitted real attestations are one refresh from destruction; the build trusts working-tree files for attest but committed state for the index, guaranteeing mismatch.
- **Evidence:** 20 dirty submodules, 17 stashes; `versionNumber` gaps MLSNA 57→60, namedcoin 7→11; popaye v56 was uncommitted and invisible to build-store (FLEET idx 767).
- **Remediation:** Make the publish entry point FAIL if any catalog submodule has uncommitted RELEASE.json/metadata/app.spk content; commit-and-push real attestations before building; build from committed state only.
- **Depends on:** K05

---

**K19** · `[FIX]` · **Make refresh non-destructive of unpushed real attestations** — `CONFIRMED`

- **Target:** `build-store.sh:108-123`, `Makefile refresh:86-100`, `scripts/refresh-submodules.sh:18`, `scripts/sync-catalog.sh:56-69` (all `checkout FETCH_HEAD` / `reset --hard`)
- **Rationale:** Three+ independent implementations of submodule refresh discard locally-regenerated RELEASE.json/metadata that was never pushed upstream — the mechanism that regresses namedcoin/MLSNA to stubs.
- **Evidence:** Four refresh implementations confirmed; `checkout FETCH_HEAD` with stderr suppressed; detached HEADs across the catalog submodules.
- **Remediation:** Collapse to ONE refresh implementation that refuses to discard dirty content (abort if working tree differs from the fetched tip in attest/metadata); delete `scripts/refresh-submodules.sh` (callerless legacy). Pair with K18.
- **Depends on:** K18

---

**K20** · `[CONSOLIDATE]` · **Define ONE publish entry point; demote ship-changes/publish-apps/sync-catalog to wrappers around it** — `CONFIRMED`

- **Target:** `Makefile publish` (`Makefile:336`), `scripts/ship-changes.sh`, `scripts/publish-app-full.sh`, `scripts/publish-apps.sh`, `scripts/sync-catalog.sh`
- **Rationale:** Multiple independently-triggered drivers each rebuild the catalog and force-push; with no single owner, a manual `make publish`, the 7-min loop, and a per-app driver race the same files.
- **Evidence:** Entry points verified; `ship-changes`/`sync-catalog` both drive `make plan`/`apply`.
- **Remediation:** Declare catalog `make publish` (refresh → `build-store --no-refresh` → plan → apply under the lock) the single human driver; rewrite `ship-changes.sh`/`sync-catalog.sh`/`publish-apps.sh` to call it (not re-implement plan/apply) and to acquire the shared lock (K08).
- **Depends on:** K08

---

**K21** · `[FIX]` · **Replace orphan-force-push full-replace with additive/merge publish to stop wholesale-clobber and dropped-publish races** — `CONFIRMED`

- **Target:** `Makefile apply` orphan-commit lane (`:268-275`, `:303`, `:309`); `build-store.sh` non-idempotent full-reassembly (`:598 rm -rf`)
- **Rationale:** Apply rebuilds an orphan snapshot from `main` and force-pushes, wholesale-replacing the remote tree; any host with a partial `packages/` shrinks the live catalog, and a worktree-stacked publish chain (cyberteller/ccashconfig) gets silently reverted.
- **Evidence:** 2026-04-25 dropped 4 apps; dangling `/tmp/store-wt` 8-commit chain reverted cca.sh Config `0.0.26→0.0.24`.
- **Remediation:** Either build the catalog by merging with the live tree (no orphan full-replace) or add a fail-closed shrink gate (publish must not drop apps without `MELUSINA_PUBLISH_SHRINK_OK`); ensure plan/apply operate on committed state only.
- **Depends on:** K18, K20

---

**K22** · `[INVESTIGATE]` · **Reconcile and commit the 20 dirty submodules (RELEASE.json/metadata/changelog) before the next build** — `CONFIRMED`

- **Target:** `packages/hrbrlife/{MLSNA_token, melusina-namedcoin-app, MELUSINA_BOTMOTHER, the 17 others}` working trees
- **Rationale:** Uncommitted real attestations, half-finished bumps (BotMother metadata v1.1.3 vs signed v1.1.2), and key-case/em-dash ping-pong sit in 20 trees; the next `make publish` ships whatever state they happen to be in.
- **Evidence:** 20 dirty submodules now; BotMother `metadata.json` modified only; consilium/jinn/openclaw show `masterNftMint→MasterNftMint` flips.
- **Remediation:** Per-app triage: commit real attestations (K05), discard stub/serializer-noise edits, re-run ceremony for half-finished bumps; then build from clean committed state.
- **Depends on:** K18

---

**K26** · `[FIX]` · **Authenticate or loopback-bind the admin-server rollback API and require the admin token** — `CONFIRMED`

- **Target:** `scripts/admin-server.py:46-52`, `:194-196`, CORS `*`
- **Rationale:** The runtime publish-branch controller is unauthenticated by default (token optional) with wildcard CORS; any reachable caller can trigger a live force-push rollback.
- **Evidence:** `_check_auth` returns True when `MELUSINA_ADMIN_TOKEN` unset; `main()` only warns; CORS `Access-Control-Allow-Origin '*'`.
- **Remediation:** Make `MELUSINA_ADMIN_TOKEN` mandatory (fail-closed/refuse to start without it); bind `127.0.0.1`; remove wildcard CORS. Combine with K09's lock+gate routing.
- **Depends on:** K09

---

### P2 — backfill integrity, de-duplicate tooling, hygiene

---

**K23** · `[FIX]` · **Add a changelog/release-notes field to the catalog schema and stop clobbering version history** — `CONFIRMED`

- **Target:** `build-store.sh` (no changelog field), `src/main.jsx` hardcoded `APP_VERSIONS` maps, per-app `changelog.md`
- **Rationale:** No changelog data exists in the published store; rapid multi-controller same-day rebuilds (cyberteller `0.1.51→0.1.57`) make "what changed" unreconstructible and appId rotations orphan the hardcoded frontend maps.
- **Evidence:** grep `changelog` across `dist-publish`/`index.json`/`build-store.sh`/`scripts` = 0; `PUBLISH_QC.md:11` maps keyed by appId.
- **Remediation:** Emit a `changelog` field from each app's `changelog.md` into `apps/index.json`; generate the frontend maps from catalog data rather than hand-maintaining them keyed by appId.
- **Depends on:** K20

---

**K27** · `[KILL]` · **Delete residual PGP keyrings/pubkeys that violate the zero-PGP policy** — `CONFIRMED`

- **Target:** `packages/hrbrlife/{MELUSINA_BOTMOTHER,INSTASYS_MAIL,MiniGit}/author.pgp.pub`; `packages/hrbrlife/Melusina/sandstorm/keys/release-keyring.gpg`
- **Rationale:** The Janeway zero-PGP-surface kill held for `.asc` but `author.pgp.pub` files and a release keyring survive in shipping publish trees, contradicting `README.md:113` and the kill-list acceptance criteria.
- **Evidence:** `find` confirms 3× `author.pgp.pub` + `release-keyring.gpg` present.
- **Remediation:** Delete the 3 `author.pgp.pub` and the `release-keyring.gpg`; add a CI grep-fail for gpg/pgp/gnupg surface in pack/publish.
- **Depends on:** K25

---

**K28** · `[CONSOLIDATE]` · **Eliminate the byte-identical `build-store` / `build-store.sh` twins** — `CONFIRMED`

- **Target:** `build-store` and `build-store.sh` (42729 bytes each, identical)
- **Rationale:** Two copies of the catalog assembler must be patched in lockstep; a single-file patch silently forks the validator — the exact admin-store fork-and-drift failure reproduced in one repo.
- **Evidence:** `cmp` → IDENTICAL; `536547ba` patched both.
- **Remediation:** Keep one file; make the other a symlink or thin shim that execs it; remove the duplicate from git.
- **Depends on:** —

---

**K29** · `[INVESTIGATE]` · **Resolve the second catalog (melusina-admin-store) publishing overlapping apps at conflicting versions** — `PARTIAL`

- **Target:** `store-rebuild/melusina-admin-store` (origin `melusina-admin-store.git`) vs `static_store`
- **Rationale:** A separate full build tree publishes to a different prod repo and overlaps `static_store` on NamedCoin Admin (`0.1.13` vs `0.1.0`) and Shell Tester (`0.1.5` vs `0.1.6`); whichever publishes last defines that app's version on its channel.
- **Evidence:** `melusina-admin-store` has its own `build-store.sh`/`Makefile`/`dist-publish`; POSTMORTEM follow-up #1 unresolved.
- **Remediation:** Declare one authoritative catalog per app; if both must exist, partition app ownership so no app is published by both, and document it. **NOTE:** the wave-1 "second static_store CHECKOUT force-push race" claim was REFUTED — `/home/user/Desktop/Melusina/static_store` is a gitignored non-checkout with no push path; do not action that.
- **Depends on:** K20

---

**K31** · `[QUARANTINE]` · **Remove do-not-reintroduce apps and Riker test builds that reached production** — `CONFIRMED`

- **Target:** `packages/hrbrlife/{teleport, melusina-bloom-app, INSTASYS_MAIL}`; `riker-test-deploys/` (DueProcess v2, ccash Domain Template v2)
- **Rationale:** Apps explicitly listed do-not-reintroduce (Teleport, BLOOM, INSTASYS_MAIL) are back and shipping, and in-tree Riker test builds are indistinguishable to build-store and got published into the live catalog.
- **Evidence:** `apps/index.json` contains BLOOM Identity + Teleport with attest present; riker `dueprocess`/`ccash_domain` appIds present in catalog.
- **Remediation:** Remove the dirs and catalog entries (or get a documented exception); add a defer/archive roster check in the publish gate so killed apps cannot re-enter.
- **Depends on:** K20

---

**K32** · `[FIX]` · **Reconcile gh-pages version skew and the orphan ccashconfig binary; add publish-time invariants** — `CONFIRMED`

- **Target:** gh-pages: `packages/189fb6d73ada49bceeaf19f9b109cefc`, `apps/index.json` (cca.sh Config), `attest/6gdgveudr.../RELEASE.json`
- **Rationale:** Three versions of cca.sh Config are live simultaneously (binary `v0.0.26` unreferenced, index `v0.0.24`, signed attest `v0.0.22`) because a binary-only hot-push to gh-pages bypassed the catalog build; index-vs-attest was already skewed before the push.
- **Evidence:** `989c23f7` added only the 11MB binary; index points at `c547f1ce` (`0.0.24`); attest says `0.0.22`; zero references to `189fb6d7`.
- **Remediation:** Decide the live version and make all three agree (regenerate index + re-sign attest, or delete the orphan binary); add publish-time invariants that fail if `index.version != attest.version` or any `packages/*` blob is unreferenced by index. Stop out-of-band `/tmp/ghp` hot-pushes.
- **Depends on:** K14

---

**K33** · `[FIX]` · **Clean up abandoned worktrees, stashes, dangling commits and the stale lock** — `PARTIAL`

- **Target:** `/tmp/store-wt` (orphan publish chain), `/tmp/ghp`, 17 stashes, 641 dangling commits, `.publish.lock` (0 bytes Jun 10)
- **Rationale:** Partial/abandoned publish state accumulates because the pipeline uses worktrees + stash-juggling instead of atomic commits; the stale empty lock gives a false sense of serialization while a write ran on gh-pages today.
- **Evidence:** 3 worktrees, 17 stashes, `.publish.lock` 0 bytes. Correction: store-wt chain is worktree-pinned (not gc-dangling); the full declared submodule set, not an earlier partial inventory, has dirty content rather than SHA drift.
- **Remediation:** `git worktree remove /tmp/store-wt` + prune after capturing/dropping its chain; stop `/tmp/ghp` out-of-band gh-pages writes (route through K20); triage+clear stashes; gc dangling commits after review; make `.publish.lock` real (K08) or remove it.
- **Depends on:** K08, K20

---

### P3 — doc reconciliation, dormant/orthogonal cleanup

---

**K30** · `[FIX]` · **Reconcile the three-way doc contradiction on entry point and the auto-bump contract** — `PARTIAL`

- **Target:** `README.md:25-39/:86`, `PUBLISH_QC.md:281-296`, `SHIP-IT.md:9-14/:324`, `GREENFIELD_READY_2026_05_18.md:90-101`
- **Rationale:** README says `make pack` auto-bumps; PUBLISH_QC and SHIP-IT say it must not; the code (`ship-changes.sh:251` pre-pack hook) proves it *does* — a real same-layer contradiction. Greenfield's per-app auto-dispatch is self-admittedly inactive and describes wiring absent from this repo.
- **Evidence:** Auto-bump contradiction CONFIRMED; entry-point half is un-reconciled layers, not 3 competing definitions. `ship-changes.sh` has no `--only`/flock that GREENFIELD's hooks invoke.
- **Remediation:** Declare README/PUBLISH_QC catalog `make publish` canonical, document `ship-changes.sh` as a thin wrapper; fix the auto-bump sentence to match the code (pack auto-bumps) or remove the hook and fix README; banner GREENFIELD as unactivated future state.
- **Depends on:** K20

---

**K34** · `[FIX]` · **Resolve the update-channel split-brain (`latest.json` build4 vs `manifest.json` build13)** — `PARTIAL`

- **Target:** `update/latest.json`, `update/manifest.json`, `update/dev`, `update/stable`
- **Rationale:** `latest.json` is a writer-less vestigial sidecar frozen at build 4 while the live channel (dev/stable/manifest) advanced to build 13; latent audit-confusion, **not** a live client downgrade (installer reads dev/stable, not latest.json).
- **Evidence:** `latest.json` build 4 (2026-03-08), `manifest.json` build 13; dev/stable both 13; no in-repo writer of `latest.json`; installer fetches dev/stable. Severity P2→P3 (dormant).
- **Remediation:** Either delete `update/latest.json` (nothing consumes it) or have build-store generate it from the same source as dev/stable/manifest; add a catalog-doctor check asserting `latest.json.build == manifest.json.build == cat(dev) == cat(stable)`.
- **Depends on:** —

---

**K35** · `[QUARANTINE]` · **Move runtime/update-client failures to a separate bucket — they are NOT store-publish drift** — `CONFIRMED`

- **Target:** `melusina-squads-watcher` (43k+ restart loop), `melusina-recover`, `melusina-update-checker` (203/EXEC), `melusina-authzsign`/`authz-relay` (inactive)
- **Rationale:** These are VM-side/runtime-authz and update-consumer concerns structurally separate from host-side store-publish; publishes kept landing while these were down. They must not pad or mask the publish-drift kill list.
- **Evidence:** squads-watcher `NRestarts 43941+` (mkdir perms), update-checker 203/EXEC every 6h (missing venv + missing tool + nonexistent `verify-release-allowed` subcommand), authzsign inactive — all orthogonal to publishing.
- **Remediation:** Track in a separate "runtime-authz / update-client health" bucket: fix squads-watcher state-dir perms, disable-or-fix update-checker (restore venv/tool/subcommand/field), decide intent on authzsign/recover. Do not block the publish-pipeline fix on these.
- **Depends on:** —

---

## Target architecture — the single driver

**One entry point.** Catalog `make publish` (`Makefile:336`) runs exactly: `refresh → build-store.sh --no-refresh → make plan → make apply`, the whole thing wrapped in `scripts/with-publish-lock.sh` acquiring `flock -w 600` on `.publish.lock`. Every other path becomes a wrapper around this single driver or read-only: `ship-changes.sh`, `publish-apps.sh`, `publish-app-full.sh`, and `sync-catalog.sh --deploy` must **call** `make publish` (not re-implement plan/apply) and acquire the same lock. The admin rollback API, `rollback-all.sh`, and `_rollback.py` route their force-push through the same lock **and** the Makefile remote-drift gate, and require `MELUSINA_ADMIN_TOKEN`. `/tmp/ghp` out-of-band gh-pages writes and the `/tmp/store-wt` worktree are removed.

**One writer per artifact.**

| Artifact | Single writer / rule |
|----------|----------------------|
| **RELEASE.json** | Exactly one promote-to-catalog helper writes `packages/hrbrlife/<repo>/<slug>/RELEASE.json`, invoked once at the end of `make publish`. The single canonical ceremony driver (`scripts/pearl-app-ceremony.sh` against the core-app-team 3-of-4 Squads `4sPNmdcSz...`) emits only to `/tmp OUTPUT_DIR`. `pearl-ceremony.sh`, `welcome-pearl-ceremony.sh`, and the offline-stub generator are deleted/quarantined; `release-json-stub-fallback` is gone. `COPY_TO_CATALOG` defaults to `0`. |
| **On-chain ReleaseEntry** | The content-addressed create-only PDA is correct as-is (**not** a drift bug — the wave-1 "drifts every loop" claim was refuted). The only fix: `build-store.sh` must re-attest when a version/SPK changes rather than reuse a stale attestation. |
| **version** | Bumped in exactly one place (operator-set `metadata.json` **or** the pre-pack hook, but not both — pick one and make the docs match). build-store FAILS if signed version != index version. |
| **updatedAt** | Derived solely from `RELEASE.json signedAtUnix`, which must come from a real signing event, never SPK mtime. |
| **manifest (index/appHash)** | build-store recomputes `sha256(app.spk)` and FAILS unless it equals `RELEASE.json.appHash`, reads `MasterNftMint` case-insensitively, and rejects stub/legacy schemas (fail-closed; `MELUSINA_ATTEST_REJECT_STUBS=1` default, on-chain `verify-release` restored). |
| **gh-pages deploy** | Written only by `make apply` under the lock; either additive/merge or guarded by a fail-closed shrink gate so a partial tree cannot wholesale-replace the live catalog. |

**Locking / serialization.** `.publish.lock` becomes a real `flock` held by **every** writer (publish, rollback, sync, ship loop, external hooks) for the full duration of plan+apply, so concurrent publishes and rollbacks cannot interleave. The build operates on **committed state only** and FAILS if any catalog submodule has uncommitted RELEASE.json/metadata/app.spk; the single refresh implementation refuses to discard dirty content.

**Demoted to read-only or deleted.**

- **Collapsed to one file:** `build-store` duplicate → symlink/shim of `build-store.sh`.
- **Deleted:** `scripts/refresh-submodules.sh`, `scripts/pearl-ceremony.sh`, `scripts/welcome-pearl-ceremony.sh`, `scripts/release-json-stub-fallback`.
- **Quarantined:** do-not-reintroduce apps (Teleport, BLOOM, INSTASYS_MAIL) and `riker-test-deploys/`.
- **Partitioned:** the second `admin-store` catalog gets disjoint app ownership.
- **Security preconditions:** `offline-sign-server` bound to loopback with auth; the Melusina secret-bearing submodule unbound and its keys rotated; residual PGP surface deleted.
- **Separate bucket:** the runtime-authz/update-client failures (K35) are tracked off the publish-pipeline critical path.

## Execution order

Sequenced as stop-the-bleeding → de-duplicate writers → backfill integrity. Each step notes its dependencies.

1. **K24** — Stop/relock the unauthenticated `offline-sign-server` on `0.0.0.0:3848`. *(no deps; signing oracle is wide open right now)*
2. **K25** — Unbind the secret-bearing Melusina submodule and rotate every leaked key. *(no deps; do before any history purge)* → then **K27** (delete residual PGP surface; depends on K25).
3. **K02** — Delete/quarantine the `release-json-stub-fallback` generator and its copies; remove its invocations. *(no deps; stops new forgeries)*
4. **K04** — If the stub survives in any form, stop sourcing `signedAtUnix` from SPK mtime. *(depends K02)*
5. **K03** — Make the publish lane fail-closed on stubs; fix the vacuously-true detector; default `REJECT_STUBS=1`. *(no deps)*
6. **K05** — Commit namedcoin's real v0.1.9 attestation before a refresh destroys it. *(depends K18 — guard refresh first or freeze refresh during the commit)*
7. **K18** — Require committed submodule state; FAIL on uncommitted RELEASE.json/metadata/app.spk. *(depends K05 for namedcoin specifically; in practice land the K05 commit, then turn on K18)* → **K19** non-destructive refresh (depends K18) → **K22** reconcile/commit the dirty submodules (depends K18).
8. **K13** — Gate the build on `sha256(app.spk)==appHash`; quarantine the 34 failing apps. *(depends K06)*
9. **K01** — Restore popaye's real 3-of-4 attestation and republish. *(depends K02, K13)*
10. **K08** — Add the real `flock` (`with-publish-lock.sh`) on every force-push site. *(no deps; serialization foundation)* → **K09** route rollbacks through the lock+gate (depends K08) → **K26** make the admin token mandatory + loopback-bind (depends K09).
11. **K06** — Collapse to one RELEASE.json writer. *(depends K02)* → **K07** quarantine `pearl-ceremony.sh` (depends K06) → **K12** one Squads identity + one appHash recipe (depends K07, K13).
12. **K20** — Declare one publish entry point; demote others to wrappers on the shared lock. *(depends K08)* → **K21** additive/merge or shrink-gated apply (depends K18, K20).
13. **K10** — Stop the loop hardcoding the safety-gate overrides. *(depends K28)* — **K11** assert no unpushed commits before hard-reset *(no deps; land alongside the loop fixes)*.
14. **Integrity backfill on the index:** **K14** signed-version == published-version (depends K13); **K15** case-insensitive `MasterNftMint` (depends K06); **K16** reject unsigned/legacy schemas (depends K03); **K17** restore on-chain `verify-release` or amend the docs (depends K13).
15. **De-duplicate tooling / hygiene:** **K28** collapse the build-store twins *(no deps)*; **K29** partition the admin-store catalog (depends K20); **K31** quarantine do-not-reintroduce + riker builds (depends K20); **K23** add changelog field (depends K20); **K32** reconcile gh-pages skew + invariants (depends K14); **K33** clean worktrees/stashes/dangling/lock (depends K08, K20).
16. **Doc + dormant + orthogonal:** **K30** reconcile the auto-bump/entry-point docs (depends K20); **K34** resolve the update-channel split-brain *(no deps; dormant)*; **K35** move runtime/update-client failures to a separate bucket *(no deps; do not block the pipeline fix on these)*.

**Critical-path dependency notes.** K05 ↔ K18 are mutually entangled (commit the real attestation, *then* enforce committed-only / guard refresh) — sequence K05's commit before flipping K18 on, but guard the refresh (K19) so the commit window is safe. K13 gates K01, K14, and K17, so the hash gate must land before the popaye restore and the version/on-chain backfills. K08 (the lock) is the prerequisite for K09, K20, K21, K26, and K33 — land it early in the writer-consolidation wave.

## Open questions

1. **Stub survival (K04, K03).** Is an interim offline-sign mode genuinely required? If yes, K04's `signedAtUnix` derivation and K03's `MELUSINA_ATTEST_OFFLINE` waiver must be specified; if no, K02 deletes the stub outright and both become moot.
2. **Version-bump owner (K30, target arch).** The version must be bumped in exactly one place — operator-set `metadata.json` **or** the pre-pack hook. Which one is canonical? README/PUBLISH_QC/SHIP-IT currently contradict each other and the code; this must be decided before the docs can be reconciled.
3. **On-chain verification vs docs (K17).** Re-invoke `melusina-pearl-tool verify-release`, or formally amend the docs to stop claiming a verification that does not run? The choice depends on whether the pearl-tool path is operationally available on the publish host.
4. **Two-catalog ownership (K29).** If both `static_store` and `melusina-admin-store` must coexist, the disjoint per-app ownership partition is undefined — who owns NamedCoin Admin and Shell Tester? (The wave-1 "second `static_store` checkout force-push race" is refuted and out of scope.)
5. **appHash recipe (K12, K13).** The verifier documents the raw-SPK recipe (`verifier/index.html:99`) and 9 apps pass it, but the ceremony path uses a dir-tree hash. Confirm raw-SPK is the single canonical recipe before regenerating the 34 failing RELEASE.json against it.
