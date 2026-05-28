# pearl Fleet Kill-List — MVP

Greenfield plan to put the full Melusina app + sidecar fleet through the
Squads-cosigned ReleaseEntry ceremony, rebuild both stores, and publish
every artifact with on-chain attestation.

Authored 2026-04-23. Every fact in the **State Snapshot** below is
checkable against the working tree and RPC today. When this document is
next read, its **first action** is re-verifying the snapshot — any drift
invalidates downstream phase gates.

---

## 0. State Snapshot (as of 2026-04-23; re-verified 2026-04-23)

| Item | Value |
|---|---|
| License-registry program source | patched (attestation.rs line 586–609 still enforces `master_nft_ata.owner == authority` — blocks Squads custody) |
| License-registry deployed program ID (devnet) | `BSENx6t1GVPzhnnd4yiojxWk7HjKZiiRQEkriHg6Mpix` — `Solana program show -u devnet` verifies ProgramData `FzWmii4kH7Qqe4UjsFFyaN23pkBxTHdWkWM1TZbCZTpX`, last deployed slot `456342456`; this is **pre-Phase-0.1 source** until redeployed |
| Squads multisig (Core App Team) | **not minted**; `melusina-attestdeployer-tool/docs/devnet-state.md` is absent |
| Core App Team wallets | 4 keypairs under `Melusina/test-wallets/core-app-team/`, all **0 SOL devnet** |
| `melusina-pearl-tool` | v0.1.0-scaffold (commit `05a56a6`, private repo `hrbrlife/melusina-attestdeployer-tool`); **not installed on PATH** (`go run ./cmd/melusina-pearl-tool version` prints `0.1.0-scaffold`) |
| → `compute-app-hash` | **works** (deterministic SHA-256 walk, 5 passing tests) |
| → `version` | works |
| → `propose-release` | **stub** — returns `Squads v4 client wiring pending` |
| → `finalize-release` | **stub** — returns `on-chain ReleaseEntry readback pending` |
| → `verify-release` | **stub** — returns `on-chain ReleaseEntry verification pending` |
| `melusina-spkmodule-component` | `main` at `cac4d67`, zero GPG residue, hooks + `mk/pearl.mk` + `bin/spk-verify-strict` all greenfield |
| `melusina-attest` Go tests | pass |
| `melusina-attest` Py / TS tests | env not set up (runners present) |
| Public store apps (`static_store/packages/hrbrlife/`) | 23 shipping, 0 with `RELEASE.json`, 23 carry legacy `metadata.json.asc` |
| Admin store apps (`store-rebuild/melusina-admin-store/packages/hrbrlife/`) | 6 shipping, 0 with `RELEASE.json`, 5 carry legacy `.asc` |
| Sidecars (`Melusina/sidecar/`) | 8 deployable, 0 with `RELEASE.json`, no `sidecar.mk` exists |
| Public-store `build-store.sh` | ReleaseEntry-required, rejects `.asc`, delegates to `melusina-pearl-tool verify-release`; `./build-store.sh --dry-run` fails 23/23 until `RELEASE.json` exists and `.asc` is gone |
| Admin-store `build-store.sh` | diverged 654-line fork, `validate_release_attestation` removed, no `.asc` rejection, no tool integration; `./build-store.sh --dry-run` currently passes 6/6 because it does not check ReleaseEntry attestations |
| `acceptUnattestedSPKs` shell kill-switch | still live — removing it today bricks every currently-installed pearl |

**Fleet total: 37 components. Fleet migrated: 0/37. Proposals executed: 0.**

---

## 1. Scope

### In-scope (MVP)

- Land a devnet-deployed `license-registry` that accepts Squads-vault custody for `RegisterReleaseEntry`.
- Finish the three stubbed `melusina-pearl-tool` subcommands (`propose-release`, `finalize-release`, `verify-release`).
- Mint the Core App Team Squads multisig on devnet. Fund all four wallets.
- Port `melusina-admin-store/build-store.sh` to the greenfield ReleaseEntry-verify path.
- Take **one pilot app** end-to-end through the ceremony and verify both stores catalog it correctly.
- Take all **23 public-store** apps through the ceremony and rebuild the public catalog.
- Take all **6 admin-store** apps through the ceremony and rebuild the admin catalog.
- Author `mk/sidecar.mk` in `melusina-spkmodule-component`. Take all **8 sidecars** through the sidecar-flavoured ceremony.
- Publish both rebuilt stores. Every app in both catalogs must have a finalized `RELEASE.json` referencing a verifiable on-chain `ReleaseEntry`.

### Explicit non-goals

- Mainnet cutover.
- Removing the `acceptUnattestedSPKs` shell kill-switch (last-mile post-MVP; done in a follow-up sweep).
- Deleting legacy `metadata.json.asc` from existing per-app publish branches (cosmetic; post-MVP).
- Rewriting the 11 attestation PDAs or introducing new ones (`GlobalAppApproval` / `LocalAppApproval` are not in the program — see §2).
- Backfilling real `slug` / `developer` fields into metadata (`N/A` is tolerated; catalog derives from dir paths).
- npm / PyPI publishes of `notify-sandstorm`, `identity-gate-py`, `pearl-auth` language ports.
- Cross-machine `pearl-restore` portability.
- pearl-auth v0.3 envelope migration unless a named sidecar depends on it (see §8 risks).
- Creating new apps / minting Master NFTs for apps not already in the registry.

### Deferred apps honored by absence

`waikiki`, `Teleport` (`melusina_teleport2`), `INSTASYS_CHAT`, `Gogs`, `BLOOM.Community KYC`: none of these directories exist under either store's `packages/`. The defer list is satisfied by omission, not by explicit exception. Do not reintroduce them in this iteration.

---

## 2. Melusina-Approval Model — single-gate decision

**"Melusina approval for each" = Squads cosigner quorum on the Core App Team multisig executing `register_release_entry`.** One gate, not two.

Rationale:
- `license-registry/state/attestation.rs` defines 11 attestation PDAs. `GlobalAppApproval` and `LocalAppApproval` are **not among them** — adding them is out of MVP scope.
- `RELEASE.json.quorumPolicy.multisigPda` is a single Pubkey; the schema carries one quorum, not two.
- `ReleaseEntry.publisher_squads_vault` is a single Pubkey. The ed25519 `authorSig` verified inside `handler_register_release_entry` is produced exactly once — when the Squads threshold executes the vault transaction.
- The alternative reading (separate foundation Master-NFT signoff after Squads quorum) collapses to the same thing because Master-NFT custody **is** the Squads vault (MELUSINA-ATTEST-DESIGN §10.9). A second gate would require a second PDA and a second instruction; neither exists.

Record this decision in `melusina_solana_dev-license104/docs/attestation-model.md` so future conversations do not reopen it without a code change.

---

## 3. Phases

Six phases. Each has a single gating acceptance criterion; no phase starts until the previous phase's criterion is checkable-true.

### Phase 0 — Prerequisite Infra

| # | Task | Where | Done-when |
|---|---|---|---|
| 0.1 | Relax `master_nft_ata.owner` check in `RegisterReleaseEntry` to accept Squads-vault custody (vault PDA owns the ATA; `authority` is the Squads-executed proxy) | `license-registry/src/instructions/attestation.rs:586–609` | `cargo check -p license-registry` passes; unit test covers both legacy-author-owner-reject and Squads-vault-accept |
| 0.2 | Deploy patched program to devnet | `melusina_solana_dev-license104/` | program ID recorded in `docs/devnet.md`; `Solana program show <id>` returns the new hash |
| 0.3 | Implement `propose-release` in pearl-tool | `melusina-attestdeployer-tool/internal/commands/proposerelease.go` | dry-run against devnet produces a proposal PDA; `go test ./...` includes a happy-path integration test marked `short` skippable |
| 0.4 | Implement `finalize-release` in pearl-tool | `.../finalizerelease.go` | polls proposal; on Executed, reads ReleaseEntry and rewrites `RELEASE.json`; reruns `apphash.Compute` and aborts `RELEASE_BINDING_DRIFT` on mismatch; unit test asserts both happy-path and drift-reject |
| 0.5 | Implement `verify-release` in pearl-tool | `.../verifyrelease.go` | given a finalized `RELEASE.json`, fetches the PDA, verifies appHash + authorSig; returns 0/non-zero; unit test covers both cases |
| 0.6 | Mint Core App Team Squads multisig on devnet | script in `melusina-attestdeployer-tool/scripts/mint-multisig.sh` (new) | multisig PDA + vault address committed to `hrbrlife/melusina-attestdeployer-tool` config; quorum 3-of-4 recorded |
| 0.7 | Fund all four Core App Team wallets | `Solana airdrop` against devnet (or Helius airdrop if 429) | each wallet ≥ 2 SOL; `Solana balance` output logged |
| 0.8 | Greenfield port of admin-store `build-store.sh` | `melusina-admin-store/build-store.sh` | diff of new vs public `build-store.sh` is pure path/branding; both call `validate_release_attestation` identically; both reject `.asc`; both delegate on-chain verify to pearl-tool |
| 0.9 | Author `mk/sidecar.mk` in spkmodule-component | `melusina-spkmodule-component/mk/sidecar.mk` (new) | defines `APP_PEARL_ENABLED=no` by default, `PEARL_SIDECAR_ENABLED=yes`; hooks compute container-image digest as `binaryHash`; `register_sidecar_identity` + `register_sidecar_release` (whichever maps) invoked via pearl-tool sidecar subcommands (design note: extend CLI with `compute-binary-hash`, `propose-sidecar-release`, `finalize-sidecar-release`) |
| 0.10 | Extend pearl-tool with sidecar subcommand trio | `melusina-attestdeployer-tool` | three sidecar-flavoured subcommands land with same stub-then-implement pattern as the app trio |

**Phase 0 gate:** pearl-tool v0.2.0 tagged; devnet program ID + Squads multisig PDA + funded-wallet balances all recorded in `melusina-attestdeployer-tool/docs/devnet-state.md`.

### Phase 1 — Pilot (one app end-to-end)

Pick **`cyberteller`** as the pilot (has current Makefile discipline, uses spkmodule, known-good existing SPK pack).

| # | Task | Done-when |
|---|---|---|
| 1.1 | `make bootstrap-author` in `cyberteller` repo | `.spkmodule-hooks/` contains the four pearl hook samples |
| 1.2 | Set `APP_PEARL_ENABLED=yes` and `PEARL_*` vars in cyberteller `Makefile` | `make publish` phase-A enters propose-release without error |
| 1.3 | Run `make publish` phase A | Squads proposal PDA stashed in `.melusina/release-ceremony/state.json` |
| 1.4 | Squads cosigners approve 3-of-4 | `Solana transaction-history` on the multisig shows Executed |
| 1.5 | Run `make publish` phase B | `RELEASE.json` finalized (authorSig, releaseEntryPda, signedAtUnix>0, quorumPolicy populated); `appHash` matches on-chain ReleaseEntry |
| 1.6 | `publish-to-branch` pushes `app.spk + metadata.json + RELEASE.json` to `cyberteller/publish` | remote branch has expected three artifacts |
| 1.7 | Public-store `build-store.sh` accepts cyberteller | dry-run on just cyberteller completes with `verify-release` returning 0 |

**Phase 1 gate:** one app's `RELEASE.json` verifies on-chain; both the local `make verify` and the public-store build's delegated `verify-release` return 0.

### Phase 2 — Public-store fleet (22 remaining)

One pass per app. Each app loops 1.1–1.6 above. Phase-A batch can parallelize (different proposals; non-conflicting nonces). Phase-B must be sequential only if the machine running `make publish` also runs the store-index build — otherwise concurrent.

**Phase 2 gate:** `build-store.sh` on `static_store/` main HEAD runs to completion with zero `validate_release_attestation` failures; catalog JSON lists all 23 apps.

### Phase 3 — Admin-store fleet (6 apps)

Same loop against the six admin apps (§4). Uses the Phase-0.8-ported `build-store.sh`.

**Phase 3 gate:** admin-store `build-store.sh` completes with zero failures; catalog lists all 6 apps.

### Phase 4 — Sidecar wave (8 sidecars)

Depends on Phase 0.9 + 0.10. Each sidecar:

1. Bootstrap sidecar Makefile from `spkmodule/mk/sidecar.mk`.
2. Produce container image + compute `binaryHash`.
3. Submit `register_sidecar_release` proposal via `pearl-tool propose-sidecar-release`.
4. Squads cosigners approve.
5. `finalize-sidecar-release` rewrites a sidecar-flavoured `RELEASE.json`.
6. Push to per-sidecar `publish` branch.

**pearl-auth v0.3 check:** iterate each of the 8 sidecars; if any one's current auth envelope is v0.2 and it serves a pearl whose pearl.mk requires v0.3, that sidecar is blocked. Decision (record in the PR): either (a) cut v0.3 now, or (b) defer that specific sidecar from Phase 4 and name it in §7. **Default: (b) — defer named sidecars, ship the rest.**

**Phase 4 gate:** `melusina-spkmodule-component/mk/sidecar.mk` is in main; 8 sidecars each have a `publish` branch carrying a finalized sidecar `RELEASE.json` (or are explicitly named in §7 as deferred).

### Phase 5 — Store rebuilds + publish

| # | Task | Done-when |
|---|---|---|
| 5.1 | `make rebuild` on `static_store/` | `dist-publish/` reflects all 23 apps; catalog index schema-validates |
| 5.2 | `make rebuild` on `melusina-admin-store/` | admin `dist-publish/` reflects all 6 apps |
| 5.3 | Deploy public store to GitHub Pages | `https://hrbrlife.github.io/melusina-static_store/` serves new `apps/index.json` with all 23 `attest` blobs |
| 5.4 | Deploy admin store to private deploy target | admin catalog URL (record in `melusina-admin-store/README.md`) serves new index; reachable under whatever auth the admin panel uses today |
| 5.5 | e2e spec `all_apps.spec.ts` | Playwright asserts every app's `/attest/<appId>/RELEASE.json` is 200 and its on-chain `releaseEntryPda` resolves |

**Phase 5 gate:** public catalog + admin catalog both served; e2e green; no `metadata.json.asc` referenced in either store's source tree.

---

## 4. Component Rosters (enumerated)

### Public store — 23 apps (`static_store/packages/hrbrlife/<repo>/<slug>/`)

| # | Repo dir | Slug | Has Makefile today? |
|---|---|---|---|
| 1 | AI_Lagoon | ai-lagoon | check |
| 2 | AITX-Procedures | dueprocess | check |
| 3 | ccash | ccash | Y |
| 4 | client_collection | clientspace | check |
| 5 | cyberteller | cyberteller | Y (pilot) |
| 6 | instaco-app | instaco-app | check |
| 7 | INSTASYS_MAIL | mermail | check |
| 8 | MELUSINA_BOTMOTHER | botmother | Y |
| 9 | melusina-bureau-cal-app | bureau-cal | Y |
| 10 | melusina-bureau-contacts-app | bureau-contacts | Y |
| 11 | melusina-bureau-diagram-app | diagram-bureau | Y |
| 12 | melusina-bureau-doc-app | doc-bureau | Y |
| 13 | melusina-bureau-notes-app | bureau-notes | Y |
| 14 | melusina-bureau-paint-app | paint-bureau | Y |
| 15 | melusina-bureau-sheets-app | sheets-bureau | Y |
| 16 | melusina-canboard-app | canboard | check |
| 17 | melusina-ccash-client-app | ccash-client | check |
| 18 | melusina-ccash-org-member-app | ccash-org-member | check |
| 19 | melusina-consilium-app | consilium | check |
| 20 | melusina-cratelink-app | cratelink | check |
| 21 | melusina-NamedCoin-app | NamedCoin | check |
| 22 | MiniGit | minigit | check |
| 23 | openclaw-main | melusina-openclaw | Y |

State audit reported 11/23 with Makefiles; the other 12 need bootstrap. Phase 2 opens with a Makefile-presence sweep.

### Admin store — 6 apps (`melusina-admin-store/packages/hrbrlife/<repo>/<slug>/`)

| # | Repo dir | Slug | appId |
|---|---|---|---|
| 1 | Fineract-setup | Fineract-setup | s9zjkgngzmpvhcdh70m8smwhz3xg74f1xwceztpyp9c70xdvwwk0 |
| 2 | melusina-mermail-station-app | mermail-station | 501eh4yhmjg7me2jxzc3z108cvd1yqx2ysv4s4j8wtq1cf91vguh |
| 3 | melusina-NamedCoin-admin-app | NamedCoin-admin | zh9vyp4c4kwafr543p0haf8c2fwjvkvun122j54y1xguc4ngffq0 |
| 4 | pr_ninja | telescreen | w1wq63jy7jtuwhxmf0y36w8egmpyej0vn8x8zqtrrfurtne23xq0 |
| 5 | shell_tester | shell-tester | nn4ddmmdrs72caf25m0czd4ayk6qt0vx9ny7yzkygn962tkk08kh |
| 6 | telescreen-companion | telescreen-companion | 7csqt2uwjeh7f1jkvcg1wtr5axmrtqajr7d8u4w0j28pc4yxg29h |

5 of 6 still carry legacy `.asc`. None has an app-level Makefile — Phase 3 must bootstrap all six.

### Sidecars — 8 deployable (`Melusina/sidecar/`)

Excludes `go-sandstorm` and `go-util` (Go libraries, not deployables).

| # | Name | Makefile | sandstorm-pkgdef | Dockerfile | Artifact shape |
|---|---|---|---|---|---|
| 1 | ailagoon-sidecar | — | — | — | **no artifacts yet** |
| 2 | dns-sidecar | — | — | — | **no artifacts yet** |
| 3 | mermail-sidecar | — | — | — | **no artifacts yet** |
| 4 | remotebak-sidecar | — | — | — | **no artifacts yet** |
| 5 | telescreen-companion-app | Y | — | — | Makefile only |
| 6 | telescreen-sidecar | Y | — | Y | Makefile + Docker |
| 7 | vintage-sidecar | Y | Y | — | Makefile + pkgdef |
| 8 | wolfdog-sidecar | Y | — | — | Makefile only |

Half the sidecars ship no release artifacts today. Phase 4 is **sequenced after** Phase 0.9 + 0.10 and will spend its first sub-phase **defining each sidecar's artifact shape** (container image vs SPK bundle) before ceremonies begin.

---

## 5. Acceptance Criteria (binary)

Every row is a fact checkable at the moment of ship.

| Gate | Binary signal |
|---|---|
| Phase 0 ship | `melusina-pearl-tool version` prints `v0.2.0`; `pearl-tool verify-release` exits 0 on a ReleaseEntry minted during smoke-test; devnet program ID ≠ the pre-patch program ID; multisig PDA + 4 funded balances recorded in `docs/devnet-state.md`. |
| Phase 1 ship | `cyberteller/publish` branch HEAD contains `app.spk + metadata.json + RELEASE.json`; the `RELEASE.json.releaseEntryPda` resolves on devnet; `pearl-tool verify-release --release-json <...>` exits 0. |
| Phase 2 ship | `static_store/build-store.sh` completes with 23/23 apps validated; catalog `apps/index.json` lists 23 apps, each with `attest.releaseEntryPda` non-empty. |
| Phase 3 ship | admin-store `build-store.sh` is a parameterized relative of the public one (diff is path/branding only); completes 6/6; catalog lists 6 apps with non-empty `releaseEntryPda`. |
| Phase 4 ship | `melusina-spkmodule-component/mk/sidecar.mk` is on `main`; each of 8 sidecars either has a `publish` branch with a finalized sidecar `RELEASE.json` **or** is named in §7 as deferred for a stated reason. |
| Phase 5 ship | e2e `all_apps.spec.ts` green against both deployed stores; no reference to `metadata.json.asc` in either store's source tree. |

No gate passes on intent. Every gate requires an artifact (PDA address, commit SHA, CI run ID, or e2e report).

---

## 6. Risk Register

Ordered by (likelihood × severity). Mitigations are **specific** — a pointer, a command, or a config file.

| # | Risk | Mitigation |
|---|---|---|
| R1 | `RELEASE_BINDING_DRIFT` between phase A and phase B on the same machine | Already handled — `finalize-release` re-runs `apphash.Compute` + aborts on mismatch. Document `make pearl-clean` + re-propose as the only recovery. |
| R2 | Squads proposal zombie when a cosigner loses their key | Add `make abort-release` target that closes the vault-tx; add TTL check in `finalize-release` that emits warning after N hours. MVP: document the manual `Squads tx close` path; automate later. |
| R3 | `melusina-pearl-tool` version drift between developer laptops and the store-build host | Pin tool version in a `.tool-version` file at each consumer repo root; `build-store.sh` asserts version on startup; fail-closed. |
| R4 | Solana devnet RPC 429s under burst of 37 proposals | Use a paid / dedicated RPC endpoint; configure in `melusina-attestdeployer-tool/config.toml`. Document fallback: serialize proposals one-at-a-time with backoff. |
| R5 | Squads v4 devnet UI intermittent availability | Ship CLI-only ceremony driver as fallback (existing `pearl-tool propose-release` must not require UI to function). |
| R6 | GitHub Release 2 GB asset cap exceeded by large SPKs (cyberteller, botmother, openclaw historically) | Check sizes before Phase 5 deploy. If any SPK > 2 GB, split assets per store's existing large-asset path (Git LFS or chunked upload). Named apps to pre-flight: cyberteller, MELUSINA_BOTMOTHER, openclaw-main. |
| R7 | Admin store is a PRIVATE repo → GitHub Pages not available on free plan | Decide admin deploy target before Phase 5: options are (a) paid GH Pages on private, (b) private S3 + CloudFront, (c) signed-tarball artifact. Record decision in `melusina-admin-store/README.md`. |
| R8 | Concurrent pushes to per-app `publish` branch create merge conflicts | `publish-to-branch` already does an idempotent push based on `packageId+appHash`. Serialize multi-app phase-B runs by convention: one host runs phase B; phase A is parallel-safe. |
| R9 | `metadata.json` slug / developer fields are all `"N/A"`; catalog derives slugs from dir paths | Catalog build is unaffected; document that renames of `packages/*/*/` dirs are breaking changes; no backfill in MVP. |
| R10 | In-flight `M src/main.jsx` + untracked `KEEP - COMPONENTS FOR APPS.md` on main | Stash both before the first fleet-scale commit; neither is absorbed into kill-list changes. |

---

## 7. Non-Goals / Post-MVP (explicit)

Anything below is **not** blocked by this plan and will be kept out of these phases unless a phase explicitly gates on it.

- Mainnet deploy of `license-registry` or any ReleaseEntry mint on mainnet.
- Removing the `acceptUnattestedSPKs` shell kill-switch.
- Deleting `metadata.json.asc` from historical publish branches.
- `GlobalAppApproval` / `LocalAppApproval` PDAs (not in code; would require separate Anchor design).
- `StoreReleaseListing` PDA minting for each published release.
- `SensitiveActionPolicy` / `CrossLicenseHopAuthorization` flows.
- pearl-auth v0.3 envelope cutover (gated on Phase 4 sidecar analysis; may defer named sidecars instead).
- melusina-attest Python / TS `pip` / `npm` publish.
- Master-NFT minting ceremony for apps not already in the registry.
- Cross-machine `pearl-restore` portability.
- CI auto-verify for the fleet (GitHub Actions across all 37 publish branches).
- Re-running `make publish` for version bumps (first clean run must land; bumps follow).
- Writing new apps or onboarding new app authors.

---

## 8. Execution DAG

```
         [0.1] relax custody check
               │
               ▼
         [0.2] deploy to devnet ─────┐
                                      │
   [0.3/0.4/0.5] pearl-tool trio      │ (parallel)
                                      │
         [0.6] mint Squads ───────────┤
         [0.7] fund wallets ──────────┤
         [0.8] port admin build-store─┤
         [0.9] write sidecar.mk ──────┤
        [0.10] pearl-tool sidecar trio┘
               │
               ▼
         [Phase 1]  cyberteller pilot
               │
               ▼
         [Phase 2]  22 remaining public apps
               │        (parallel phase-A, serial phase-B)
               ▼
         [Phase 3]  6 admin apps
               │
               ▼
         [Phase 4]  8 sidecars (through new sidecar.mk path)
               │
               ▼
         [Phase 5]  two-store rebuild + publish + e2e
```

Phases 2 and 3 are independent and can run concurrently once Phase 1 proves the pipeline.
Phase 4 can start in parallel with Phases 2-3 once 0.9 + 0.10 land; its gate blocks Phase 5 only for sidecars.

---

## 9. Prose Discipline

The next conversation that reads this plan must not inherit aspirational language from it. Enforce:

**Avoid:** "implemented" (when scaffolded), "available" (when unfunded / undeployed), "ready for mainnet", "the fleet is migrating" (passive hides 0/N), "supports both X and Y" (shim smell).

**Prefer:** "scaffold stub returning not-yet-implemented", "unfunded on devnet", "0 of 37 migrated as of <date>", "greenfield; `.asc` path removed", "devnet-only; mainnet out of scope this iteration".

Status sections carry no future-tense verbs. "Will ship" belongs in plan sections, never in status snapshots. A claim without a PDA address, commit SHA, CI run ID, or e2e report is not a status claim.

---

## 10. First Action on Next Read

Before executing any task below 0.1, re-run the §0 State Snapshot queries. If any row moved, update §0 before proceeding. The plan's correctness rests on the snapshot's correctness.

```
# Phase 0 snapshot re-verification commands
Solana program show <license-registry devnet id>            # row: deployed program ID
cat melusina-attestdeployer-tool/docs/devnet-state.md       # rows: multisig PDA + wallet balances
melusina-pearl-tool version                                 # row: tool version
(cd melusina-attestdeployer-tool && go test ./...)          # tool health
(cd static_store && ./build-store.sh --dry-run)             # public-store validator health
(cd store-rebuild/melusina-admin-store && ./build-store.sh --dry-run)  # admin-store validator health
```

If any of those commands fails or returns something different from §0, stop and update the snapshot before touching anything downstream.
