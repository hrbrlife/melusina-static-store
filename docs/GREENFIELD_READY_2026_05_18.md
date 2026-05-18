# Greenfield publish — ready state, 2026-05-18

20/20 apps on canonical Melusina hosts are wired for `make publish` self-service. Foundation master NFT transfer landed on devnet. This document captures the per-app state and the one-command path to publish.

---

## Per-app self-publish readiness

All 20 apps have `origin/main` updated with:

- `.spkmodule-hooks/post-publish` (executable, 72-line dispatcher to `static_store/scripts/ship-changes.sh`)
- `spkmodule` submodule pinned to `origin/greenfield` (`579da4a` as of this writing)
- Pearl-mode placeholder block in `Makefile` (after `APP_SLUG`)
- Auto-bump pre-pack hook removed (in the 6 apps that had it)
- Legacy `APP_PEARL_ENABLED := no` dead-line removed

| # | App | Path |
|---|---|---|
| 1 | melusina_botmother | `/home/user/Desktop/melusina_botmother` |
| 2 | ccash_go_htmx | `/home/user/Desktop/ccash_go_htmx` |
| 3 | ccash_wholesale | `/home/user/Desktop/ccash_wholesale` |
| 4 | ccash_domain_template | `/home/user/Desktop/ccash_domain_template` |
| 5 | DueProcess | `/home/user/Desktop/DueProcess` |
| 6 | cyberteller | `/home/user/Desktop/cyberteller` |
| 7 | melusina_cybertellerconfig_app | `/home/user/Desktop/melusina_cybertellerconfig_app` |
| 8 | melusina_ccashconfig_app | `/home/user/Desktop/melusina_ccashconfig_app` |
| 9 | instaco.app | `/home/user/Desktop/instaco.app` |
| 10 | melusina-namedcoin-app | `/home/user/Desktop/namedcoin-work/melusina-namedcoin-app` |
| 11 | client_collection | `/home/user/Desktop/client_collection` |
| 12 | shell_tester | `/home/user/Desktop/store-rebuild/shell_tester` |
| 13 | INSTASYS_MAIL | `/home/user/Desktop/store-rebuild/INSTASYS_MAIL` |
| 14 | melusina-bureau-doc-app | `/home/user/Desktop/store-rebuild/melusina-bureau-doc-app` |
| 15 | melusina-bureau-diagram-app | `/home/user/Desktop/store-rebuild/melusina-bureau-diagram-app` |
| 16 | melusina-bureau-paint-app | `/home/user/Desktop/store-rebuild/melusina-bureau-paint-app` |
| 17 | melusina-bureau-sheets-app | `/home/user/Desktop/store-rebuild/melusina-bureau-sheets-app` |
| 18 | cca-tc-operator | `/home/user/Desktop/cca-tc-operator` |
| 19 | cca-tc-vendor | `/home/user/Desktop/cca-tc-vendor` |
| 20 | cca-tc-buyer | `/home/user/Desktop/cca-tc-buyer` |

### ccash_go_htmx — note

The old `origin/main` was a "ccash playground" stub branch. It was force-replaced with the production greenfield-ready tree. Two real e2e commits (`83bdf5a`, `3e48263`) and three playground commits unique to the old main were preserved at `origin/feat/killlist-ccash-b4-provider-routes-20260509`.

---

## Foundation master NFT transfer

**Executed 2026-05-18 on devnet.** Canonical master NFT `B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe` transferred from Foundation Squads vault `5SmcSBsuaa21ZEhbj71ME2FpCKeshvjUpmDymbF7nupk` to Core App Team Squads vault `3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3` (Squads multisig `4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V`, 3-of-4).

Squads ceremony trail:

| Step | Tx signature |
|---|---|
| Pre-create destination ATA `EA2FEHzhg4ZunhchFhcBMjaVtTh3pGkEy2SG6FEmYepn` | `4BDBa3sz...` |
| `vaultTransactionCreate` (txIndex 85) | `29ukyFDGK2jg...` |
| `proposalCreate` | `5eswyiAiw9us...` |
| `proposalApprove` (licensee-signer-1) | `4QYJNdPMFSG1...` |
| `proposalApprove` (licensee-signer-2) | `CtVKdgiKTMTs...` |
| `vaultTransactionExecute` | `5HcjJgGDAdwW4Jecc8ovHRc6eNyLFmBquBgcTm2QX2nPqhvgDE14ty8Lngd1Pb9Vvmkhh6h3sQDCy2ZjNyLgEzmv` |

The v104 `license-registry` contract's `validate_release_master_nft_custody` check (`attestation.rs:1342`, requires `master_nft_ata_owner == publisher_squads_vault`) is now satisfied — `make publish` on any of the 20 apps will pass the master-NFT gate.

---

## One-command publish flow per app

From any of the 20 app folders:

```bash
melusina-pearl-tool onboard --lineage=live \
  --app-dir=. \
  --canonical-master=B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe \
  --wait-active
```

What this does:

1. Sanity checks (Solana + spl-token CLIs, app dir layout, Makefile vars).
2. Mints a per-app License NFT, transfers mint authority to Core App Team vault.
3. Short-circuits master mint to the canonical master (skipping the per-app master mint that v104 would reject).
4. Queries Core App Team Squads next-transaction-index.
5. `propose-release` on devnet (writes ceremony state at `.melusina/release-ceremony/live/state.json`).
6. Prints Squads UI URLs for 3-of-4 cosigner approval.
7. Polls proposal status (30s/30min via `--wait-active`).
8. `finalize-release` + `verify-release` (writes signed RELEASE.json).
9. Patches `Makefile` `PEARL_LIVE_MASTER_NFT_MINT` + `PEARL_LICENSE_MINT` placeholders with real pubkeys, commits on `feat/pearl-onboard-live-<date>`.

Then:

```bash
make publish
```

What this does:

1. Runs unconditional Gate A — version-bump check (compares local SPK hash + version vs `origin/publish:<slug>/RELEASE.json`).
2. Runs unconditional Gate B — SPK size auto-route (≤100MB inline git-blob via LFS-skip; >100MB to GitHub Releases + `releases-url.json` pointer).
3. Runs unconditional Gate C — Squads on-chain quorum check via `spk-verify-strict` (structural check on RELEASE.json's `quorumPolicy.signatures[]` + threshold; reflects on-chain truth via the finalize-release step).
4. Pushes signed SPK to `origin/publish`.
5. Post-publish hook auto-dispatches `bash $MELUSINA_STATIC_STORE/scripts/ship-changes.sh --only $APP_SLUG --skip-fetch` (with flock on `$STATIC_STORE/.publish.lock`).
6. Catalog rebuilds + force-pushes `dist-publish` to `gh-pages`.

If any gate refuses, `make publish` exits non-zero with an actionable error message naming what to fix.

---

## When Stream A v105 lands

Stream A (other team) is shipping `license-registry-v105` with per-app `AppMasterNFT` + `Lineage` enum + `DevAppRegistry` PDA. ETA was 8-10 days from 2026-05-18 (~2026-05-26 to 2026-05-28). When that lands:

1. Drop `--canonical-master` from the `melusina-pearl-tool onboard` invocation.
2. Re-run the ceremony for each app — this time minting a per-app master NFT instead of reusing the canonical.
3. Bump each app's spkmodule pin off `greenfield-spike-canonical-master` (if any are on the spike) onto plain `greenfield`.

Stream B already shipped the `--lineage` flag on `spk-verify-strict` (gated behind `MELUSINA_VERIFY_RPC_ENABLED=1` + `MELUSINA_PEARL_TOOL_HAS_LINEAGE=1`) so flipping over is environment-flag-only on our side.

---

## When Stream C devstore-sidecar lands

Stream C is building the dev-store HTTP sidecar (POST `/team/<vault>/dev/packages` per the contract in `spkmodule/docs/stream-c-dev-store-envelope-proposal.md`). When that lands:

- `make devpublish` becomes operable (currently the target exists but `bin/devstore-push` will get HTTP errors against an absent sidecar).
- Each app needs `PEARL_DEV_MASTER_NFT_MINT` + `TEAM_DEV_SQUADS` declared in its Makefile (currently commented out in the placeholder block).

---

## Working tree state on this host

- Loop cron deleted (`11629476` cancelled).
- Several local stashes accumulated during the sweep (in `ccash_go_htmx`, `ccash_domain_template`, etc.) — can be cleaned up with `git stash list` + `git stash drop` per app, or left in place.
- spkmodule `greenfield` branch tip: `579da4a` on `origin`.
- spkmodule `greenfield-spike-canonical-master` tip: `bf0aa89`, tagged `v0.0.0-spike-canonical-master.2`.

---

## Boundary contracts frozen with other teams

| We own (Stream B) | Status |
|---|---|
| `.spkmodule` field names: `APP_LIVE_MASTER_NFT`, `APP_DEV_MASTER_NFT`, `TEAM_LIVE_SQUADS`, `TEAM_DEV_SQUADS` | Locked |
| `RELEASE.json` schema v2 with `lineage` enum + `$schema` discriminator | Locked |

| Other-team contracts | Status |
|---|---|
| Stream A: lineage-as-PDA-seed (Option C, single instruction); team-only DEV mint; DevAppRegistry FCFS; remote-cosigner pattern (no in-grain custody) | Acknowledged + shipping |
| Stream C: POST `/team/<vault>/dev/packages` multipart + canonical-envelope-JSON + Ed25519 sig + `X-Melusina-Idempotency-Key` + pending tier with auto-promotion on ReleaseEntry Active | Frozen |

---

## See also

- `spkmodule/docs/pearl-ceremony-gotchas.md` — 4 known ceremony gotchas + v104 workaround
- `spkmodule/docs/stream-c-dev-store-envelope-proposal.md` — DEV-lineage upload contract
- `static_store/docs/PEARL_ONBOARDING_RUNBOOK.md` — developer-facing onboarding runbook
- `static_store/SHIP-IT.md` — overall ship-loop runbook (with Greenfield Pearl-mode preview section)
- Memory: `project_greenfield_publish_design.md`, `project_devpublish_spec_integration_2026_05_18.md`, `project_greenfield_cycle1..5_*.md`
