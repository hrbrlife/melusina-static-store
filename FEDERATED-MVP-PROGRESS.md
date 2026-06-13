# Federated Store MVP — Progress & Audit Ledger

> STATE for the `/loop` (cron `b4040345`, every 20m). Each fire: read this, advance the next unblocked task, run builds/tests, update this file. Spec = `FEDERATED-STORE-MVP.md`.
> **DONE = two CONSECUTIVE OK audits** (see §Audit ledger). When reached → `CronDelete b4040345` + report.

## Operating mode
- Division of labor (safety): **workflows** do parallel grounding (read 4 repos → implementation recipes) + adversarial **audits** (read-only). **Main loop (me)** writes code via Edit/Write on dedicated branches, runs builds/tests, integrates. No parallel writers to one repo.
- Defaults in force: D1 Foundation-co-sign reseller releases · D2 rotatable-root-PDA+kill-switch · D3 live-for-reseller/cached-for-root · D4 one-process-per-license.
- **GUARDRAILS:** branch-only; never push/deploy/ceremony/RPC-write; don't disturb other repos' WIP.

## Repos & branches
| Repo | Path | Branch | Created |
|---|---|---|---|
| static_store | /home/user/Desktop/static_store | `feat/federated-store-mvp` | ✅ |
| Anchor program | /home/user/Desktop/Melusina/melusina_solana_dev-license104 | `feat/store-operator-authz` | 🔄 (C1 workflow wf_95d744d9-564) |
| shell | /home/user/Desktop/Melusina/sandstorm-b31/shell | `feat/federated-store-accepted-sources` | ⬜ |
| authzsign | /home/user/Desktop/Melusina/melusina-authzsign-component | `feat/cascade-store-stage` | ⬜ |

## Task board (see spec §4 for acceptance criteria)
Status: ⬜ todo · 🔄 in-progress · ✅ done(evidence) · ⛔ blocked

### C1 — Anchor program (foundational; unblocks C2/C4/C5) — 🔄 wf_95d744d9-564
- 🔄 C1.1 `StoreOperatorAuthorization` PDA + LEN=193 (field formula; earlier "224" was an arithmetic slip — implementer pinned 193 w/ `len_is_193` test) (contract C-1; mirror reseller_approval.rs)
- 🔄 C1.2 `authorize_store_operator` / `revoke_store_operator` (is_root Master-NFT-only + pinned ROOT_STORE_DOMAIN_HASH const)
- 🔄 C1.3 guard `register_store_release_listing.store_authority` == Active StoreOperatorAuthorization; +store_domain_hash/operator_authorization on StoreReleaseListing (LEN +64)
- 🔄 C1.4 `PERM_STORE_OPERATE=1<<55` + capnp mirror (+coherence test if present)
- 🔄 C1.4b `LicenseEntry.accepted_stores:Vec<Pubkey>(cap 16)` + `root_store_domain_hash` BEFORE bump (C-4) + `update_accepted_stores` (Squads-vault-gated, root locked)
- ✅ C1.5 (RECLASSIFIED) on-chain version floor NOT added — recipe proved release_v2 PDA seed already prevents dup per app_hash; version policy enforced off-chain at install boundary (C4/C5)
- ⬜ C1.6 (DEFERRED) reseller `AppTierPolicy` PDA → later; foundation apps use existing `FoundationAppEntry.tier` (no change)
- 🔄 C1.7 `cargo check` green (anchor build/IDL regen best-effort)

### C2 — Store sidecar (Phase-1 spine) — 🔄 read surface LANDED (sidecar/melusina-store-sidecar/, branch feat/federated-store-mvp)
- 🔄 C2.1 module skeleton + JSON config loader + go.mod (stdlib) — builds; `derive.DeriveSidecar` identity pending dep-wiring post-C1
- ✅ C2.2 READ surface byte-identical — `http.FileServer(dist-publish)`; smoke: /healthz 200, /apps/index.json 200, /index.html 301→/, POST /publish 501 (handler.go)
- ⬜ C2.3 gated POST /publish + REAL Go on-chain verify + single writer — BLOCKED on C1 PDAs + melusina-attest dep wiring
- ⬜ C2.4 store-signed provenance receipt — blocked on C1
- 🔄 C2.5 bypasses compiled out (MELUSINA_ATTEST_OFFLINE/SKIP_STEPS/SCAN_NOOP → reject; verified); boot identity/TLS check pending post-C1
- ⬜ C2.6 reseller root-mirror worker
- ✅ C2.7 go build / go vet / gofmt green (read-surface scaffold)

### C3 — Submit-client
- ⬜ C3.1 `make publish <storeurl>` → sealed-v3 submit; force-push deleted

### C4 — authzsign daemon
- ⬜ C4.1 cascade.go 4th store-stage from store-signed receipt
- ⬜ C4.2 blacklist read + version floor + root-class + cached root fast-path
- ⬜ C4.3 go build/test green

### C5 — Shell
- ⬜ C5.1 accepted_stores governance UI (Squads proposal)
- ⬜ C5.2 updateAppIndex multi-source verify (re-hash before startInstall; auto-update chokepoint; root precedence-by-identity)
- ⬜ C5.3 server-side tier gate + visitor invariant + signed tier-policy
- ⬜ C5.4 build/tests

## Audit ledger
**Consecutive OK count: 0 / 2.** (any non-OK resets to 0)

| # | Date | Builds | Critical/High findings | Verdict |
|---|---|---|---|---|
| — | — | — | — | — |

## Frozen cross-component contracts (from recipe workflow wf_7d011aea-017)
Full recipes: `/tmp/claude-1000/.../tasks/_recipes.txt`; contracts: `_contract.txt`. Key bindings ALL components must match:
- **C-1** StoreOperatorAuthorization: seeds `[b"store_operator", license_nft_mint, store_domain_hash]`, **LEN=193** (8+32+32+32+32+1+1+4+1+32+8+(1+8)+1; the "224" in the recipe was wrong), field order fixed (see spec/contract).
- **C-2** provenance receipt: signed msg = raw 96 bytes `appHash||releaseHash||servingDomainHash`; HTTP form adds operatorSignature(b58)+storedAt; daemon Context carries raw 96 (sig pre-verified by sidecar).
- **C-3** sealed-v3 publish envelope: `KindArtifact`, Body=canonical RELEASE.json, RequestHash=sha256(SPK)=appHash; SPK uploaded alongside (not in envelope).
- **C-4** `accepted_stores:Vec<Pubkey>` (StoreOperatorAuthz addrs) + `root_store_domain_hash` appended BEFORE `bump` on LicenseEntry.
- **C-5** canonical host→hash = `sha256(ascii_lower(strip_one_trailing_dot(host)))` (== licenses.rs:121-129). Do NOT route via DeriveDomainClaim. One cross-lang test vector required (S8).
- **C-6** tier ceiling keyed by on-chain 32-byte `app_id` (ReleaseEntry.app_id / FoundationAppEntry.app_id), NOT app_hash, NOT base32 catalog appId.
- **SHOWSTOPPER (mismatch #1):** daemon `Context` must be length-discriminated: 32 bytes (appHash only) OR ≥128 (appHash + 96-byte receipt). C4+C5 must ship this wire change in LOCKSTEP (HashRequest signs full Context).

## Next action (updated each fire)
**→ C1 workflow wf_95d744d9-564 STILL RUNNING** (implement phase ~12min in @ 11:53; likely mid `anchor build`; review phase not started; output 0 bytes). Agent has written store_operator.rs (state+instructions) + edits to attestation/license/permissions/constants/errors/licenses/lib/mod/capnp — all UNCOMMITTED WIP in the program repo. DO NOT touch that repo while the agent writes. On completion: review the diff + `cargo check` + commit the C1 work (or accept the agent's commit), mark C1 ✅/fix. If still running at next cron fire with 0-byte output → consider TaskStop + take over the uncommitted state directly. Then:
1. If review=OK + build green → mark C1 ✅; else apply fixes (resume the workflow or fix directly).
2. Wire C2.3 gated /publish: add melusina-attest/identity-gate/primitives local replaces to sidecar go.mod; implement on-chain verify (re-hash SPK==ReleaseEntry.app_hash, Active, blacklist, FetchStoreOperatorAuthz) + build-store.sh single-writer call + provenance-receipt signing (contract C-2).
3. C3 submit-client (sealed-v3 POST replacing publish-app-full.sh force-push).
4. C4 + C5 Context length-discrimination change in LOCKSTEP (mismatch #1: 32 vs ≥128 bytes).

## Log
- 2026-06-13: loop armed (cron b4040345); spec + ledger written; static_store branch created; grounding workflow launched.
- 2026-06-13: recipes + frozen contracts received (wf_7d011aea-017); C1 scope finalized (version-floor→off-chain, AppTierPolicy deferred); C1 implementation workflow launched (wf_95d744d9-564).
- 2026-06-13: C2 READ surface scaffolded in parallel (sidecar/melusina-store-sidecar/: main/config/handler.go, go.mod, store.yaml.example, README) — go build/vet/fmt green, smoke-tested (read 200s, /publish fail-closed 501, no bypass). Committed f6b460a9 on feat/federated-store-mvp. Gated path blocked on C1.
- 2026-06-13: pinned contract C-5 — `StoreDomainHash` (domainhash.go) + shared testdata/domain_hash_vectors.json (Rust/Go/JS must match; S8). ROOT_STORE_DOMAIN_HASH("melusina-os.org")=0595e1c4..d4d7. go test green. Committed c44e59da. Remaining work (C2.3 gated path, C3, C4, C5) blocked on C1 → yielding to let wf_95d744d9-564 land.
- 2026-06-13 (cron fire): C1 workflow still in implement phase (~12min, anchor build). Corrected StoreOperatorAuthorization LEN 224->193 in spec+ledger (implementer caught the slip). Added sidecar LoadConfig tests (go test green). Program repo left untouched (active single writer). Audit count 0/2.
