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
| Anchor program | /home/user/Desktop/Melusina/melusina_solana_dev-license104 | `feat/store-operator-authz` | ✅ C1 committed 918921e (review OK; build-sbf+76 tests green) |
| Melusina monorepo shared/ libs | /home/user/Desktop/Melusina | `feat/store-operator-go-readers` | ✅ C1b committed d41272af (review OK; 3 modules build+test green) |
| shell | /home/user/Desktop/Melusina/sandstorm-b31/shell | `feat/federated-store-accepted-sources` | ⬜ |
| authzsign | /home/user/Desktop/Melusina/melusina-authzsign-component | `feat/cascade-store-stage` | ⬜ |

## Task board (see spec §4 for acceptance criteria)
Status: ⬜ todo · 🔄 in-progress · ✅ done(evidence) · ⛔ blocked

### C1 — Anchor program — ✅ DONE (commit 918921e; review verdict OK, 0 findings; wf_95d744d9-564)
- ✅ C1.1 `StoreOperatorAuthorization` PDA, LEN=193, seeds+field order match C-1 (`len_is_193` test)
- ✅ C1.2 `authorize_store_operator`/`revoke_store_operator` — is_root requires Master-NFT custody AND `store_domain_hash==ROOT_STORE_DOMAIN_HASH` (compromised non-root path cannot mint a root); reseller path = Active license + `PERM_STORE_OPERATE`
- ✅ C1.3 guard `register_store_release_listing`: `store_operator_authz.status==Active && .store_authority==signer`; +store_domain_hash/operator_authorization on StoreReleaseListing (LEN 187→251); optional FoundationAppEntry tier-ceiling check when present
- ✅ C1.4 `PERM_STORE_OPERATE=1<<55` + capnp `storeOperate @55` mirror
- ✅ C1.4b `LicenseEntry.accepted_stores:Vec<Pubkey>(cap 16)` + `root_store_domain_hash` BEFORE bump (C-4); `update_accepted_stores` Squads-vault-gated, root-locked; activate + force_init zero-init/seat root
- ✅ C1.5 (RECLASSIFIED) on-chain version floor NOT added — release_v2 PDA seed prevents dup per app_hash; version policy enforced off-chain (C4/C5)
- ⬜ C1.6 (DEFERRED) reseller `AppTierPolicy` PDA → later; foundation apps use existing `FoundationAppEntry.tier`
- ✅ C1.7 `cargo check` + `cargo build-sbf` + `anchor build --no-idl` GREEN; `cargo test --lib` 76/76. (full anchor-build IDL regen = ENV blocker, see follow-ups)
- ⚠️ BPF stack fix: growing LicenseEntry +548B blew the 4096 stack in `AuthorizeCrossLicenseHop` → Box-ed both accounts (repo pattern). Watch for similar elsewhere.

### C1b — shared Go derivers/readers — ✅ DONE (commit d41272af; review OK; offsets verified byte-for-byte)
- ✅ `primitives.StoreDomainHash` (ASCII-lower, Rust parity), `DeriveStoreOperatorAuthz`, `DeriveBlacklistEntry` (+SeedStoreOperator/SeedBlacklist)
- ✅ `pda.StoreOperatorAuthorization` / `pda.BlacklistEntry` / `pda.StoreDomainHash` wrappers
- ✅ `verify` readers + RPC: `FetchReleaseEntry`(appHash+status), `FetchStoreOperatorAuthz`(status,storeAuthority,allowedTierMask,isRoot,storeDomainHash), `FetchStoreReleaseListing`, `FetchBlacklistEntry`(present,type) + `Read*` decoders. AttestationStatus/AuthorizationStatus w/ RequireActive()
- ✅ go build+test green (3 modules); only pre-existing unrelated testvectors fail
- ⚠️ CALLER CAVEATS: (a) `FetchBlacklistEntry` — existence==deny; not-found=(false,0,nil) NOT err → C4/C2.3 must treat present==true as blacklisted AND fail-closed on genuine RPC err. (b) `StoreDomainHash` ASCII-lower → IDN must be punycode-encoded BEFORE the call. (c) `verify.Pubkey = [32]byte` local alias (no primitives import).
- 📌 C4 PREREQ: still need a `verify` reader for `LicenseEntry.accepted_stores` (Vec<Pubkey>) + `root_store_domain_hash` — fold into the C4 workflow.

### C1 FOLLOW-UPS (tracked; not build-blocking)
- ⏳ FU-1 IDL regen: full `anchor build` IDL doc-extraction fails on this host (proc-macro2 1.0.86 vs rustc 1.95.0 nightly; 1.85.0 breaks ark-bn254). Code builds clean (build-sbf + --no-idl). IDL must regen on a compatible Anchor-0.30.1 host before any deploy. Go readers don't need IDL (raw-byte decode). Shell client (C5) may — confirm.
- ⏳ FU-2 `tls_cert_fingerprint` is currently populated from a carrier account's pubkey bytes (the frozen authorize param list omitted it). Fix: pass it as a `[u8;32]` instruction arg + add `update_store_tls` (S8) so the operator's real cert SPKI binds on-chain. Needed before C4/C5 TLS pinning (S2/S8).
- ⏳ FU-3 no `permission_bit_coherence_test` file exists (only referenced in comments); bit 55/capnp mirrored manually — wire a real coherence test if/when the harness is added.

### C2 — Store sidecar (Phase-1 spine) — 🔄 read surface LANDED (sidecar/melusina-store-sidecar/, branch feat/federated-store-mvp)
- 🔄 C2.1 module skeleton + JSON config loader + go.mod (stdlib) — builds; `derive.DeriveSidecar` identity pending dep-wiring post-C1
- ✅ C2.2 READ surface byte-identical — `http.FileServer(dist-publish)`; smoke: /healthz 200, /apps/index.json 200, /index.html 301→/, POST /publish 501 (handler.go)
- 🔄 C2.3 gated POST /publish + REAL Go on-chain verify + single writer — wf_b6b56d74-79c (UNBLOCKED: C1+C1b done; deps wired via ../../../Melusina/shared replaces)
- 🔄 C2.4 store-signed provenance receipt (raw-96 C-2) — part of wf_b6b56d74-79c
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
**→ C1 ✅ + C1b ✅. C2.3 gated /publish IN FLIGHT (wf_b6b56d74-79c).** On C2.3 review-OK → launch C4 (cascade store-stage; also add the `LicenseEntry.accepted_stores` reader) & C5 in lockstep on the 128-byte Context, plus C3 submit-client. Remaining sequence:
1. **C2.3 gated /publish** — add melusina-attest/identity-gate/primitives local replaces to sidecar go.mod (paths resolved: shared/melusina-attest, shared/melusina-identity-gate, shared/melusina-solana-primitives — all in the Melusina monorepo). Real Go on-chain verify: `pda.Release`→`verify.FetchReleaseEntry` (re-hash SPK==app_hash, Active), `pda.StoreOperatorAuthorization`→`FetchStoreOperatorAuthz` (Active, store_authority, tier covers), blacklist check; `envelope.Verify(KindArtifact)`; then `build-store.sh` single-writer; sign provenance receipt (C-2: raw-96 `appHash||releaseHash||servingDomainHash`).
2. **C3 submit-client** — `make publish <storeurl>` → `envelope.Sign(KindArtifact,...)` sealed-v3 POST replacing publish-app-full.sh force-push.
3. **C4 + C5 in LOCKSTEP** — Context length-discrimination (mismatch #1: 32B appHash OR ≥128B appHash+receipt); cascade store-stage + accepted_stores decode + blacklist + tier gate (C5 server-side).
- Real API confirmed: `envelope.Sign/Verify`, `derive.DeriveSidecar(ref, SidecarShards)`, `pda.Release/InstallerRelease/SidecarIdentity`, `binhash.AttestSelfHashWith(ctx,Options)`, `verify.RPCClient.Fetch*Status/FetchGlobalAppApprovalAppHash` (templates for the new readers C1b adds).

## Log
- 2026-06-13: loop armed (cron b4040345); spec + ledger written; static_store branch created; grounding workflow launched.
- 2026-06-13: recipes + frozen contracts received (wf_7d011aea-017); C1 scope finalized (version-floor→off-chain, AppTierPolicy deferred); C1 implementation workflow launched (wf_95d744d9-564).
- 2026-06-13: C2 READ surface scaffolded in parallel (sidecar/melusina-store-sidecar/: main/config/handler.go, go.mod, store.yaml.example, README) — go build/vet/fmt green, smoke-tested (read 200s, /publish fail-closed 501, no bypass). Committed f6b460a9 on feat/federated-store-mvp. Gated path blocked on C1.
- 2026-06-13: pinned contract C-5 — `StoreDomainHash` (domainhash.go) + shared testdata/domain_hash_vectors.json (Rust/Go/JS must match; S8). ROOT_STORE_DOMAIN_HASH("melusina-os.org")=0595e1c4..d4d7. go test green. Committed c44e59da. Remaining work (C2.3 gated path, C3, C4, C5) blocked on C1 → yielding to let wf_95d744d9-564 land.
- 2026-06-13 (cron fire): C1 workflow still in implement phase (~12min, anchor build). Corrected StoreOperatorAuthorization LEN 224->193 in spec+ledger (implementer caught the slip). Added sidecar LoadConfig tests (go test green). Program repo left untouched (active single writer). Audit count 0/2.
- 2026-06-13 (cron fire): **C1 ✅** — wf_95d744d9-564 review verdict **OK, 0 findings**; commit 918921e; cargo build-sbf + `anchor build --no-idl` + 76/76 lib tests GREEN; contract-conformant (is_root gate, listing guard, accepted_stores-before-bump, PERM bit55). Follow-ups FU-1 (IDL regen=env), FU-2 (tls_cert_fingerprint→instr arg + update_store_tls, S8), FU-3 (coherence test). Launched C1b shared Go derivers/readers (wf_ecc26307-65e) to unblock C2.3+C4; scouted real melusina-attest API. End-to-end audit count unchanged **0/2** (a per-component review is NOT one of the two final end-to-end audits).
- 2026-06-13 (C1b completion): **C1b ✅** — wf_ecc26307-65e review OK; commit d41272af; Go derivers/readers for StoreOperatorAuthorization/StoreReleaseListing/ReleaseEntry/BlacklistEntry, offsets byte-verified, 3 modules build+test green. Monorepo on feat/store-operator-go-readers (sidecar replaces resolve against it). Launched C2.3 gated-publish workflow (wf_b6b56d74-79c). C4 deferred until C2.3 receipt confirmed (+ needs accepted_stores reader). Audit 0/2.
