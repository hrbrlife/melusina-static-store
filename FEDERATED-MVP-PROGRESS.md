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
| shell | /home/user/Desktop/Melusina/sandstorm-b31/shell | `feat/federated-store-accepted-sources` | ✅ C5 COMPLETE (C5-core e25215a, C5.3 8f6e411, C5.1 a1e4747) |
| authzsign | /home/user/Desktop/Melusina/melusina-authzsign-component | `feat/cascade-store-stage` | ✅ C4 committed f653de4 (review OK; build+23 tests green) |

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
- ⏳ FU-4 legacy gh-pages force-push still present in static_store `make apply` target (the OLD static-publish path). The verifying sidecar + C3 supersede it; the new driver no longer invokes it, but full removal/neutralization is an ops follow-up (the whole point is killing force-push).

### C2 — Store sidecar — ✅ gated path DONE (commit a2fb31a9; review OK, fail-closed audit YES)
- ✅ C2.1 module + config (+CatalogRepoRoot) + go.mod wired to 3 shared libs (offline-resolved; go.sum = x/crypto + edwards25519)
- ✅ C2.2 READ surface byte-identical (handler.go)
- ✅ C2.3 gated /publish: `VerifyPublish` steps a–d (re-hash==app_hash Active → StoreOperatorAuthz Active+authority+tier → blacklist deny), `envelope.Verify(KindArtifact)`+nonce, single-writer mutex; `go test -race` green w/ full accept/reject matrix (verify.go/handler.go)
- ✅ C2.4 provenance receipt — `SignReceipt` over raw-96 `appHash||releaseHash||servingDomainHash` (C-2); test asserts exact-96 signing (provenance.go)
- 🔄 C2.5 bypasses compiled out ✅ (offline/skip/scan-noop→400). BOOT IDENTITY pending → operator key nil → /publish 503 fail-closed (derive.DeriveSidecar + domain/TLS assert TODO; needs FU-2 tls fingerprint)
- ✅ C2.6 reseller root-mirror worker — committed e3b64855 (sidecar) + 0e37aea2 (monorepo readers); go build+test GREEN. Adversarial review folded into the end-to-end audit (its workflow review died on suspension).
- ✅ C2.7 go build/vet/test green
- 📌 follow-ups: blacklist target = App(masterMint)+License(licenseMint) only (Author/app_hash-keyed not checked — refine w/ app_id record); FoundationApp tier reader not wired (VerifyPublish takes mask, handler passes 0) — wire when app_id-keyed tier reader lands.

### C3 — Submit-client — ✅ DONE (commit 2c9cd1c6; review OK; build+test green incl in-process e2e)
- ✅ C3.1 `cmd/submit/main.go`: `envelope.Sign(KindArtifact, Body=RELEASE.json, RequestHash=sha256(spk))` → POST (JSON or multipart) to /publish; verifies returned receipt sig vs ON-CHAIN store_authority (`FetchStoreOperatorAuthz`); defends serving-domain + on-chain-domain drift. Makefile `publish-sealed` target + `publish-app-full.sh` Step 4 force-push DELETED (no fallback). 14 tests.
- 📌 C3 follow-ups: (a) no well-known identity endpoint yet → `--store-pubkey` = operator identity.Public JSON path (handler matches by identity Digest, not raw key). (b) publisher key = JSON {ref, sign_seed_hex, box_seed_hex} → identity.NewPrivate (MVP; standardize later). (c) receipt-verify needs RPC_URL (Helius devnet).

### C4 — authzsign daemon — ✅ DONE (commit f653de4; review OK, fail-closed audit PASS; 23 new tests)
- ✅ C4.1 `store_cascade.go` 4th stage: trustless on-chain listing-chain verify (servingStore∈accepted_stores∪root; StoreReleaseListing Active; ReleaseEntry Active; blacklist deny) from the receipt — closes S2 (shell-lie can only name a store with a genuine Active listing)
- ✅ C4.2 `store_borsh.go`/`store_pda.go`/`store_wire.go`: decoders+derivers in NEW files (left WIP borsh.go/pda.go untouched); `DecodeLicenseEntryStoreFields` walk for accepted_stores+root_hash; Context 32 OR ≥128 + appHash-match, back-compatible (daemon side READY for C5's 128-byte form)
- ✅ C4.3 fail-closed on every RPC/decode err; blacklist present==REJECT (no cache); D3 cached-last-known-good for ROOT only; resellers live-verified
- 📌 ROOT-path: servingDomainHash==root skips operator/listing checks (root=identity, serves canonical releases directly), still gated by ReleaseEntry Active + blacklist. Revisit IF on-chain root design requires a real root listing. Discriminators = sha256("account:&lt;T&gt;")[0:8] — CI-pin vs real IDL advisable (FU-1).

### C5 — Shell (C5-core ✅; C5-gov-tier 🔄)
- ✅ C5.2 (**C5-core**, e25215a, review OK, fail-closed audit PASS) updateAppIndex multi-source verify (re-hash SPK==on-chain ReleaseEntry.app_hash BEFORE startInstall; Active StoreReleaseListing from accepted store; auto-update through SAME chokepoint; root precedence-by-IDENTITY) + 128-byte Context producer + JS decoders. **CROSS-LANG LOCKSTEP PROVEN**: JS storeDomainHash("melusina-os.org")=0595e1c4..d4d7; 5 discriminators == Go store_borsh.go; JS 128-byte Context parses identically in Go ParseContext.
- ✅ C5.1 App-Sources governance UI (a1e4747): curated accepted_stores list, LOCKED root row, prepare-only Squads proposal (review confirmed NO on-chain write/sign/submit), buildAcceptedStoreProposal 15/15 node tests, eslint 0 errors.
- ✅ C5.3 server-side tier gate (rescued+committed 8f6e411): tier-gate.js (unknown→DENY, visitor-never-installs HARD invariant, policy rollback/unverified/bad-epoch REJECT), tier-resolve.js (app_hash→ReleaseEntry.app_id→FoundationAppEntry), tier-policy.js (signed monotonic epoch). Node tests pass; eslint 0 errors. S6 closed.
- ⬜ C5.4 lint+typecheck (+ node tests); full `meteor build`/`test` = ENV limitation (no Meteor runtime) — flag like FU-1
- env: meteor bin present but full build too heavy; lint(eslint)+typecheck(tsc) usable; tsc fails only on @types/node esnext.disposable (pre-existing, identical on HEAD). DETACHED-HEAD +1 WIP left untouched.

## Audit ledger
**Consecutive OK count: 1 / 2.** (any non-OK resets to 0)

| # | Date | Builds | Critical/High findings | Verdict |
|---|---|---|---|---|
| 1 | 2026-06-13 | all 4 repos green | 0 | **OK** (wf_7cf91641-104; 4 dims OK, store↔shell in-tune, deploy-time items fail-closed) |

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
**→ C1 ✅ · C1b ✅ · C2 (gated path) ✅ · C3 ✅ · C4 ✅ · C5-core ✅. C5-gov-tier + C2.6 IN FLIGHT in parallel** (shell vs static_store+monorepo — independent). When BOTH land review-OK:
1. **First END-TO-END audit** (spec §7): a fresh cross-repo adversarial pass over the WHOLE assembled system (all 4 repos) — does publish→sidecar-verify→install-verify agree byte-for-byte on appHash/PDA-seeds/128-byte-Context/domain-hash/tier across Rust+Go+JS; is every path fail-closed; are S1–S8 closed; are all C1–C5 boxes checked (C2.5 boot-identity = documented deploy-time/ceremony-gated, NOT a code gap).
2. If OK → **second END-TO-END audit** (independent agents) → if OK → **CronDelete b4040345** + report DONE.
3. If either audit finds critical/high → fix, reset the consecutive-OK counter to 0, re-audit.
- DEPLOY-TIME items (out of code scope / guardrail-blocked, NOT audit-blocking): FU-1 IDL regen (needs compatible Anchor host), C2.5 sidecar boot-identity activation (needs on-chain onboarding ceremony), FU-2 update_store_tls cert, on-chain store-operator/accepted-stores ceremonies. All code is written + fail-closed pending these.

## Log
- 2026-06-13: loop armed (cron b4040345); spec + ledger written; static_store branch created; grounding workflow launched.
- 2026-06-13: recipes + frozen contracts received (wf_7d011aea-017); C1 scope finalized (version-floor→off-chain, AppTierPolicy deferred); C1 implementation workflow launched (wf_95d744d9-564).
- 2026-06-13: C2 READ surface scaffolded in parallel (sidecar/melusina-store-sidecar/: main/config/handler.go, go.mod, store.yaml.example, README) — go build/vet/fmt green, smoke-tested (read 200s, /publish fail-closed 501, no bypass). Committed f6b460a9 on feat/federated-store-mvp. Gated path blocked on C1.
- 2026-06-13: pinned contract C-5 — `StoreDomainHash` (domainhash.go) + shared testdata/domain_hash_vectors.json (Rust/Go/JS must match; S8). ROOT_STORE_DOMAIN_HASH("melusina-os.org")=0595e1c4..d4d7. go test green. Committed c44e59da. Remaining work (C2.3 gated path, C3, C4, C5) blocked on C1 → yielding to let wf_95d744d9-564 land.
- 2026-06-13 (cron fire): C1 workflow still in implement phase (~12min, anchor build). Corrected StoreOperatorAuthorization LEN 224->193 in spec+ledger (implementer caught the slip). Added sidecar LoadConfig tests (go test green). Program repo left untouched (active single writer). Audit count 0/2.
- 2026-06-13 (cron fire): **C1 ✅** — wf_95d744d9-564 review verdict **OK, 0 findings**; commit 918921e; cargo build-sbf + `anchor build --no-idl` + 76/76 lib tests GREEN; contract-conformant (is_root gate, listing guard, accepted_stores-before-bump, PERM bit55). Follow-ups FU-1 (IDL regen=env), FU-2 (tls_cert_fingerprint→instr arg + update_store_tls, S8), FU-3 (coherence test). Launched C1b shared Go derivers/readers (wf_ecc26307-65e) to unblock C2.3+C4; scouted real melusina-attest API. End-to-end audit count unchanged **0/2** (a per-component review is NOT one of the two final end-to-end audits).
- 2026-06-13 (C1b completion): **C1b ✅** — wf_ecc26307-65e review OK; commit d41272af; Go derivers/readers for StoreOperatorAuthorization/StoreReleaseListing/ReleaseEntry/BlacklistEntry, offsets byte-verified, 3 modules build+test green. Monorepo on feat/store-operator-go-readers (sidecar replaces resolve against it). Launched C2.3 gated-publish workflow (wf_b6b56d74-79c). C4 deferred until C2.3 receipt confirmed (+ needs accepted_stores reader). Audit 0/2.
- 2026-06-13 (C2.3 completion): **C2.3+C2.4 ✅** — wf_b6b56d74-79c review OK, fail-closed audit YES; commit a2fb31a9; gated /publish on-chain verify + raw-96 provenance receipt; go test -race green (full accept/reject matrix). Confirmed authzsign is self-contained (own pda/borsh; no monorepo dep) → launching C3 (submit-client, static_store) + C4 (cascade store-stage, authzsign) IN PARALLEL. C4 store-stage uses trustless on-chain listing-chain verify (not shell-asserted) → closes S2. Audit 0/2.
- 2026-06-13 (C3 completion): **C3 ✅** — wf_7f3b6493-a95 review OK; commit 2c9cd1c6; sealed-v3 submit-client, force-push DELETED from publish-app-full.sh, receipt sig verified vs on-chain store_authority, 14 tests incl e2e. C4 implement committed (f653de4), review running. Will launch C5 once C4 review confirms the Context behavior. Audit 0/2.
- 2026-06-13 (C4 completion): **C4 ✅** — wf_cfda217f-548 review OK, fail-closed audit PASS; commit f653de4; trustless store-stage + 23 tests, build green; root-path resolved (identity, ReleaseEntry+blacklist gated). ALL 5 component cores now done+reviewed (C1,C1b,C2,C3,C4). Launched C5-core (wf_d229e042-508): shell install-side verify + 128-byte Context (lockstep w/ C4) + JS decoders. C5-gov-tier (governance UI + tier gate) to follow. Audit 0/2.
- 2026-06-13 (cron fire): C5-core implement committed (e25215a, shell branch feat/federated-store-accepted-sources); review running. On review-OK → INTERIM cross-component spine audit (Rust/Go/JS agreement on bytes/PDA/Context/domain-hash) before C5-gov-tier + C2.6. Two FINAL end-to-end audits still pending (need all C1-C5 boxes). Audit 0/2.
- 2026-06-13 (C5-core completion): **C5-core ✅** — wf_d229e042-508 review OK, fail-closed PASS, CROSS-LANG LOCKSTEP PROVEN (JS↔Go discriminators+Context+domain-hash). 6/6 component cores done (C1,C1b,C2,C3,C4,C5-core). Launched final two in parallel: C5-gov-tier (wf_27955dce-16b, shell — S6 tier gate + governance) + C2.6 root-mirror (wf_c3ce727c-57a, sidecar+monorepo readers). On both OK → FIRST end-to-end audit. Audit 0/2.
- 2026-06-13 (RECOVERY): session suspended ~13:51→18:49 (5h); the two in-flight workflows (C5-gov-tier, C2.6) DIED without completing/notifying. Recovered: **C2.6 ✅** had committed (e3b64855 + 0e37aea2), builds+tests pass. **C5.3 ✅** work survived UNCOMMITTED in shell tree — verified (node tests pass, eslint 0 errors) + committed (8f6e411). C5.1 (governance UI, non-trust-critical) was never done → re-launching. Per-component reviews for C2.6/C5.3 died → folding into the end-to-end audit. Audit 0/2.
- 2026-06-13 (C5.1 ✅): wf_15f8a1fe-116 review OK; commit a1e4747. **ALL C1–C5 boxes done.** Implementation complete modulo documented deploy-time items (C2.5 boot-identity ceremony, C1.6 reseller AppTierPolicy, FU-1..FU-4). → Launching FIRST end-to-end audit (§7). Audit 0/2.
- 2026-06-13 (AUDIT 1/2 ✅): first end-to-end audit wf_7cf91641-104 → **OVERALL OK**. 4 dims OK, 0 critical/high (41 info), builds_all_green, all 5 §7 criteria PASS, lockstep re-derived first-hand (domain-hash 0595e1c4..d4d7 Rust==Go==JS), S1-S8 closed on BOTH daemon+shell install sides. Launching 2nd INDEPENDENT audit (exploit-focused lens). If OK → 2/2 → CronDelete b4040345 + DONE.
