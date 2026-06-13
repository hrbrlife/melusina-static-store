# Federated Verifying Store — MVP Implementation Spec

> Authoritative contract for the federated, license-gated, multi-store verifying-sidecar.
> This is the rubric the adversarial audits check "fully implemented" against.
> Companion state/ledger: `FEDERATED-MVP-PROGRESS.md`. Synthesis origin: workflow `wf_bcc3d11d-3f6` (2026-06-13).

## 0. The load-bearing invariant

**Trust is decided at the INSTALL's boundary by reading the chain — never by trusting what a store says about itself.**
A store sidecar's receive-side checks protect the *operator* from bad publishers; they do nothing against a *malicious operator*. Only the install, reading on-chain `ReleaseEntry` + `StoreOperatorAuthorization` + a **store-signed provenance receipt**, makes a rogue reseller harmless. Every design decision below serves this invariant.

## 1. Corrected on-chain ground truth (verified against program source 2026-06-13)

Program: license-registry `7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb`, repo `/home/user/Desktop/Melusina/melusina_solana_dev-license104`. See memory `onchain-federation-ground-truth`.

**Already shipped — reuse, do NOT rebuild:**
- `ReleaseEntry`/`release_v2` (`state/attestation.rs:29`): `app_hash:[u8;32]`, `release_hash:[u8;32]`, seeds `["release_v2", master_nft_mint, app_hash]`; register handler **verifies the author ed25519 sig on-chain** via the instructions-sysvar precompile (`verify_ed25519_ix_at`). NOT theater. (Legacy `ReleaseRecord` in `state/release.rs` IS the old theater object — ignore.)
- Global→Reseller→Local cascade (apps + sidecars) + cascade-revoke; `InstallerReleaseEntry` (base-binary pin, Master-NFT-only, `attestation.rs:282`); `FoundationAppEntry` (basic apps, **Core/Standard tier**, keyed by app_id, `foundation.rs:44`); `SidecarIdentityEntry`/`AppSidecarAuthorization`; per-install Squads custody on `LicenseEntry`; `InstallAdminEntry`; perm bits used ≤54, **55–63 free** (`permissions.rs:96`); shell live cascade verify (`authzsign cascade.go`); Squads v4 ceremony (`pearl-onchain-submit.js`).

**Must build (the real gaps):**
- `register_store_release_listing.store_authority` is a **bare unguarded `Signer`** (`instructions/attestation.rs:1090`) — anyone can list. → new `StoreOperatorAuthorization` PDA + guard.
- No per-install accepted-stores set (shell uses one `appIndexUrl`); no store-origin awareness in `cascade.go`; `GlobalAppApproval` has **no tier**; no monotonic version floor; cascade reads neither `StoreOperatorAuthorization` nor `BlacklistEntry`; store still gh-pages force-push (no verifying sidecar / single writer).

## 2. Decisions (defaults; user may override)

| # | Decision | MVP default |
|---|---|---|
| D1 | Reseller publishes its **own** app | **Foundation co-signs** the `ReleaseEntry` mint (no new origination authority for MVP). Resellers *operate stores that list* canonically-attested releases. |
| D2 | Root identity mobility | **Foundation-rotatable PDA**, write-gated to Master-NFT, with kill-switch + program-const fallback. |
| D3 | Live on-chain verify at install | **Live for reseller stores; cached-last-known-good for root + basic apps** (chain outage must not brick base functionality). |
| D4 | Multi-tenant sidecar | **One process per license** for v1. |

## 3. Architecture resolution (settled conflicts)

- Resellers do **not** originate releases; they create `StoreReleaseListing`s over already-attested `ReleaseEntry`s.
- **Domain binding lives on `StoreReleaseListing`, never in the release signature** — preserves legitimate mirroring (one canonical release, many stores) and avoids per-store re-signing.
- One owner per responsibility: store-operate = `StoreOperatorAuthorization`; trusted stores = `LicenseEntry.accepted_stores` (Squads-governed, root pinned in code); user-level = on-chain app→tier ceiling (app_id-keyed) + signed install policy enforced server-side; single writer = the sidecar; "are these the attested bytes" = the install, on-chain, at fetch.

## 4. Components & acceptance criteria (the "fully implemented" checklist)

### C1 — Anchor program (`melusina_solana_dev-license104`, branch `feat/store-operator-authz`)
- [ ] `StoreOperatorAuthorization` PDA, seeds `["store_operator", license_nft_mint, store_domain_hash]`; fields `{license_nft_mint, store_domain_hash:[u8;32], store_authority:Pubkey, tls_cert_fingerprint:[u8;32], is_root:bool, allowed_tier_mask:u8, max_listings, status, authorized_by, authorized_at, revoked_at, bump}`. **LEN=193** (8+32+32+32+32+1+1+4+1+32+8+(1+8)+1), mirrors `reseller_approval.rs` shape.
- [ ] `authorize_store_operator` / `revoke_store_operator` instructions. `is_root=true` ONLY under Master-NFT custody and only for the pinned root domain_hash; otherwise requires operator `LicenseEntry` Active + reseller chain Active + InstallAdmin bearing `PERM_STORE_OPERATE`, license-Squads co-sign for admin/infrastructure tiers.
- [ ] Guard `register_store_release_listing`: require `store_authority == an Active StoreOperatorAuthorization.store_authority` whose `allowed_tier_mask` covers the app; persist `store_domain_hash` + `operator_authorization` on the listing.
- [ ] `PERM_STORE_OPERATE = 1<<55`; mirror into `idl/MelusinaPermissions.capnp`; `permission_bit_coherence_test` green.
- [ ] Monotonic version floor: mark prior app_hash `Superseded` at `register_release_entry`; verify path denies non-Active parents incl. `RevokingCascadeInProgress`.
- [ ] On-chain app→tier ceiling readable per app_id (extend `FoundationAppEntry` pattern or add an app_id-keyed record; do NOT key the ceiling by app_hash).
- [ ] **`anchor build` green; existing + new unit tests pass.**

### C2 — Store sidecar (`static_store`, branch `feat/federated-store-mvp`)
- [ ] `melusina-store-sidecar` (Go) — one reusable artifact; per-operator config `store.yaml {license_nft_mint, domain, store_id, reseller_nft_mint?, root_store_url, policy{allowed_tiers, require_scan_report, accept_publishers[]}, rpc_url, listen_addr, tls}` + 3 attest shards.
- [ ] **READ surface byte-identical** to today's `dist-publish/` (SPA, `/apps/index.json`, `/attest/`, `/packages/`, `/verifier/`), public/unauthenticated.
- [ ] **Gated WRITE** `POST /publish` (sealed-v3 envelope from attested publisher) → REAL on-chain verify in Go (re-hash SPK == `ReleaseEntry.app_hash`; PDA Active; ed25519 already chain-verified; blacklist clear; version floor) → **single writer** (invoke `build-store.sh` as in-process assembler, not the trust authority). Emits a **store-signed provenance receipt** `{appHash, releaseHash, servingDomainHash}` signed by operator key.
- [ ] Offline/skip bypasses (`MELUSINA_ATTEST_OFFLINE`, `SKIP_STEPS`, `SCAN_NOOP`) **compiled out of the receive path**.
- [ ] Boots only if `store.yaml.domain == SidecarIdentityEntry.domain_hash` and TLS SPKI == on-chain `tls_cert_fingerprint`.
- [ ] Reseller root-mirror worker: re-verify `InstallerReleaseEntry`/`FoundationAppEntry` + serve identical root bytes under origin marker; never originate root.
- [ ] **`go build`/`go test` green.**

### C3 — Submit-client (`static_store`)
- [ ] `make publish <storeurl>` → packs SPK, computes appHash, optional local on-chain pre-check, wraps canonical RELEASE.json in sealed-v3, POSTs to `<storeurl>/publish`; streams accept/reject with failing check named. Force-push path deleted.

### C4 — authzsign daemon (`melusina-authzsign-component`, branch `feat/cascade-store-stage`)
- [ ] `cascade.go` gains a 4th **store stage**: derive serving store from a **store-signed provenance receipt** (not a shell-asserted field), require Active `StoreOperatorAuthorization` ∈ `accepted_stores ∪ {root}`, require Active `StoreReleaseListing[store, appHash]`.
- [ ] Verify path reads `BlacklistEntry`; denies `Superseded`/below-floor versions; root-class apps require root store; cached-last-known-good fast-path for root (D3).
- [ ] **`go build`/`go test` green.**

### C5 — Shell (`sandstorm-b31/shell`, branch `feat/federated-store-accepted-sources`)
- [ ] `LicenseEntry.accepted_stores` governance: App-Sources panel becomes a curated list (root row locked); add/remove = Squads proposal, not Mongo write.
- [ ] `updateAppIndex()` multi-source: fetch from each accepted store; **re-hash SPK == on-chain app_hash + Active listing from accepted operator** BEFORE `startInstall`; route auto-update through the same chokepoint; root-class apps precedence-by-identity (never shadowed by a reseller version bump).
- [ ] Server-side tier gate at install/launch/download keyed on on-chain tier ceiling vs requester level, fail-closed; **visitor never gets an install surface** (hard invariant); signed `tier-policy.json` with on-chain monotonic epoch.
- [ ] Shell builds; relevant tests pass.

## 5. Safety bar (must close — from the red-team)

- **S1** Malicious sidecar → install verifies chain itself (C4/C5). **Showstopper.**
- **S2** Confused-deputy provenance → store-signed receipt verified by daemon (C2/C4). **Showstopper.**
- **S3** Reserved-root leak → `FoundationAppEntry(Core)`/`InstallerReleaseEntry` authoritative set + precedence-by-identity + program-pinned root (C1/C5). **Showstopper.**
- **S4** Downgrade → monotonic version floor at publish + install (C1/C2/C4/C5). **Showstopper.**
- **S5** Revocation propagation → store + blacklist reads, WS-invalidate, client re-verify installed apps, rotation revokes prior key.
- **S6** Tier UI-only → server-side enforcement, visitor invariant.
- **S7** Publisher report advisory only → sidecar sole authority, attested separate scanner, bypasses compiled out.
- **S8** Foot-guns → length-tolerant Borsh decoder + atomic migration + root cached-fast-path; one canonical `host→domain_hash` with cross-lang coherence test.

## 6. Build order
Phase 1 (spine, one store): C2 read+verify+single-writer + C3 submit-client — kills the "hot mess" before federation. → Phase 2: C1 store-operator primitive + C4 install-side trust (S1/S2). → Phase 3: root + downgrade + revocation (S3/S4/S5). → Phase 4: C5 tier server-side (S6). → Phase 5: paired `melusina-publish` + sandboxed attested AV (S7).

## 7. Audit rubric (an audit returns OK only if ALL hold)
1. Every C1–C5 box checked in `FEDERATED-MVP-PROGRESS.md` with evidence (file:line).
2. All four repos: builds green; new + existing tests pass (no skips of relevant tests).
3. Zero **critical/high** findings from adversarial review vs §0/§5 (store↔shell in tune: the bytes/PDA/provenance/version/tier checks agree end-to-end).
4. No live bypass (`MELUSINA_ATTEST_OFFLINE`/`SKIP_STEPS`/`SCAN_NOOP`) reachable on any receive/verify path.
5. Guardrails honored: branch-only, nothing pushed/deployed, no on-chain ceremony run.

**DONE = two CONSECUTIVE OK audits.**

## 8. Guardrails (hard limits for the autonomous loop)
Branch-only in all repos; **never** push, deploy, run on-chain ceremonies, or RPC writes; do not disturb other repos' existing WIP branches/working-tree changes; surface anything ambiguous in the ledger rather than guessing destructively.
