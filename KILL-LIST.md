# KILL LIST — Melusina bazaar standardization (greenfield)

> **Purpose:** single-document handoff to align every Melusina bazaar app around a fixed set of ten `github.com/hrbrlife/melusina-<name>-component` repos. Greenfield: no legacy data, no prior users, no migration shims. An engineer picking this up from scratch should be able to execute it end to end.
>
> **Scope horizon:** ~25 engineer-days of serial work; critical path ~15 days; realistic wall time with 3 engineers ~3 calendar weeks (not 2 — see Sec. 9).
>
> **Non-goals:** preserving any existing grain state, migrating users across schema versions, keeping deprecated APIs alive. Every grain boots empty.

---

## 0. Pre-flight facts (trust, don't re-verify)

Anchored in a two-iteration audit at 2026-04-22.

1. **`grainrestore` already exists** at `/home/user/Desktop/grainrestore/` as Go module `github.com/melusina/grainrestore`. **Namespace is wrong.** No new extraction is needed — only rename + bugfix + promotion.
2. **`grainrestore` has two production-blocking bugs** (Sec. 4): `RegisterKeyRewrap` is registered but never invoked at restore; `ResignDecision` modes (Keep/Replace/Migrate/Drop) are inert — the hook is called with empty args and its return is discarded.
3. **`grain-crypto-journal`** is already under the correct namespace (`github.com/hrbrlife/grain-crypto-journal`). Canonical working copy: `/home/user/Desktop/Melusina/shared/grain-crypto-journal/`. Vendored into 27+ apps via submodule + in-tree copies that must be deleted.
4. **`grain-e2e-binding`** is at `/home/user/Desktop/Melusina/shared/grain-e2e-binding/` as `github.com/melusina-os/grain-e2e-binding` — a **different wrong namespace** from grainrestore's `melusina/`. Both must move to `hrbrlife/`.
5. **`melusina-Solana-primitives` and `melusina-identity-gate`** live at `melusina-os/` namespace inside `/home/user/Desktop/Melusina/shared/`. **Zero consumers today.** Both must either be promoted to hrbrlife repos (if we actually use them) or archived (see Sec. 8 decisions).
6. **`melusina-spkmodule-component`** already exists as `github.com/hrbrlife/melusina-spkmodule-component`; apps mount it as a submodule at `./spkmodule/`.
7. **Real current consumers of grainrestore** (go.mod grep): `ccash_go_htmx`, `melusina-NamedCoin-admin-app`, `melusina-NamedCoin-app`. That is the entire set. PHASE-STATUS.md claims five; wrong.
8. **Sandstorm restore mechanics:** backup is an unencrypted ZIP of `/var` + `GrainInfo`; restore mints a new grainId; no restore hook. GrainId is read from `/var/grainid` (and `SANDSTORM_GRAIN_ID` env fallback). `X-Sandstorm-Grain-Id` HTTP header does **not** exist.

---

## 1. Target component roster (final state)

**Eleven repos** under `github.com/hrbrlife/`. Every grain-packaged app consumes `melusina-spkmodule-component` as a submodule; implicit from here on.

| # | Final repo name | Import path | Owns | Depends on |
|---|---|---|---|---|
| 1 | `melusina-spkmodule-component` | (submodule; not a module) | Canonical Makefile discipline: `mount → verify inodes → spk pack → spk verify → publish-to-branch`. `.spkmodule-hooks/` API. Icon/manifest scaffolding. Pre-pack capability static check. | — |
| 2 | `melusina-capnp` | `github.com/hrbrlife/melusina-capnp` | Single source of truth for every `.capnp` schema: `grain-authz`, `botmother`, `agentchat`, `payment`, `wallet`, `audit`, `ai`, `kyc`, `notification`, `storage`, `identity`, `station`, `supervisor`, `telegram`, `static-publish`, `document`, `workflow`, `instance`, `testcap`, `gohtmx`, `casemeta` (21 schemas). Auto-generated Go/TS/Py bindings via CI. | — |
| 3 | `melusina-grain-crypto-journal-component` | `github.com/hrbrlife/grain-crypto-journal` | `keybox.Manager` (Rewrap/ClearAuthorizedKeys/ResetBinding/UnsealPathB), `sqlitestore.Store` (AES-256-GCM + hash-chained `Audit`), binding state machine, JS twin. | — |
| 4 | `melusina-Solana-primitives-component` | `github.com/hrbrlife/melusina-Solana-primitives` | **Canonical PDA seed lock** — InstallAdminEntry, OrganizationMemberEntry, LicenseEntry, GlobalAppApproval, ResellerAppApproval, LocalAppApproval, GlobalSidecarApproval, ResellerSidecarApproval, LocalSidecarApproval, ContractWhitelist, AppContractPair, DomainClaim. Plus base58, PDA derivation, Ed25519 helpers. Single source of truth prevents silent auth bypass from seed drift. | `filippo.io/edwards25519` |
| 5 | `melusina-identity-gate-component` (+ `-py` sibling) | `github.com/hrbrlife/melusina-identity-gate` | Canonical envelope v1/v2 parser, Ed25519 verification, on-chain PDA checks (InstallAdminEntry / OrganizationMemberEntry / app-cascade / sidecar-cascade), policy engine (route → resource-policy → signer quorum), nonce cache (10 min TTL, claim-once). The four-app cross-app authorization contract is pinned against this module. | #4 |
| 6 | `melusina-grain-auth-component` | `github.com/hrbrlife/melusina-grain-auth/go` + npm `@melusina/grain-auth` + PyPI `melusina-grain-auth` | Three-language Cap'n Proto admin authz sidecar client. Fail-closed middleware. ≤500 ms UI perms TTL. Ed25519 verification. Schema-coherence CI. | #2, #3, #4, #5 |
| 7 | `melusina-http-component` | `github.com/hrbrlife/melusina-http-component/go` | Canonical Sandstorm HTTP-out + PowerBox. `BuildHTTPOutDescriptor`, 4-variant sidecar selector, `PowerboxManager` with mandatory `SandstormApi.drop(token)`. | #3 |
| 8 | `melusina-grain-e2e-binding-component` | `github.com/hrbrlife/grain-e2e-binding` | E2E wallet-binding protocol: keybox ↔ wallet for Path-B recovery, binding/migration state, authorized-key sync. | #3, #4 |
| 9 | `melusina-grain-restore-component` | `github.com/hrbrlife/melusina-grain-restore` | **v0.1.0 scope: same-machine restore only** (persona remap). `Open/Register*/Mount/CaptureOnBackup/RewriteOnRestore`, dispatch matrix, manifest. **Both current bugs fixed** (Sec. 4). Cross-machine migration deferred to v1.0.0 per Sec. 4.6. | #3, #8, #6 |
| 10 | `melusina-e2e-test-component` | PyPI `melusina-e2e` | Browser-driven E2E harness, screenshot store, Sandstorm shell helpers. Orchestrates 23-scenario constellation tests including TeleScreen C4. | `melusina-grain-auth-py` |
| 11 | `melusina-bureau-shell-component` | npm `@hrbrlife/bureau-shell` | Shared Bureau chrome, document-picker, zip export, **snapshot API** (CRUD + Ed25519 signature column reserved for v0.2.0 Solana-tied signing). Content-addressed blob storage at `/var/snapshots/<first2>/<hash>.blob`. | #3, #7, #6 |

**Out-of-scope of this kill list but documented in Sec. 12 / 13:**
- `melusina-Fineract-sidecar` — already correct namespace, unrelated to standardization.
- `mermail-sidecar` — dedicated to mermail-station-app; stays app-local unless a 2nd consumer appears.
- `pr_ninja` / TeleScreen — **core sidecar, operational** (897 LOC Python, FastAPI, 12+ OSINT providers, 364 tests). Infrastructure-adjacent; not a Bucket 3 target. Consumes #5 identity-gate. See Sec. 13.
- `miniapp-static` — shared static JS scaffolding for clientspace-style apps. Kept as a utility submodule, not a numbered component.
- `melusina-license-component` — legal artifact mounted as `LICENSE/` submodule across several apps. Not code.
- `go-sandstorm`, `go-util` — third-party zenhack forks; pinned, never standardized.

### 1a. Post-KILL-LIST shipped components

Extracted after the original 11 planned above. Both under `hrbrlife/`; each tagged v0.1.0 on 2026-04-22 and bumped to v0.1.1 on 2026-04-23.

| # | Final repo name | Import path | Owns | Depends on |
|---|---|---|---|---|
| 12 | `melusina-static-publish` | `github.com/hrbrlife/melusina-static-publish` | Static-publishing primitives (HMAC tokens, key + session types, path-safety, canonical `/published/{keyID}/{subKey}/` layout) and stateful `service.Service` (expiry math, BurnAfterRead, pluggable Store, cleanup loop, ExpireHook). v0.1.1 fixes the keyID-omission write-path bug and adds `ResolveKeyID`. Capnp server subpackage deferred to v0.2.0. | — |
| 13 | `melusina-notify-sandstorm` | `github.com/hrbrlife/melusina-notify-sandstorm` (Go) + npm `@hrbrlife/melusina-notify-sandstorm` (TS; not yet published) | Sandstorm activity-notification dispatch via `sandstorm-helper`. Canonical wire payload (`sessionId, path, caption, activityType, thread, recipients, bridgeSocket`). Factory auto-selects `NoopService` when the helper binary is absent. v0.1.1 propagates first-attempt errors to concurrent `EnsureIdentity` waiters and trims `Event` to only wire-serializable fields. | — |

**Consumers (as of 2026-04-23):**
- `melusina-static-publish`: **Service-tier consumer** — `melusina_botmother` (full `service.Service` delegation via journal adapter). **Primitives-only consumers** — `cyberteller` (uses HMAC + path helpers, does its own write via `FilePublisher`). Deferred: grain-instance template.
- `melusina-notify-sandstorm`: `ccash_go_htmx` (policy + factory wired; real dispatch activates only when the helper binary is present).

---

## 2. Current state inventory

### 2.1 Component namespace status

| Component | Current path | Current module | Correct? | Action |
|---|---|---|---|---|
| grain-crypto-journal | `Melusina/shared/grain-crypto-journal/` | `github.com/hrbrlife/grain-crypto-journal` | ✓ | **SHIPPED** — v0.1.0 + v0.1.1 tagged and pushed. 15+ consumers still use `v0.0.0 + local replace`; bumping each is consumer-by-consumer port work (see instaco.app / vintage-test-dec below), not a mass task. |
| grainrestore | `/grainrestore/` → now `hrbrlife/melusina-grain-restore` | `github.com/hrbrlife/melusina-grain-restore` | ✓ | **SHIPPED** — v0.1.0 + v0.1.1 tagged. Consumers: ccash + 2 NamedCoin apps. |
| grain-e2e-binding | `Melusina/shared/grain-e2e-binding/` (monorepo copy) + standalone at `hrbrlife/grain-e2e-binding` | `github.com/hrbrlife/grain-e2e-binding` (standalone) | ✓ | **SHIPPED** — standalone v0.1.0 live. Monorepo copy still declares `melusina-os/` but is effectively legacy; `hrbrlife/` is canonical. 3 consumers (instaco.app, vintage-test-dec, store-rebuild duplicate) still pin `melusina-os/ v0.0.0 + replace` — consumer port jobs, not a tag op (API diverged: `UserContext.WalletChain`, `HasLegacyPIN`, `WalletPubkey`, `keybox.GetUserKey`, `RegisterWalletUser` all removed before v0.1.0). |
| melusina-Solana-primitives | `_killlist_staging/melusina-Solana-primitives/` (canonical); `Melusina/shared/melusina-Solana-primitives/` (stale source copy, delete) | `github.com/hrbrlife/melusina-Solana-primitives` | ✓ | **SHIPPED** — v0.1.0 tagged and pushed; Go proxy resolves. Zero consumers today. The `melusina-os/` GitHub repo never existed (404). |
| melusina-identity-gate (+ `-py` sibling) | `_killlist_staging/melusina-identity-gate/` (Go) + `_killlist_staging/melusina-identity-gate-py/` (Python) | `github.com/hrbrlife/melusina-identity-gate` (Go) + `github.com/hrbrlife/melusina-identity-gate-py` (Py) | ✓ | **SHIPPED (Go)** — v0.1.0 tagged, ccash consumes it directly on the tag (no replace). **Py side:** repo + v0.1.0 + v0.1.1 tagged; wheel+sdist built at `dist/melusina_identity_gate-0.1.1-*`. **PyPI publish pending** user auth. |
| melusina-grain-auth | `/melusina-grain-auth/` | `github.com/hrbrlife/melusina-grain-auth/go` + `@hrbrlife/grain-auth` (npm, package.json 0.1.1) + `melusina-grain-auth` (PyPI, pyproject 0.1.1) | ✓ | **SHIPPED (Go)** — `go/v0.1.0` + `go/v0.1.1` Git tags live; Go proxy resolves. Consumers: cyberteller + ai-lagoon pinned at v0.1.1. **npm publish pending** user auth (dry-run `npm pack` green — 16 files, 7.7 kB). **PyPI publish pending** user auth (wheel+sdist built at `py/dist/`). |
| melusina-http-component | `/melusina-http-component/` | `github.com/hrbrlife/melusina-http-component/go` | ✓ | **SHIPPED** — v0.1.0 tagged (`v0.1.0` + `go/v0.1.0`); Go proxy resolves; `grain-crypto-journal` pinned at v0.1.0 (no sibling replace). Consumers: cyberteller + ai-lagoon pinned at v0.1.0. |
| melusina-e2e-component | `/melusina-e2e-component/` | PyPI `melusina-e2e-component` (pyproject name; not `melusina-e2e` as originally roster'd) | ✓ | **SHIPPED (git)** — v0.1.0 tagged + pushed. Wheel + sdist pre-built at `dist/melusina_e2e_component-0.1.0-*`. **PyPI publish pending** user auth. |
| melusina-spkmodule-component | `_killlist_staging/melusina-spkmodule-component` (submodule source); submodules in botmother + ccash | n/a | ✓ | **SHIPPED** — v0.2.0 + v0.2.1 tagged and pushed; `.manifest` hook schema landed in v0.2.1 capability-tooling bump. |
| capnp schemas | `hrbrlife/melusina-capnp` (canonical); empty `capnp/` dirs in botmother + teleport2 | `github.com/hrbrlife/melusina-capnp` | ✓ | **SHIPPED** — v0.1.4 live with 22 canonical schemas. Primary consumers (botmother, teleport2) fully migrated, in-tree `.capnp` files removed (dirs now contain only redirect READMEs). |
| melusina-static-publish | `/melusina-static-publish/` | `github.com/hrbrlife/melusina-static-publish` | ✓ | **SHIPPED** — v0.1.1 tagged. Consumers: botmother (Service-tier), cyberteller (primitives-only). See §1a. |
| melusina-notify-sandstorm | `/melusina-notify-sandstorm/` | `github.com/hrbrlife/melusina-notify-sandstorm` (Go) + npm `@hrbrlife/melusina-notify-sandstorm` (0.1.1 in package.json; not yet npm-published) | ✓ | **SHIPPED** — Go v0.1.1 tagged. Consumer: ccash. npm publish blocked on interactive auth; run `npm publish --access public` once logged in. See §1a. |
| (new) melusina-bureau-shell-component | — | — | — | Extract from bureau app shared scaffold (#11); tag v0.1.0 |

### 2.2 Per-app roster

Adoption targets (Bucket 3): 13 apps. Deferred / out-of-scope: 5 apps (Sec. 12).

| App path | Git remote | Branch | grainrestore | grain-crypto-journal | Other shared | Status |
|---|---|---|---|---|---|---|
| `/Desktop/ccash_go_htmx` | hrbrlife/ccash_go_htmx | main | ✓ (local replace) | ✓ submodule | — | **CONSUMING** (3 dirty) |
| `/Desktop/NamedCoin-work/melusina-NamedCoin-admin-app` | hrbrlife/melusina-NamedCoin-admin-app | feat/NamedCoin-audit | ✓ (local replace) | ✓ submodule | — | **CONSUMING** (2 dirty) |
| `/Desktop/NamedCoin-work/melusina-NamedCoin-app` | hrbrlife/melusina-NamedCoin-app | feat/NamedCoin-audit | ✓ (local replace) | ✓ submodule | — | **CONSUMING** (5 dirty) |
| `/Desktop/cyberteller` | hrbrlife/cyberteller | feat/admin-auth-harmonize | ✗ | ✓ (indirect via http-component) | melusina-grain-auth, melusina-http-component | **PARTIAL** |
| `/Desktop/ai-lagoon` | hrbrlife/ai-lagoon | feat/admin-auth-harmonize | ✗ | ✓ (indirect via http-component) | melusina-grain-auth, melusina-http-component | **PARTIAL** |
| `/Desktop/instaco.app` | hrbrlife/melusina-instaco-app | main | ✗ | ✓ direct | — | **PARTIAL** |
| `/Desktop/melusina_botmother` | hrbrlife/melusina_botmother | main | ✗ | ✓ submodule (`shared/`) | — | **PARTIAL** |
| `/Desktop/melusina_teleport2` | hrbrlife/melusina_teleport2 | main | ✗ | ✓ submodule (`shared/`) | — | **PARTIAL** (stale Feb 2020; **Sec. 8 #6**) |
| `/Desktop/sailsto_system` | hrbrlife/sailsto_system | main | ✗ | ✗ | — | **VERIFY** (3 dirty, 1 unpushed) |
| `/Desktop/AITX Procedures` (+ `clientspace`, `telescreen-pearl` subgrains) | hrbrlife/AITX-Procedures | main | ✗ | ✓ submodule | melusina-e2e-component; clientspace submodule | **PARTIAL** |
| `/Desktop/openclaw-main` (Go bridge + JS) | hrbrlife/openclaw-melusina | main | ✗ | ✗ | — | **PARTIAL** (1 dirty) |
| `/Desktop/client_collection` | hrbrlife/clientspace | main | ✗ | ✗ | miniapp-static submodule | **PARTIAL** |
| `/Desktop/MiniGit` | hrbrlife/MiniGit | publish | ✗ | ✗ | — | **PARTIAL** (67 dirty on `publish`; reconcile first) |
| `/Desktop/store-rebuild/melusina-mermail-station-app` | hrbrlife/melusina-mermail-station-app | main | ✗ | ✗ | mermail-sidecar (external service) | **ADOPT** — canonical mail app (47 commits ahead of INSTASYS_MAIL; clean Melusina sidecar-consumer pattern) |
| `/Desktop/store-rebuild/melusina-bureau-doc-app` | hrbrlife/melusina-bureau-doc-app | main | ✗ | ✗ | (→ bureau-shell) | **ADOPT** |
| `/Desktop/store-rebuild/melusina-bureau-sheets-app` | hrbrlife/melusina-bureau-sheets-app | main | ✗ | ✗ | (→ bureau-shell) | **ADOPT** |
| `/Desktop/store-rebuild/melusina-bureau-paint-app` | hrbrlife/melusina-bureau-paint-app | main | ✗ | ✗ | (→ bureau-shell) | **ADOPT** |
| `/Desktop/store-rebuild/melusina-bureau-diagram-app` | hrbrlife/melusina-bureau-diagram-app | main | ✗ | ✗ | (→ bureau-shell) | **ADOPT** |
| ~~`/home/user/INSTASYS_MAIL`~~ | ~~hrbrlife/INSTASYS_MAIL~~ | ~~main~~ | — | — | — | **ARCHIVE** — superseded by `mermail-station-app` (47 commits ahead). Migrate `htmx_uiview_mail/`, `real_example/`, novel tests into mermail-station before archive. Keep `mermail-sidecar/` submodule at `/Desktop/Melusina/sidecar/mermail-sidecar/`. |

**Duplicates to delete in Bucket 4:**
- `/Desktop/store-rebuild/melusina-instaco-app` — canonical at `/Desktop/instaco.app`
- `/Desktop/store-rebuild/melusina_botmother` — canonical at `/Desktop/melusina_botmother`

---

## 3. Greenfield purge catalog

User declaration: zero legacy data, zero prior users, zero migration support. Purge before component rollout.

### 3.1 Cross-cutting deletions (Bucket 4)

- `/home/user/Desktop/Melusina/shared/` (entire tree — superseded by per-component hrbrlife repos)
- `/home/user/Desktop/grainrestore/` (renamed repo)
- `/home/user/Desktop/ccash_tmp.YxwYht/` (scratch tmp)
- `/home/user/Desktop/BLOOM_FINAL/shared/` (stale vendor; BLOOM.Community itself is a hard-NO per Sec. 12)
- `/home/user/Desktop/vintage-test-dec/` (stale scratch)
- `/home/user/Desktop/shell_tester/shared/` (stale vendor)
- `/home/user/Desktop/store-rebuild/melusina-instaco-app/` (duplicate)
- `/home/user/Desktop/store-rebuild/melusina_botmother/` (duplicate)
- Every in-tree `shared/grain-crypto-journal/` copy inside an app repo.

**Take a tarball snapshot** to `/home/user/Desktop/.kill-list-snapshots/<timestamp>/` before each deletion — Bucket 4 operations are one-way (Sec. 6.7 rollback protocol).

### 3.2 Per-app purge (Bucket 3)

**ccash_go_htmx**
- `grain-crypto-journal/keybox/fields.go` lines 13, 57–60: "ENC1:" plaintext-fallback prefix + `DecryptEventData` compat branch. **Strip** — greenfield keybox is always ciphertext.
- `grain-crypto-journal/keybox/binding_test.go`: `MigrationState`/`MigrationComplete` assertions. **Strip** — no migration state in greenfield.
- `Fineract-sidecar/upstream/mifos-web-app/`: **DELETE** — was an example reference, not load-bearing.
- **Delete `internal/httpout/`** if present — ccash now adopts `melusina-http-component` #7 (no exemption).
- Regenerate `.capnp.go` bindings from `melusina-capnp` at build time; remove generated files from version control.

**NamedCoin admin + app**
- Audit `NamedCoin/` subdir for v0 artifacts; drop if unused.
- Both on `feat/NamedCoin-audit` — finish standardization on the branch, then merge (Sec. 5 branch-order rationale).

**AITX Procedures**
- Regenerate `capnp/*.capnp.go` at build time; remove generated files from VC.
- Clientspace submodule: after #2 ships, switch to tagged Go module where possible.

**melusina_botmother / melusina_teleport2 / sailsto_system**
- teleport2: Sec. 8 #6 blocks — archive vs. adopt.
- sailsto: reconcile 3 dirty + 1 unpushed before adoption.
- All three: delete in-tree `shared/grain-crypto-journal/`; switch to tagged Go module.

**MiniGit**
- Dual-branch state: `publish` has 67 uncommitted (build-artifact branch per bazaar convention — never merges to `main`). Inspect uncommitted work; if source, cherry-pick to `main`; `git reset --hard origin/publish` on `publish` to restore artifact-only discipline. 2 unpushed commits on `main`: push or discard per owner decision.

**INSTASYS_MAIL → archive**
- `mermail-station-app` at `/Desktop/store-rebuild/melusina-mermail-station-app` is the successor (47 commits ahead, designed as pure sidecar-consumer). Before archiving INSTASYS_MAIL: migrate any novel content from `htmx_uiview_mail/` (Mailbox pearl — if still needed, spin into its own repo; otherwise discard), `real_example/` (config/DNS examples — lift into mermail-station docs), and any novel test assertions from `grain-station/`. Keep `mermail-sidecar/` at `/Desktop/Melusina/sidecar/mermail-sidecar/`.

### 3.3 Code smells to strip wherever found

- Files named `*_legacy*`, `*_deprecated*`, `*_v0*`, `*_old*`, `v1_*_compat*`
- `migrations/` SQL targeting schema v0 → v1 (greenfield starts at v1)
- Feature flags gating old/new behavior
- Go build tags `!legacy` / `legacy_schema`
- Hardcoded seed users/passwords/sessions in init
- Committed `backup.zip` / `sample-grain.zip` fixtures in prior format
- `// TODO: remove after migration` older than 30 days
- Unused exported symbols

---

## 4. grainrestore — v0.1.0 scope + bug fixes

**Scope locked:** v0.1.0 handles **same-machine restore only** (persona remap after the user remounts the grain on the same Melusina host). Cross-machine grain migration — the DNS-TXT-pinning / verifyDestination / grain-migration-receive protocol referenced in prior stubs — is **deferred to v1.0.0** per the design foreseen in `/Desktop/Melusina/sandstorm/`. Those stubs do not actually exist in the current Sandstorm source; the "transfer" codepath in `transfers-server.js` reuses the same backup-restore flow (new grainId + persona remap) as local restore.

Both bugs below must be fixed **before** the repo is renamed to `hrbrlife/melusina-grain-restore-component` and tagged v0.1.0. Fanning out a broken restore component to more apps multiplies the bug.

### 4.1 Bug A — `RegisterKeyRewrap` never invoked

**Evidence:**
- `restorer.go:153-157` — `RegisterKeyRewrap(fn)` stores the hook.
- `restorer.go:185-211` — `RewriteOnRestore` calls only `rewriteSQL` and `rewriteJSON`; no keyRewrap invocation.
- `restorer_test.go:219-232` — `TestKeyRewrapRegistration` only asserts storage, with self-incriminating comment *"The hook is stored — a real rekey ceremony invokes it."*

**Fix:** New method `(r *Restorer) invokeKeyRewrap(ctx, oldCtx, newCtx MasterKeyContext) error`. Called from `RewriteOnRestore` **after sidMap construction (~line 222) and before SQL rewrite (~line 249)**. Rationale: rewrap must complete before any code reads encrypted rows, otherwise signature verification against the stored DEK fails.

### 4.2 Bug B — `ResignDecision` modes inert

**Evidence:**
- `restorer.go:306-318` — `applyResignHook` calls the hook with `map[string]any{}` (empty row) and `""` (empty newSID), discards the returned `ResignDecision`.
- `restorer_test.go:198-217` — `TestResignHookInvoked` asserts the hook fires; never checks that Mode drives DB change.

**Fix:** Rewrite `applyResignHook` to iterate rows in the target table (scoped by `TypeEd25519Pubkey` / `TypeSignature` columns), pass the actual row + new SID, and execute the returned decision:
- `ResignKeep` — no-op.
- `ResignMigrate` — insert `NewRow` with `AuditNote`, preserving chain linkage.
- `ResignReplace` — UPDATE the row in place with `NewRow` values.
- `ResignDrop` — DELETE with audit trail.

### 4.3 Manifest schema v1 (greenfield mints one schema, no v2 bump)

Because this is greenfield, there is no prior manifest format to preserve. Mint `schemaVersion: 1` with these fields. `Open()` rejects any other schemaVersion with `ErrSchemaUnknown` — clear error, no silent downgrade.

```go
// manifest_file.go — v1 schema (greenfield)
type grainManifest struct {
    SchemaVersion     int          `json:"schemaVersion"`      // == 1
    GrainID           string       `json:"grainId"`
    InstallID         string       `json:"installId"`
    GrainKind         string       `json:"grainKind"`
    CapturedAt        string       `json:"capturedAt"`         // RFC3339Nano
    Personas          []personaRow `json:"personas"`
    InstallTrustRoot  []byte       `json:"installTrustRoot"`   // base64
    OperatorWalletPub []byte       `json:"operatorWalletPub"`  // base64
    KeyVersion        uint64       `json:"keyVersion"`
}
```

### 4.4 Consumer-side follow-through (app builds the row)

Decision locked: **app supplies `NewRow` via the Resign hook** — the library never synthesizes domain-specific audit rows.

- `ccash_go_htmx/pkg/grainrestoreadapter/adapter.go:124-129` returns `ResignDecision{Mode: Migrate, AuditNote: ...}` but `NewRow` is empty. Populate with a forward-anchor row (entry_type="restore_boundary", prev_hash=old_tail, signer_pubkey=new-signer, payload=resigning-context) before the component bug-fix lands.
- `NamedCoin-app/pkg/grainrestoreadapter/adapter.go` — same pattern; same fix.
- `NamedCoin-admin-app` — no resign hook needed (admin app doesn't hold grain keys).

### 4.5 Row-iteration scope (bounded)

Decision locked: Resign hook iterates **only rows whose FK is present in sidMap** — not every row in the table. Bounded work proportional to remapped identities, not total history.

### 4.6 KeyRewrap failure semantics (abort)

Decision locked: **abort restore** on KeyRewrap error. `RewriteOnRestore` returns early; `RestoreReport.EncryptedBlobsLost` set; consumer renders re-enrollment UI. No partial-restore state where some rows re-signed and others not.

### 4.7 Cross-machine migration (deferred)

Not v0.1.0. When implemented (v1.0.0), the protocol lives in the Sandstorm shell (`/Desktop/Melusina/sandstorm/src/sandstorm/`) not in the grain component. The grain-side contract is: accept a migration-bundle envelope at `/grainrestore/migrate-receive`, verify signed receipt + destination attestation, then run the same ceremony as local restore. Kill list is explicit this is future work; the library v0.1.0 does NOT expose a migrate endpoint.

### 4.8 Required new tests (component repo)

- `TestKeyRewrapInvokedOnRestore` — verifies hook called with correct old/new MasterKeyContext.
- `TestKeyRewrapFailureAbortsRestore` — if rewrap returns error, RewriteOnRestore returns early; report sets `EncryptedBlobsLost > 0`; no rows mutated.
- `TestResignKeepIsNoOp` / `TestResignMigrateEmitsAppSuppliedNewRow` / `TestResignReplaceOverwrites` / `TestResignDropDeletes` — one per Mode; Migrate test asserts the row inserted equals what the hook supplied in `NewRow` (byte-exact).
- `TestResignScopedToSidMapRows` — verifies that rows whose FK is NOT in sidMap are untouched; rowcount-equal, hash-equal.
- `TestManifestSchemaUnknownRejected` — `Open()` on manifest with unknown schemaVersion returns `ErrSchemaUnknown`.
- `TestSameMachineRestoreNoOp` — `manifest.GrainID == currentGrainID` → no mutations, short return.

---

## 5. Execution sequence

Each task lists its **blocker** (Sec. 8 decision that must land first) and acceptance criterion.

### Bucket 0 — Tooling & prerequisites (days 0–1, ~1.5 days)

| # | Task | Acceptance | Days |
|---|---|---|---|
| 0.1 | Build `check-pins` GitHub Action: regex over `go.mod` + `package.json` rejecting pseudo-versions and relative `replace` paths | Action lives in `melusina-spkmodule-component/actions/check-pins/`; green on ccash dry-run | 0.25 |
| 0.2 | Build `tools/schema-coherence.sh` for Go↔TS↔Py↔capnp parser comparison | Script lives in `melusina-grain-auth-component`; green on existing repo state | 0.5 |
| 0.3 | Build consumer-canary workflow template | Template in `melusina-spkmodule-component/workflows/consumer-canary.yml.tmpl` | 0.25 |
| 0.4 | Shared `.golangci.yml` | In `melusina-spkmodule-component/lint/golangci.yml`; included via submodule by every Go component + app | 0.25 |
| 0.5 | Tarball-snapshot helper `bin/snapshot.sh` (see Sec. 6.7) | Outputs to `/home/user/Desktop/.kill-list-snapshots/<ts>/` | 0.25 |

**Exit gate:** Bucket 0 artifacts are on `melusina-spkmodule-component` `main`, pending its v0.2.0 tag in Task 1.4.

### Bucket 1 — Foundations (days 1–6, ~5 days)

Critical-path ordering (serial): **Sec. 8 decisions #1–#5 → 1.1 → 1.4 → 1.2** (others may parallelize).

| # | Task | Days |
|---|---|---|
| 1.1a | Fix grainrestore **Bug A** + **Bug B** in-place at `/Desktop/grainrestore/` (scope per Sec. 4.5 bounded iteration; Sec. 4.6 abort-on-failure; Sec. 4.4 app-supplies-NewRow); write Sec. 4.8 tests; confirm green | 1.0 |
| 1.1b | Create `github.com/hrbrlife/melusina-grain-restore-component` repo; `git mv` source; `gofmt -r 'github.com/melusina/grainrestore -> github.com/hrbrlife/melusina-grain-restore' -w ./...`; `go mod tidy`; update 3 consumer `replace` directives | 0.5 |
| 1.1c | Tag v0.1.0 (see Sec. 6 "first-tag workflow") | — |
| 1.2 | Promote `grain-crypto-journal` out of `Melusina/shared/` → `hrbrlife/melusina-grain-crypto-journal-component`; preserve import path `github.com/hrbrlife/grain-crypto-journal` (rename the repo, not the module); tag v0.1.0 | 0.5 |
| 1.3 | **PROMOTE** `melusina-Solana-primitives` → `hrbrlife/melusina-Solana-primitives-component`. Change module path `github.com/melusina-os/melusina-Solana-primitives` → `github.com/hrbrlife/melusina-Solana-primitives` via `gofmt -r` across consumers; tag v0.1.0 | 0.5 |
| 1.4 | `melusina-spkmodule-component` v0.2.0: formalize `.spkmodule-hooks/.manifest` schema (Sec. 6.1); add pre-pack capability static check; include Bucket 0 artifacts | 1.0 |
| 1.5 | **PROMOTE** `melusina-identity-gate` → `hrbrlife/melusina-identity-gate-component`. Change module path; `gofmt -r` across consumers; tag v0.1.0. Also publish `-py` sibling `hrbrlife/melusina-identity-gate-py` (PyPI: `melusina-identity-gate`) | 0.75 |
| 1.6 | Enable CI workflows on all Bucket 1 repos: test, vet, lint, tag-gate, consumer-canary stub | 1.25 |
| 1.7 | **NEW — Create `hrbrlife/melusina-capnp` as Component #2.** Seed from `melusina_botmother/capnp/` (20 schemas) + `melusina-grain-auth/capnp/grain-authz.capnp` = 21 canonical schemas under `interfaces/`. Add Go/TS/Py binding generators (`capnp compile`, `capnpc-ts`, `pycapnp`) wired into CI. Update `melusina_botmother`, `melusina_teleport2`, and `melusina-grain-auth` consumers to import from the canonical repo; delete their in-tree capnp copies. Tag v0.1.0 | 1.5 |

**Exit gate:** every Bucket 1 repo has a green v0.1.0 (or v0.2.0 for #1.4) tag, no sibling `replace` directives, includes the shared `.golangci.yml`.

### Bucket 2 — Wrappers (days 6–11, ~5 days)

| # | Task | Blocker | Days |
|---|---|---|---|
| 2.1 | Rename `grain-e2e-binding` → `hrbrlife/melusina-grain-e2e-binding-component`. `gofmt -r 'github.com/melusina-os/grain-e2e-binding -> github.com/hrbrlife/grain-e2e-binding' -w ./...` across consumers; drop sibling `replace`s; tag v0.1.0 | 1.2, 1.3 | 1.0 |
| 2.2 | Finalize `melusina-http-component` as standalone: drop sandstorm + grain-crypto-journal sibling `replace`s; pin tagged grain-crypto-journal; tag v0.1.0 | 1.2 | 0.75 |
| 2.3 | `melusina-grain-auth-component` v0.1.0 publish — simultaneous **Go tag → npm → PyPI** (in that order; only npm/PyPI are irreversible; dry-run against verdaccio + TestPyPI first) | 1.5, 2.1, Sec. 8 #4 | 1.5 |
| 2.4 | Extract `melusina-bureau-shell-component` (npm `@hrbrlife/bureau-shell`); identify shared React chrome, picker, export from four bureau apps; tag v0.1.0 | Sec. 8 #5 | 1.5 |
| 2.5 | Tag `melusina-e2e-test-component` v0.1.0 (Python) | 2.3 | 0.25 |

**Exit gate:** every component in Sec. 1 has a tagged release with green consumer-canary.

### Bucket 3 — App adoption (days 11–24, ~13 days, 6 parallel lanes)

Apps cluster by shared feature branches or shared component dependencies. **Not 13 independent lanes.**

| Lane | Apps | Special | Days |
|---|---|---|---|
| 3.A | ccash_go_htmx | **Adopt `melusina-http-component` #7 — no exemption.** Delete `internal/httpout/` if present; migrate PowerBox + HTTP-out to the shared component. Consumer side of Bug A/B fixes from Sec. 4.4. Delete `Fineract-sidecar/upstream/mifos-web-app/`. | 1.5 |
| 3.B | NamedCoin admin + app (share `feat/NamedCoin-audit`) | **Standardize on the feature branch**, run full test suite + `make pack` + `make verify`, then merge to `main` in one wave. Rationale: unmerged audit work in the branch must survive standardization; merge-first loses audit context in the squash | 1.5 |
| 3.C | cyberteller + ai-lagoon (share `feat/admin-auth-harmonize`) | Same pattern as 3.B. cyberteller: **delete `internal/httpout/`**, replaced by #7. ai-lagoon: drop three sibling `replace`s. Both: adopt identity-gate (#5). | 2.25 |
| 3.D | instaco.app + melusina_botmother | Stubs today; drop sibling `replace`s; pin tags; verify boot + empty-keybox flow (Sec. 6.11). Adopt identity-gate. Both pull capnp from #2 `melusina-capnp`. | 1.0 |
| 3.E | sailsto_system + AITX Procedures (+ clientspace, telescreen-pearl) | sailsto: reconcile 3 dirty + 1 unpushed first. AITX: telescreen-pearl is Python → adopts `melusina-grain-auth-py` + `melusina-identity-gate-py` | 2.0 |
| 3.F | openclaw-main + client_collection + MiniGit | MiniGit: reconcile dual-branch first (Sec. 3.2). openclaw: Go bridge adopts grain-crypto-journal + http-component + grain-auth; JS side adopts `@melusina/grain-auth` + `@hrbrlife/bureau-shell` if waikiki-template editing overlaps | 2.25 |
| 3.G | 4 bureau apps + melusina-mermail-station-app | **Bureau apps adopt `@hrbrlife/bureau-shell` npm + `grain-crypto-journal` + `http-component`.** Each app ships its `DocumentAdapter<S>` module per Sec. 11.4. mermail-station-app: adopt grain-crypto-journal + grain-auth + identity-gate; migrate novel content from INSTASYS_MAIL before Bucket 4 archives it | 2.5 |

**Per-app exit gate (Sec. 12 adoption checklist):**
1. `go.mod` / `package.json` has zero `replace` directives pointing outside the module cache.
2. `.spkmodule-hooks/.manifest` present, consistent with declared capability; pre-pack static check passes.
3. Full test suite green.
4. `make pack` emits a deterministic `.spk` (same inputs → same `sha256`).
5. `make verify` green (GPG signature + packageId cross-check).
6. Reviewer sign-off on `.manifest` + exempt justifications.

### Bucket 4 — Cleanup (days 24–26, ~2 days)

| # | Task | Days |
|---|---|---|
| 4.1 | Snapshot + delete `/Desktop/Melusina/shared/`, `/Desktop/grainrestore/`, all sibling-dir checkouts backing removed `replace`s | 0.5 |
| 4.2 | Snapshot + delete `ccash_tmp.YxwYht/`, `BLOOM_FINAL/shared/`, `vintage-test-dec/`, `shell_tester/shared/` | 0.25 |
| 4.3 | Snapshot + delete `store-rebuild/melusina-instaco-app/`, `store-rebuild/melusina_botmother/` (duplicates) | 0.25 |
| 4.4 | Fleet audit: `grep -rE "^replace .*=>" --include=go.mod . 2>/dev/null` returns zero hits (documented exemptions allowed) | 0.25 |
| 4.5 | Archive old-namespace GitHub repos (`melusina/grainrestore`, `melusina-os/grain-e2e-binding`, etc.). **No `retract` directives needed** — greenfield has no external consumers | 0.25 |
| 4.6 | Bazaar republish: refresh `static_store` pointers against tagged component versions; run `build-store.sh`; publish `static_store/publish` | 0.5 |
| 4.7 | Update auto-memory: [`project_grainrestore_repo.md`](../../../.claude/projects/-home-user-Desktop-static_store/memory/project_grainrestore_repo.md) to reflect new hrbrlife paths and API | — |

**Exit gate:** `grep -rE "^replace " --include=go.mod /home/user/Desktop /home/user 2>/dev/null` returns zero hits outside documented exemptions.

---

## 6. Governance (post-convergence)

### 6.1 Per-app capability declaration

Every app ships `.spkmodule-hooks/.manifest` consumed by the pre-pack static check.

```ini
# .spkmodule-hooks/.manifest — grammar reference
GRAIN_CRYPTO=required            # required | stateless
GRAIN_RESTORE=required           # required | stateless
HTTP_COMPONENT=required          # required | none  (no "exempt" — all HTTP-out uses #7)
GRAIN_AUTH=required              # required | none
IDENTITY_GATE=required           # required | none  (four-app contract pinned here)
BUREAU_SHELL=none                # required | none
CAPNP=required                   # required | none  (via #2 melusina-capnp)
```

**Worked examples:**

```ini
# ccash_go_htmx/.spkmodule-hooks/.manifest
GRAIN_CRYPTO=required
GRAIN_RESTORE=required
HTTP_COMPONENT=required          # no exemption; migrated off internal/httpout
GRAIN_AUTH=none                  # ccash is not an admin-authz consumer
IDENTITY_GATE=required           # four-app cross-app auth contract
BUREAU_SHELL=none
CAPNP=required
```
```ini
# melusina-bureau-doc-app/.spkmodule-hooks/.manifest
GRAIN_CRYPTO=required
GRAIN_RESTORE=stateless
HTTP_COMPONENT=required
GRAIN_AUTH=none
IDENTITY_GATE=none
BUREAU_SHELL=required
```
```ini
# NamedCoin admin app/.spkmodule-hooks/.manifest
GRAIN_CRYPTO=required
GRAIN_RESTORE=required
HTTP_COMPONENT=required
GRAIN_AUTH=required
IDENTITY_GATE=required
BUREAU_SHELL=none
```

**Static check** (`melusina-spkmodule-component/check/pre-pack-capabilities.sh`) runs `go list -deps -json ./...` against the built binary (or `npm ls --json` / `pip show` per language):

- `GRAIN_CRYPTO=required` → compiled artifact imports `github.com/hrbrlife/grain-crypto-journal`.
- `GRAIN_CRYPTO=stateless` → artifact does NOT import grain-crypto-journal AND does NOT reference `MELUSINA_VAULT_SECRET` AND writes only static files under `/var`. Self-certification without static confirmation is rejected.
- `CAPNP=required` → artifact's generated bindings were produced from `melusina-capnp`'s schemas; no in-tree `.capnp` source files.
- There is **no `exempt` mode** for any capability. If a component doesn't fit an app's need, the app opens an issue on the component repo (Sec. 6.4).

### 6.2 Version pinning

- Every consumer pins a tagged release. Floating on `main` is forbidden in `go.mod` / `package.json` post-Bucket-3.
- `check-pins` CI action rejects `v0.0.0-YYYYMMDDHHMMSS-...` pseudo-versions and `replace` directives with relative paths.
- Exception: a component's own in-repo test apps may float on `main` during dev.

### 6.3 Breaking-change protocol (greenfield-adjusted)

No external consumers → no deprecation window. Procedure:
- Breaking change on a component opens a **coordinated PR wave** across every consumer app in one shot.
- Old major is removed the day the last consumer merges.
- `CHANGELOG.md` note required on every breaking release.
- Semver strict; major bump = `/v2` import path.
- Non-breaking additions ship minor; bug fixes ship patch.

### 6.4 Per-app customization boundaries

**Config knob (allowed):** `BaseDomain`, `Migrations`, `Rewrite` tables, `Encryptor`, scope lists, TTLs, sidecar-variant choice, `Dir` paths — anything passed into the component's `Options` struct.

**Fork (forbidden, PR-blocker):**
- Copying a component's code into an app's tree.
- Adding a `replace` to a fork.
- Re-implementing keybox, sqlitestore, PowerBox persistence, authz client, envelope verification, restore driver, HTTP-out in-app.
- Deviating from the capnp schema in any language binding.
- Bypassing `Require` / `fail_closed` on destructive ops.

Gap path: app opens an issue on the component repo; component gains a knob or v(N+1) API. No app forks.

### 6.5 Per-component CI

Every component repo has GitHub Actions on PR + push-to-main:
- **Test:** `go test -race ./...` / `npm test` / `pytest`. Coverage ≥70% on changed lines — measured by `codecov/codecov-action` (Go), `c8` (JS), `coverage.py` (Python).
- **Vet + lint:** `go vet`, `golangci-lint` (shared `.golangci.yml` from spkmodule-component); `eslint`; `ruff`.
- **Schema coherence** (grain-auth, identity-gate): `tools/schema-coherence.sh` — Go/TS/Py/capnp must match.
- **Build artifact:** `go build ./...` + `spk pack` dry-run for Sandstorm artifacts.
- **Tag gate:** release workflow fires on `v*` annotated tags only; requires all above green; auto-publishes npm/PyPI; warms `go.mod` proxy.
- **Consumer canary:** nightly; checks out top 3 consumers, bumps to `main`, runs their suites. Failure auto-opens an issue on the component.

**First-tag workflow** (per component):
1. `CHANGELOG.md` seeded from commit history since repo init.
2. `CODEOWNERS` present.
3. Two Bucket-1 reviewers approve (one for Bucket 2).
4. CI green on `main`.
5. Annotated tag pushed by release workflow, not locally.

### 6.6 Ownership

Each repo has `CODEOWNERS` under `hrbrlife/`. Bucket 1 repos require two reviewers; Bucket 2 require one. All merges to `main` require green CI; no admin overrides.

### 6.7 Rollback protocol

- **Tagged release regression:** re-tag forward as v0.1.1 with the fix. Never force-delete a tag.
- **App adoption regression:** revert the app's `go.mod` bump; do NOT roll back the component.
- **Bucket 4 deletions:** one-way. Always take tarball snapshot first — `bin/snapshot.sh` in Bucket 0 — to `/home/user/Desktop/.kill-list-snapshots/<timestamp>/`. 30-day retention.

### 6.8 Hotfix protocol

- Branch from `vX.Y.Z`, cherry-pick fix, tag `vX.Y.(Z+1)`.
- Open fleet-wide bump PR via `check-pins` bot annotations.
- No direct pushes to `main` that skip CI.

### 6.9 Signing key custody

- Signing key lives in the shared password manager under `hrbrlife-melusina-signing`.
- Two-person rule for rotation (one holder + one witness).
- CI receives ephemeral signing creds via OIDC-to-vault; no static secrets in Actions.
- `GPG_KEY` env var in spkmodule Makefile consumes the OIDC-issued key, not a long-lived key.

### 6.10 `MELUSINA_VAULT_SECRET` provenance

- Injected by Sandstorm per-grain env at install.
- Bootstrap at first-boot via operator-wallet signing ceremony (keybox `UnsealPathB` path; zero pre-existing state).
- Rotation via `keybox.Manager.Rewrap` with new `MasterKeyContext`.
- Static check (Sec. 6.1) references the env var name only; doesn't control its value.

### 6.11 First-boot / empty-keybox flow (greenfield)

Every grain boots empty — no prior state to recover. Per-grain first-deploy:
1. User installs grain from bazaar.
2. Grain init detects missing `/var/keybox.json` → enters enrollment UI.
3. User connects wallet (Solana signer) → keybox derives master key from wallet pubkey + vault secret.
4. Keybox writes initial `keybox.json` ciphertext; sqlitestore initializes at schema v1.
5. Audit log seeds with `entry_type=genesis`, `prev_hash=zero`.
6. For grains with Path-B wallet recovery enabled: `ResetBinding(newOwnerIdentityID)` called with the Sandstorm user's identity ID.

If a grain is *restored* (new grainId, no Path-B wallet): restore ceremony in #8 library detects the condition; surfaces `restored-pending` state; app renders a re-enrollment UI rather than booting normally.

---

## 7. Deletion checklist (end-state)

After Bucket 4, these paths MUST NOT exist (take snapshots first):
- `/home/user/Desktop/Melusina/shared/` — entire tree
- `/home/user/Desktop/grainrestore/` — renamed repo
- `/home/user/Desktop/ccash_tmp.YxwYht/`
- `/home/user/Desktop/BLOOM_FINAL/shared/`
- `/home/user/Desktop/vintage-test-dec/`
- `/home/user/Desktop/shell_tester/shared/`
- `/home/user/Desktop/store-rebuild/melusina-instaco-app/`
- `/home/user/Desktop/store-rebuild/melusina_botmother/`
- In every consumer app: any `shared/grain-crypto-journal/`, `shared/grain-e2e-binding/`, `shared/melusina-http-component/`, vendored copies

Leave untouched:
- `/home/user/Desktop/static_store/` — bazaar repo itself
- `/home/user/Desktop/go-sandstorm/`, `/home/user/Desktop/go-util/` — third-party zenhack forks
- `/home/user/Desktop/melusina-Fineract-sidecar/` — already correct namespace; separate scope
- `/home/user/Desktop/miniapp-static/` — kept as utility submodule
- `/home/user/Desktop/store-rebuild/melusina-bureau-*-app/` — Bucket 3 Lane 3.G consumers

---

## 8. Decisions — RESOLVED

All 12 blockers resolved 2026-04-22. Proceed to Bucket 0.

| # | Decision | Resolution |
|---|---|---|
| 1 | `melusina-Solana-primitives` promote/archive | **PROMOTE** → `hrbrlife/melusina-Solana-primitives-component` (Component #4). Rationale: PDA seed lock prevents silent auth bypass. |
| 2 | `melusina-identity-gate` promote/archive | **PROMOTE** → `hrbrlife/melusina-identity-gate-component` (Component #5) + `-py` sibling. Rationale: four-app cross-app auth contract is pinned against this module. |
| 3 | Row iteration scope for resign hook | **Only sidMap-referenced rows** — bounded work (Sec. 4.5). |
| 4 | Forward-anchor row source | **App supplies `NewRow`** — library stays domain-agnostic (Sec. 4.4). |
| 5 | KeyRewrap failure semantics | **Abort restore** — consumer shows re-enroll UI (Sec. 4.6). |
| 6 | `melusina_teleport2` archive/adopt | **Out of scope** for this kill list — do not touch. |
| 7 | `pr_ninja` / TeleScreen classification | **Core operational sidecar** (not a stub — 897 LOC Python, 12+ OSINT providers, 364 tests). Infrastructure-adjacent; not a Bucket 3 adoption target. Consumes Component #5. See Sec. 13. |
| 8 | ccash `Fineract-sidecar/upstream/mifos-web-app/` | **DELETE** — was reference example, not load-bearing. |
| 9 | INSTASYS_MAIL vs. mermail-station-app | **`mermail-station-app` is canonical** (47 commits ahead, designed as sidecar-consumer). Archive INSTASYS_MAIL after migrating `htmx_uiview_mail/`, `real_example/`, novel tests. |
| 10 | Bureau-shell v0.1.0 scope | **MVP = chrome + document-picker + zip export + snapshot API (CRUD + signature column reserved for v0.2.0 Solana signing)**. Full spec in Sec. 11 (new). |
| 11 | Canonical `.capnp` schema root | **CREATE `hrbrlife/melusina-capnp` as new Component #2.** Migrate 21 schemas from `melusina_botmother/capnp/` (20) + `melusina-grain-auth/capnp/` (1). Delete duplicate in `melusina_teleport2/capnp/`. Task 1.7. |
| 12 | ccash `http-component` exemption | **No exemption.** ccash must adopt Component #7 like every other app. Delete `internal/httpout/` (Lane 3.A). |

---

## 9. Critical path & realistic parallelism

Total serial work: ~27 engineer-days (up ~2d from prior estimate due to new Task 1.7 capnp migration + promote-both on Solana/identity-gate + ccash losing exemption). **Critical path (single-engineer serial):**

```
Day 0:    Sec. 8 decisions all RESOLVED (see Sec. 8 table)
Day 0–1.5: Bucket 0 tooling in place (0.1-0.5)         [1.5d]
Day 1.5:  Task 1.1a grainrestore bug fixes              [1.0d]
Day 2.5:  Task 1.1b rename + migrate consumers          [0.5d]
Day 2.5:  Task 1.4 spkmodule v0.2.0 (parallel)          [1.0d]
Day 3:    Task 1.2 grain-crypto-journal promote         [0.5d]
Day 3.5:  Task 1.7 create melusina-capnp (NEW)          [1.5d]
Day 5:    Task 2.3 grain-auth (Go+npm+PyPI)             [1.5d]
Day 6.5:  Task 3.A ccash adoption (now includes
          internal/httpout delete + mifos delete)       [1.5d]
Day 8:    Task 4.1-4.4 fleet cleanup & audit            [1.25d]
Day 9.25: Task 4.6 bazaar republish                     [0.5d]
─────────
Critical path: ~10 calendar days if decisions stay resolved.
```

**Parallelizable branches** off the critical path:
- **Lane P1:** Tasks 1.3 (Solana-primitives), 1.5 (identity-gate), 1.6 (CI scaffolding) — 2.25d, runs in parallel with 1.1.
- **Lane P2:** Task 2.1 (grain-e2e-binding rename), 2.2 (http-component finalize), 2.4 (bureau-shell extraction), 2.5 (e2e-test tag) — 3.5d, starts after 1.2+1.3 land.
- **Lane P3:** Bucket 3 lanes 3.B–3.G — 10–12d, each cluster has one-engineer shape.

**Realistic wall time:**
- 1 engineer: ~27 calendar days.
- 2 engineers: ~16 calendar days (Bucket 3 mostly serial due to shared feature branches).
- 3 engineers: ~12 calendar days (Bucket 3 lanes 3.B/3.C/3.E–3.G can truly parallelize; 3.A/3.D smaller).

**~3 weeks is realistic** with all Sec. 8 decisions pre-resolved (which they are).

---

## 10. Cross-language adoption (Go / JS / Python)

### Go (primary stack)
Default pattern above. Every consumer pins tagged versions; `go.mod` is the source of truth.

### JavaScript / TypeScript
Affected apps: `openclaw-main` (JS + Go bridge), `melusina-bureau-*-app` (TS/React), `INSTASYS_CHAT` (deferred), and the browser twin of grain-crypto-journal.

Discipline:
- npm packages published under `@hrbrlife/` and `@melusina/` scopes (TBD — pick one; default `@hrbrlife/` for consistency).
- `package.json` pins exact versions via `"dependencies": { "@hrbrlife/bureau-shell": "0.1.0" }` — no `^` or `~`.
- `npm publish` requires `npm pack` dry-run green + SHA-256 verification against registry.
- Schema coherence: every `.capnp` in a component repo triggers a TS binding regeneration via `tools/capnp-to-ts.sh` in CI.

### Python
Affected apps: `telescreen-pearl` subgrain inside AITX Procedures; `melusina-e2e-test-component`; proposed `melusina-identity-gate-py` sibling.

Discipline:
- PyPI packages published under their own names (`melusina-grain-auth`, `melusina-identity-gate`, `melusina-e2e`).
- `setup.py` / `pyproject.toml` pins via `melusina-grain-auth==0.1.0` — no `>=`.
- Lint: `ruff`; type check: `mypy --strict`.
- Test coverage via `coverage.py`, gate ≥70%.

---

## 11. Bureau-shell v0.1.0 (Component #11 full spec)

Four bureau apps (`doc`, `sheets`, `paint`, `diagram`) ship a near-identical scaffold today (`components/Conflict|Connection|ErrorBoundary|Loading|Help`, `services/{sandstorm,websocket,connectionStatus}`, `core/{dispatch,factory,libraryBase}`). Bureau-shell hoists the common chrome + snapshot API; each app keeps its engine (Y.Doc / spreadsheet / raster / mxGraphModel).

### 11.1 API surface (TypeScript)

```ts
// @hrbrlife/bureau-shell
export type Hash = string;            // hex sha-256
export type Ed25519Sig = string;      // hex, 128 chars; v0.1.0 always undefined

export interface DocumentAdapter<S> {
  serialize(state: S): Uint8Array;    // canonical bytes → hashed
  deserialize(bytes: Uint8Array): S;
  getState(): S;
  setState(state: S): void;
  mime: string;                       // e.g. "application/x.bureau-doc+json"
}

export interface SnapshotRecord {
  id: string;                         // ULID
  name: string;
  message: string;
  hash: Hash;                         // sha256(serialize(state))
  createdAt: string;                  // ISO-8601
  signature?: Ed25519Sig;             // v0.1.0: always undefined. v0.2.0 hook.
}

export interface SnapshotAPI {
  create(name: string, message: string): Promise<SnapshotRecord>;
  list(): Promise<SnapshotRecord[]>;
  get(id: string): Promise<SnapshotRecord | null>;
  restore(id: string): Promise<void>;
  exportZip(id: string): Promise<Uint8Array>;  // .blob + metadata.json
  // v0.2.0 future (reserved, not shipped):
  // sign(id: string, walletPrivateKey: Uint8Array): Promise<Ed25519Sig>;
}

export interface BureauShell<S> {
  mountChrome(root: HTMLElement, opts: { title: string; onSaveAs?: () => void }): void;
  documentPicker: { open(): Promise<string>; saveAs(name: string): Promise<void> };
  snapshots: SnapshotAPI;
}

export function createShell<S>(adapter: DocumentAdapter<S>, grainRoot: string): BureauShell<S>;
```

### 11.2 Snapshot storage

Snapshots table lives in the grain's `sqlitestore.Store` (Component #3), not a standalone DB — keeps hash-chained audit integration free.

```sql
CREATE TABLE snapshots (
  id                TEXT PRIMARY KEY,        -- ULID
  name              TEXT NOT NULL,
  message           TEXT NOT NULL DEFAULT '',
  hash              TEXT NOT NULL,           -- hex sha-256 of blob
  mime              TEXT NOT NULL,
  byte_size         INTEGER NOT NULL,
  created_at        TEXT NOT NULL,           -- ISO-8601 UTC
  created_by        TEXT NOT NULL,           -- grain user id
  signature_ed25519 TEXT NULL,               -- v0.1.0: always NULL
  signer_pubkey     TEXT NULL                -- v0.1.0: always NULL
);
CREATE INDEX idx_snapshots_hash ON snapshots(hash);
CREATE INDEX idx_snapshots_created_at ON snapshots(created_at DESC);
```

Blob storage: `/var/snapshots/<first2>/<hash>.blob` — content-addressed, dedup-friendly, fan-out prefix keeps directory entries reasonable.

### 11.3 v0.2.0 Solana-signing contract (reserved, not shipped)

```
snapshots.sign(id, walletPrivateKey)
  → sig = ed25519.sign(privKey, hex_decode(record.hash))
  → UPDATE snapshots SET signature_ed25519=?, signer_pubkey=? WHERE id=?
```

The Ed25519 curve is native to Solana (signer_pubkey == wallet address), so v0.2.0 integration with `melusina-Solana-primitives` (#4) is a direct wiring job — no schema migration needed because the signature columns are already in v0.1.0.

### 11.4 Per-app adapter (what each bureau app must ship)

Each app ships `client/src/bureauAdapter.ts` exporting one `DocumentAdapter<S>`:

| App     | State `S`                | serialize → bytes                                   | deserialize(bytes) |
|---------|--------------------------|------------------------------------------------------|--------------------|
| doc     | `Y.Doc`                  | `Y.encodeStateAsUpdate(doc)`                         | `Y.applyUpdate(new Doc(), b)` |
| sheets  | `JspreadsheetWorkbook`   | canonical JSON (sorted keys) → UTF-8 bytes           | `JSON.parse(utf8(b))` |
| paint   | `LayerStack`             | PNG-packed layers + JSON manifest in tarball         | untar, decode layers |
| diagram | `mxGraphModel`           | `mxUtils.getXml(encoder.encode(model))` → UTF-8      | `decoder.decode(parseXml)` |

Each app also: declares `mime`, implements `getState/setState` against its live editor, calls `createShell(adapter, grainRoot)` once in `main.ts`. Shell owns chrome/picker/zip-export/snapshot-CRUD/SQLite/blobs. App still owns its engine, UI below chrome, and websocket/CRDT sync.

### 11.5 v0.1.0 explicit non-goals

- Solana signing (deferred v0.2.0)
- PDF or app-format export (XLSX/SVG/PNG/XML) — app-owned, not shell
- Snapshot diff/branch/merge/cherry-pick
- Cross-grain snapshot transfer
- Encryption at rest for blobs (hash is integrity, not confidentiality — grain-crypto-journal handles confidentiality layer-above)
- Snapshot GC / retention policy
- Full-text search or tags on messages
- Shell-owned real-time collab (websockets stay in-app)

---

## 11a. Sidecar lifecycle (reference)

Sidecars today: `Fineract-sidecar` (ccash), `mermail-sidecar` (mermail-station), `openclaw-bridge` (hybrid within openclaw), TeleScreen (`pr_ninja`).

Standard pattern (no kill-list task; reference for future sidecars in `melusina-spkmodule-component/templates/sidecar.mk`):
- Sidecar binary under `./sidecar/<name>/`
- Communication: Cap'n Proto over UDS at `/var/sidecar/<name>.sock` — schemas live in #2 `melusina-capnp`
- Lifecycle: grain launches sidecar on boot (`exec` or goroutine); sidecar terminates on grain SIGTERM
- Restart: sidecar crash does NOT restart grain; grain auth client retries with exponential backoff
- Capability forwarding: Sandstorm caps (HTTP-out, PowerBox tokens) pass via capnp to sidecar; sidecar never calls Sandstorm APIs directly

No kill-list task promotes existing sidecars to component repos — out of scope.

---

## 12. Post-adoption verification

### 12.1 Fleet-wide smoke test

After Bucket 3 completes and before Bucket 4 cleanup, run `bin/fleet-smoke.sh`:
1. For each of the 14 adoption-target apps:
   a. `make pack` → produce `.spk`.
   b. Install into a fresh local Sandstorm shell.
   c. Boot grain to empty state.
   d. Run app-specific write: e.g., ccash creates one credit transfer; NamedCoin creates one name registration; bureau-doc creates one document.
   e. Restart the grain.
   f. Verify: app boots cleanly; journal intact; hash chain verifies; keybox unlocks via wallet.
   g. Trigger `CaptureOnBackup` → `/grainrestore/pre-backup`; download ZIP.
   h. Upload ZIP to new grainId on the same shell; trigger `RewriteOnRestore`.
   i. Verify: personas rebound correctly; keybox rewrapped; audit chain resigned; app serves under new grainId.
2. Emit pass/fail matrix; block Bucket 4 on any fail.

### 12.2 Consumer canary SLO

Per Sec. 6.5 consumer-canary: if 3+ consumers fail on a component's `main`-branch change, the change is auto-reverted or requires author fix within 24h. Implemented via a bot on the component repo.

### 12.3 Per-app adoption code-review checklist

Reviewer must verify:
- `.spkmodule-hooks/.manifest` accurate vs. declared capabilities.
- Exempt justifications (if any) are specific and PR-linked.
- `make pack` produces byte-identical `.spk` on repeat build (`shasum -a 256`).
- Baseline storage < 50 MB on first boot.
- `.gitignore` excludes generated `.capnp.go` / `.capnp.ts` / `.capnp.py`.

### 12.4 SPK determinism

Each app's Makefile in Bucket 3 must pin reproducibility env: `SOURCE_DATE_EPOCH`, `TZ=UTC`, deterministic zip via `mksquashfs -noappend -no-progress`. Verified in 12.3.

### 12.5 Component deprecation policy

After v0.1.0 ships, a component is considered "live." Deprecation:
- 90 days with zero consumers → archive candidate; `CODEOWNERS` approves; repo goes read-only.
- Otherwise retirement requires major-version bump + coordinated PR wave per Sec. 6.3.

---

## 13. Deferred / out-of-scope / adjacent-infrastructure apps

Per auto-memory and 2026-04-22 audit:

| App | Path | Status | Reason |
|---|---|---|---|
| `waikiki` | `/Desktop/waikiki/` | **DEFERRED** | Not on active roadmap; crypto-free |
| `INSTASYS_CHAT` | `/Desktop/INSTASYS_CHAT/` | **DEFERRED** | Node.js chat app, stateless, no active work |
| `Teleport` (original, not teleport2) | — | **DEFERRED** | Predecessor of melusina_teleport2 |
| `Gogs`/`gogs-sandstorm-master` | `/Desktop/gogs-sandstorm-master/` | **HARD NO** | Retired; MiniGit is the replacement |
| `BLOOM_FINAL` / `BLOOM_QUESTIONNAIRE` / BLOOM.Community KYC | `/Desktop/BLOOM_FINAL/`, `/Desktop/BLOOM_QUESTIONNAIRE/` | **HARD NO** | KYC hard-NO per user policy |
| `melusina_teleport2` | `/Desktop/melusina_teleport2/` | **OUT OF SCOPE** | Sec. 8 #6 — do not touch this kill list round |
| `INSTASYS_MAIL` | `/home/user/INSTASYS_MAIL/` | **ARCHIVE** | Superseded by `mermail-station-app` (47 commits ahead). Archive after content migration in Lane 3.G |
| `pr_ninja` = **TeleScreen** | `/Desktop/pr_ninja/` | **INFRASTRUCTURE sidecar — OPERATIONAL** | 897 LOC Python, FastAPI, QueueManager, 12+ OSINT providers, 364 passing tests. Core sidecar consumed by ccash C4 screening. Consumes Component #5 (`melusina-identity-gate`). Not a Bucket 3 target; listed here for reference. Its existing `melusina-identity-gate` usage is already aligned with post-standardization state. |
| `telescreen-companion-app` | `/Desktop/Melusina/sidecar/telescreen-companion-app/` | **ADJACENT** | Companion setup grain for TeleScreen config distribution. No adoption work — already aligned. |
| `melusina-Fineract-sidecar` | `/Desktop/melusina-Fineract-sidecar/` OR `/Desktop/store-rebuild/melusina-Fineract-sidecar/` | **OUT OF SCOPE** | Already correct namespace; sidecar lifecycle is separate kill-list scope |

Deferred apps are not migrated in this kill list. If any becomes active, add it to Bucket 3 as a new lane.

---

## 14. Execution order summary (one-pane view)

```
Day 0 — Sec. 8 decisions locked; snapshot current state.

Days 0–1.5 — Bucket 0 (tooling)
  check-pins, schema-coherence.sh, canary template,
  .golangci.yml, snapshot.sh

Days 1.5–7 — Bucket 1 (foundations, 11-component roster)
  1.1a grainrestore Bug A + Bug B fix              [1.0d, critical]
  1.1b rename → hrbrlife/melusina-grain-restore    [0.5d]
  1.1c tag v0.1.0
  1.2  grain-crypto-journal promote (#3)            [0.5d]
  1.3  PROMOTE Solana-primitives (#4)               [0.5d, parallel]
  1.4  spkmodule v0.2.0 + .manifest schema          [1.0d, parallel]
  1.5  PROMOTE identity-gate Go+Py (#5)             [0.75d, parallel]
  1.6  CI scaffolding across Bucket 1               [1.25d, parallel]
  1.7  CREATE melusina-capnp (#2) + migrate 21      [1.5d]
  GATE: every Bucket 1 repo tagged v0.1.0, green CI, no sibling replaces

Days 7–12 — Bucket 2 (wrappers)
  2.1 grain-e2e-binding rename (#8)                 [1.0d]
  2.2 http-component finalize (#7)                  [0.75d, parallel]
  2.3 grain-auth Go+npm+PyPI (#6)                   [1.5d]
  2.4 bureau-shell extraction (#11)                 [1.5d, parallel]
  2.5 e2e-test-component tag (#10)                  [0.25d]
  GATE: every Sec. 1 component tagged v0.1.0, canary green

Days 12–25 — Bucket 3 (app adoption, 7 clustered lanes)
  3.A ccash_go_htmx (delete internal/httpout +
      mifos-web-app; consumer side of 4.4)          [1.5d]
  3.B NamedCoin admin + app (feat branch)           [1.5d]
  3.C cyberteller + ai-lagoon (feat branch;
      cyberteller deletes internal/httpout)         [2.25d]
  3.D instaco.app + botmother                       [1.0d]
  3.E sailsto + AITX (+ telescreen-pearl Py,
      clientspace)                                  [2.0d]
  3.F openclaw + client_collection + MiniGit        [2.25d]
  3.G 4 bureau apps + mermail-station (migrate
      INSTASYS_MAIL content first)                  [2.5d]
  GATE: fleet-smoke.sh (Sec. 12.1) all-green

Days 25–27 — Bucket 4 (cleanup)
  4.1-4.3 snapshot + delete dead trees + archive    [1.25d]
           INSTASYS_MAIL
  4.4 fleet audit: zero `replace` hits              [0.25d]
  4.5 archive old-namespace repos                   [0.25d]
  4.6 bazaar republish                              [0.5d]
  4.7 update auto-memory
  GATE: grep -rE "^replace " returns zero unexpected hits

Total serial: ~27 engineer-days
Realistic 3-engineer wall time: ~3 calendar weeks
Critical path: ~10 days (Bucket 0 → 1.1 → 1.7 → 2.3 → 3.A → 4)

Scope locked:
  - grain-restore v0.1.0 = same-machine restore only.
    Cross-machine migration deferred to v1.0.0.
  - All 12 Sec. 8 decisions resolved — no blockers remain.
  - 11 components (added melusina-capnp as #2).
  - INSTASYS_MAIL archived in favor of mermail-station-app.
  - pr_ninja = TeleScreen = operational sidecar (not a stub).
```

---

## End of kill list

**Next action:** resolve Sec. 8 decisions with owners, snapshot the current fleet, then begin Bucket 0 Task 0.1.

**Related documents (already on filesystem):**
- `/home/user/Desktop/static_store/KEEP - COMPONENTS FOR APPS.md` — canonical spkmodule discipline reference
- `/home/user/Desktop/grainrestore/PHASE-STATUS.md` — component's own phase tracking (stale re: bugs Sec. 4; will be rewritten at v0.1.0 tag)
- `/home/user/.claude/projects/-home-user-Desktop-static_store/memory/project_grainrestore_repo.md` — auto-memory anchor; update in Task 4.7
