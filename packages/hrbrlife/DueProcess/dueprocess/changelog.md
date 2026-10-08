# Changelog

## 0.1.80 — 2026-09-06 — builder refusal integrity (appVersion 84)

- The Flow Builder now treats a structured `{ "success": false }` response as
  a refusal even when a legacy WebSession handler uses HTTP 200. Save keeps the
  draft dirty and preserves its unload warning; publish and discard surface an
  error and never claim a durable state transition.
- Adds `npm run test:builder-save`, a production-DOM regression test covering
  save, publish, and discard under that exact response shape.

## 0.1.79 — 2026-09-05 — fresh Stations retain workflows and accept reviewer custody (appVersion 83)

- Creates the process engine's private data directory before opening SQLite.
  A fresh Station previously logged an SQLite open error and lost its active
  workflow on restart. The durable-provider regression now starts with the
  same absent subdirectory as a new Station and verifies recovery.

- Keeps self-service wallet binding available after a Station is hydrated from
  Domain Template. The page-wide authoring lock previously disabled the control
  needed to prove custody before a reviewer could count toward four-eyes approval.
- Enables per-Station operator assignment only for users with `users_assign`.
  Workflow and permission definitions retain the template authoring lock; server
  permissions and signed wallet custody checks remain authoritative.
- Adds `npm run test:users-ui`, which renders the production Go templates and
  exercises their actual lock script for bound administrators, reviewers,
  anonymous viewers and unbound administrators.

## 0.1.78 — 2026-08-28 — controlled newborn handoff cut is self-contained (appVersion 82)

- Releases the controlled newborn-handoff source through a fresh-clone-safe
  candidate boundary. The governed `GrainFactory.controlledProvision@2` and
  `releaseControlledProvision@3` ordinals are now recorded in this repository's
  Cap'n Proto baseline.
- Vendors the pinned, stdlib-only F7 ordinal checker into this app and runs it
  from `make check-drift`; the release gate no longer depends on an unrelated
  workstation Waikiki checkout.
- Keeps the autonomous-creation wire fixture domain-neutral. It tests the
  typed Shell result shape without pretending that a test target is a Popaye
  application identity.

## 0.1.77 — 2026-08-22 — the process engine opens, and the board follows the builder (appVersion 81)

- requestedMemoryGiB = 4. Every boot logged `process engine: SQLite open failed:
  ... PRAGMA journal_mode=WAL: unable to open database file: out of memory (14)`
  — WAL's shared-memory mmap refused under the supervisor's default RLIMIT_AS.
  The console still rendered, so the grain looked healthy while its engine was
  dead.
- The Kanban board now follows the Flow Builder's saved panels. The previous
  order took the workflow YAML's kanban_columns first and consulted PanelsJSON
  only when that came back empty, so a panel just added never appeared and a
  lane already removed never left. A workflow lane that still HOLDS cases is
  carried over, so nothing is stranded; a stale empty one disappears.

## 0.1.76 — 2026-08-19 — signed CyberTeller service envelope (appVersion 80)

- Adds a body-only Ed25519 service envelope for CyberTeller’s sanctions-case
  ingest and process-rules query, because the Sandstorm WebSession boundary
  does not expose inbound HTTP headers to the application.
- Binds receiver audience, idempotency key, method, path, canonical payload
  hash, key ID, expiry, and fresh nonce; persists consumed nonces under a
  private locked ledger; and signs every verified response back to the exact
  request.
- Uses a distinct signed sanctions route with durable create-or-get semantics:
  a response-loss retry supplies a fresh nonce with the same signed
  idempotency key and receives the original compliance case.
- Keeps legacy capability/API-token routes explicitly bounded for existing
  callers. CyberTeller’s new process-rule route has no unsigned fallback.

## 0.1.75 — 2026-08-19 — autonomous-share compatibility and release identity (appVersion 79)

- Uses the versioned autonomous `createGrainWithShare` RPC when a respondent
  share is requested, while retaining the exact legacy unshared RPC for older
  shells.
- Adds an authenticated `/_mel/release` response backed by an immutable release
  identity projection, so runtime verification cannot recurse through the
  mutable post-pack metadata digest.

## 0.1.74 — 2026-08-14 — four-eyes approval gate closes three fail-opens (appVersion 78)

- Deletes the `DUEPROCESS_FOUREYES_ATTEST_DISABLE` environment bypass. It
  returned success from `attestFourEyesChecker`, recording a four-eyes approval
  with no on-chain attestation, from any environment that set it. There is now
  no environment bypass; the retired switch is pinned inert by its own control.
- Fails closed when the approval step cannot be resolved. The checker
  attestation was conditional on a step lookup that skipped the whole gate on
  error, so an unresolvable workflow step behaved exactly like a step that
  needs no distinct reviewer. The step is now resolved before any signed
  decision is verified or recorded, and an unresolvable step refuses.
- Refuses externally submitted verdicts on station-owned steps. Approval steps
  must travel the signed approval endpoint and machine / auto-advancing steps
  are system-managed; both console submit paths now reject them.
- Adds a release-cohort guard: the marketing version, appVersion and pearl
  release version must agree across `metadata.json`, `sandstorm-pkgdef.capnp`
  and the `Makefile`, the appId is immutable, and the catalog metadata stays
  free of legacy fields, screenshot advertisements and non-canonical
  categories. Mutation controls prove each clause rejects.

## 0.1.73 — 2026-08-14 — provider-safe capability lifecycle (appVersion 77)

- Keeps an owned reference for every in-flight Station, ClientHub, AI, and
  AdminGate-bundle call, so reconnecting or replacing a provider cannot revoke
  work that is already running.
- Releases cached AdminGate and sidecar-bundle capabilities deterministically
  at shutdown while allowing in-flight egress to drain.
- Extends the historical-ceiling regression gate to 96 browser, PowerBox,
  GrainFactory, provider-replacement, and sidecar-bundle lifecycles under the
  race detector.
- Allocates every fallible WebSession result before retaining its
  `SessionContext`, closing the last error-path leak in the HookTrigger picker.

## 0.1.72 — 2026-08-14 — MSB protocol union and bounded session lifecycle (appVersion 76)

- Unions the live 0.1.71/appVersion 75 release lineage with current `main` and
  the MSB protocol 1.9 contracts; no live behavior is reverted by the cut.
- Releases each per-tab `SessionContext` and provider capability when its
  `WebSession` is dropped, preventing the repeat-open connection ceiling.
- Restores sanctions screening at deposit time and carries the corrected
  request contract through the packaged screening sidecar.
- Re-vendors the exact Domain Template `75383e8` packs, including required
  clientspace identity/status barriers and the protocol completion fraction
  `1.0`; the source and embedded trees are digest-pinned and byte-identical.
- Keeps the build hermetic: all effective module replacements resolve inside
  the repository, and the CI gate covers the pinned dependency snapshots.

## 0.1.70 — 2026-08-01 — Converged tree supersedes the 0.1.69 regression; DTG bypass removed (appVersion 74)

Publishes the converged branch (0 behind `origin/main`, 61 ahead), replacing the
published 0.1.69 whose bytes were built from a branch that exists on no ref and
that regressed 13 pushed-main commits.

What 0.1.69 shipped and this release corrects:

- **DTG provenance bypass removed.** 0.1.69 compiled in
  `//go:embed domains/msb/workflows/*.yaml` and `//go:embed domains/ccash/stations/*.yaml`,
  registered through `registerEmbeddedTemplates`. That let a Station activate a
  definition the DomainTemplate never published and never signed — precisely what
  the provenance gate exists to prevent. This tree carries neither the embeds nor
  the registration; the DomainTemplate is the sole publisher of definitions.
- **Stale `domains/ccash/stations/account-opening.yaml` gone.** 0.1.69 shipped that
  file at version 2 against main's version 13 (DomainTemplate now publishes v16),
  missing `applicant_review`, the sanctions review/EDD chain, the adverse-media
  chain, `finalize_regulatory_dossier` and `popaye_activation_ack`, while still
  carrying the retired duplicate intake `account_application` and `kyc_check`.
- **Restores the 13 regressed pushed-main commits**, including "complete v1.7
  station evidence flow" and "restore complete scoped workflow", and the station
  bootstrap that carries all 24 StationProfile fields (0.1.69 dropped 14 of 24).

Manifest continues to offer exactly two pearl types (compliance workspace, new
case). Adds the authored `RUNTIME-CONTRACT.json` this app previously lacked.

## 0.1.68 — 2026-07-26 — account-opening: remove dead screening.overall_risk==exclusion condition; document proof wire-typing (appVersion 72)

Republish of the account-opening.yaml audit-h2 fix already landed on main: the
dead `screening.overall_risk == exclusion` transition condition is removed and
the proof wire-typing is documented in-place. No behavioral change beyond the
already-landed source; version cohort advanced so the store gate accepts a fresh
Active superseding 0.1.67.

## 0.1.67 — 2026-07-24 — Publish cohort bump; map the 8 full-CDD keys into account_application appData (appVersion 71)

Reproducible publish of the governed fix/fineract-egress-tenant lineage. Carries
the station change at HEAD (map the 8 full-CDD keys into account_application
appData per the popaye contract) plus the four-eyes attestation-grant producer
step and the Fineract platform-tenant fix. No behavioral change beyond the
already-landed source; version cohort advanced so the store gate accepts a fresh
Active superseding 0.1.66.

## 0.1.66 — 2026-07-24 — Thread applicant KYC attestation PDA into account-opening case (appVersion 70)

Sits on top of 0.1.65's fineract companion-egress + screening sanctions-slot
union. One behavioral change (pkg/station/server.go
applyAccountOpeningApplicantIntake):

- fix(station): thread the applicant's on-chain KYC attestation PDA into the
  account-opening case appData — `appData["attestation_pda"]` from intake
  fields (attestation_pda / namedcoin_attestation_pda). This lets the
  downstream verify_namedcoin_attestation MACHINE step resolve its input_map
  {{attestation_pda}} for a fresh UI account-open, instead of fail-closing to
  rejected_end. Removes the earlier hand-seed of
  _initial_context.kyc_attestation_pda that a recorded UI run forbids. Pure
  data-flow (accumulates into inst.Fields via SubmitStep) — no new log string.

## 0.1.65 — 2026-07-23 — Fineract companion-egress fix union republish (appVersion 69)

Ships the live-proven fineract egress fixes through the governed ceremony,
unioned with the 0.1.64 screening-egress release (both forked from 0.1.63):

- fix(station): route Fineract provisioning through the fineract companion
  egress SLOT directly (no RestrictedTransport wrap — that block rejected the
  fineract.sidecar host before the slot transport could route it).
- fix(station): deliver the Fineract-Platform-TenantId tenant selector via
  header AND ?tenantIdentifier query param (the Sandstorm HTTP-OUT whitelist
  strips the bare header on the DTG egress hop; the query param survives).
- fix(station): deliver the operator-provisioned correspondent Basic
  credential from DATA_DIR/fineract-corr-auth via the surviving
  X-Sandstorm-App-Authorization app-namespace header — never baked into the
  image; absent -> fail-closed 401 at the sidecar.
- fix(servicecall): surface upstream 4xx response bodies from the executor so
  operator-visible errors carry the sidecar's actual refusal reason.
- carried forward from 0.1.64 (d912cd7): screening wired via the sanctions
  egress slot -> OpenSanctions sidecar.

## 0.1.63 — 2026-07-16 — Republish through the v2 gate + go.mod portability fix (appVersion 67)

Version-bump republish so the un-republished station fixes already on
`feat/greenfield-build` (four-eyes checker identity pin, B3 inbox-create
actor stamp, B4 fail-closed on missing STATION_ACTIVATION_SECRET) supersede
the catalog-current 0.1.62 through the refusing v2 publish gate
(strictly-greater / supersede-on-publish). No behavioral change in this
bump; the env-seed bridge (`loadMelusinaEnvFile` / `cmd/station/envfile.go`
reading `/var/melusina/dueprocess.env`) already carries the deployer-seeded
per-tenant secrets, so no license is baked into the pkgdef.

- build(go.mod): the `melusina-lib` replace directive now uses the relative
  path `../Melusina/lib` instead of a machine-specific absolute path, matching
  every sibling replace and making the tree buildable off a bare checkout.

## 0.1.50 — 2026-07-07 — Four-eyes wallet SoD + per-case ACTIVE-bridge + deployer-env loader (appVersion 54)

Ships the four-eyes → eve-ACTIVE cohort so the executive checker's sign-off
drives eve to ACTIVE end-to-end. Three station changes land together:

- INC-1 wallet-level separation-of-duties: unique-reviewers approvals enforce
  maker≠checker at the WALLET level (not just the account level), so one signer
  can never satisfy both eyes.
- INC-2 per-case activation target: grain_state_transition resolves the
  activation target per-case, so the executive_signoff → popaye /api/v1/activate
  ACTIVE bridge fires against the correct account grain.
- C4 env-file loader (cmd/station/envfile.go): the station loads the
  deployer-seeded /var/melusina/dueprocess.env at startup, so the four-eyes
  checker attestation config (DUEPROCESS_FOUREYES_*) and the STATION_ACTIVATION_SECRET
  bearer reach the process. The file was previously DORMANT (no loader), so
  attestFourEyesChecker fail-closed with "registry not configured".

## 0.1.40 — 2026-06-11 — Disposition webhook survives popaye api-host (GAP-3) (appVersion 44)

Outbound case-disposition HMAC envelope now reaches popaye through its
Sandstorm api-host. The api-host strips every inbound request header that
isn't x-sandstorm-app-*, which silently dropped the
X-DueProcess-Timestamp/Nonce/Signature headers so an approved disposition
never authenticated at popaye. The signer (pkg/disposition/poster.go
SignHeaders) now emits each header twice — once plain (for direct,
non-Sandstorm targets) and once under the x-sandstorm-app- prefix
(X-Sandstorm-App-X-DueProcess-*). The HMAC is computed over the values
(ts.nonce.bodyHex), not the header names, so the receiver verifies
identically off either prefix. Single chokepoint: Post / redeliver / retry
all route through SignHeaders. New unit test asserts the prefixed copies
carry identical values and that a receiver reading only the prefixed
headers still verifies.

## 0.1.39 — 2026-06-08 — Operator/client UX-fix wave + BLOOM brand-leak removal (appVersion 43)

Re-publish carrying the LANE C client/operator-facing UX fixes (commit 9ed982f,
which landed after the 0.1.38 version bump without its own bump — the embedded
binary needed a version increment to actually upgrade in Sandstorm) plus the
remaining BLOOM third-party brand leaks in the engine packages.

LANE C (already on the publish HEAD, now versioned for upgrade):
- step_terms ToS/Privacy links → operator-configurable legalTermsURL/legalPrivacyURL
  (was a hard-coded bloom.community placeholder — broken trust boundary).
- error_recovery support@example.com → supportEmail func; header emoji → SVG.
- BLOOM CSS rebrand → "Melusina Compliance (DueProcess)"; bloomFadeInSoft →
  dpFadeInSoft.
- admin_users: removed raw SandstormRole "Melusina" column; "Process grain" →
  "this workflow"; emoji avatar → SVG.
- sanctions_queue auto-sweep tooltip de-op'd; theme-color #FDFBF7 on shells.
- Four-eyes money context: four-eyes-request.yaml gained amount/currency/chain/
  destination_address (+swap fields); case_disposition_form renders a
  "Transaction under review" block via computeMoneyContext().

BLOOM brand-leak removal (this commit):
- pkg/i18n/languages.go: app.title "Bloom Identity Verification" → "Melusina
  Compliance" (+ es/fr/pt localized "Cumplimiento/Conformité/Conformidade
  Melusina"); client-facing brand leak closed.
- pkg/notification (notification.go/sms.go/email.go): default SMS/email endpoints
  → canonical mermail-sidecar gateway; from-email app@bloom.community →
  noreply@melusina.io; sender id PROCESS → MELUSINA. All remain Config-overridable.
- pkg/bridge/client.go: email cap fallback endpoint/From → mermail-sidecar /
  noreply@melusina.io (EMAIL_ENDPOINT/EMAIL_FROM still override).

## 0.1.36 — 2026-06-06 — Cold-Station unattended spawn: don't gate GrainFactory.spawn on a live session (appVersion 40)

0.1.35 wired the `AutonomousGrainCreator` cap into `createAndConnectProcess`, but
`GrainFactory.Spawn` still ran an UNCONDITIONAL "no active session" guard BEFORE
calling `createAndConnectProcess`. Sandstorm idles/shuts down the Station grain
between browser sessions, so on the real PSP routing path (popaye →
ccashconfig → `GrainFactory.spawn`) the Station is COLD: `f.sessionCtx`,
`powerboxSessionCtx`, and `latestSessionCtx` are all invalid, and the guard
returned `station.capnp:GrainFactory.spawn: remote exception: no active session
— open the Station in a browser first` — never reaching the autonomous path. The
one spawn that worked was a diagnostic fired while a browser kept the Station
warm. Net effect: case routing required a human to keep the Station open.

- `GrainFactory.Spawn` (pkg/station/server.go): the session-context guard is now
  CONDITIONAL. A live `SessionContext` is required ONLY by the interactive
  `HackSessionContext.createGrain` fallback. When the admin-granted
  `AutonomousGrainCreator` cap is held (`hasAutonomousCreateCap()`), the spawn
  proceeds with a cold session — `createAndConnectProcess` routes the createGrain
  through the held cap (server.go:4678) and never touches `sessCtx`. Cold +
  no-cap still fails closed (no silent spawn).
- Same conditional applied to the admin HTTP `handleAutoCreateProcess`
  (POST api/auto-create-process) and the hook-triggered `process_start` path
  (handlers_hooks.go) — both are unattended-by-design and were gated the same way.
- New `cold_spawn_test.go`: drives the real `GrainFactory.Spawn` capnp method
  with a COLD (invalid) session. With the cap held, it asserts the autonomous
  createGrain @0 is actually invoked (impossible if the old guard had fired);
  without the cap, it asserts the spawn fails closed with "no active session".

## 0.1.35 — 2026-06-06 — Unattended case spawn via AutonomousGrainCreator (appVersion 39)

Closes the last gap that made server-to-server DueProcess case creation hang.
The Station's autonomous spawn path (createAndConnectProcess → createGrainRPC)
created case grains through `HackSessionContext.createGrain @14`, which the live
Melusina shell ALWAYS routes through a human confirmation popup (it deliberately
does not honor `matchedRule.autoApprove`). In the unattended popaye →
ccashconfig → `GrainFactory.spawn` account-opening flow there is no human, so the
call blocked on a popup nobody answered and timed out as
`AdminGate.spawnCase: context deadline exceeded`.

- New `autonomous_create.go`: acquires the shell's purpose-built
  `AutonomousGrainCreator` capability (sandstorm/autonomous-create.capnp, id
  `0x9941ef246f9b5c04`) via a standard admin-approved Powerbox REQUEST — the same
  mechanism the Station already uses for its TeleScreen / AILagoon / ClientHub
  caps. New `POST api/claim-autonomous-create` (admin-gated) claims the grant,
  stows the live cap, and persists its sturdyref; the cap is restored on boot.
- `createAndConnectProcess` now PREFERS the granted `AutonomousGrainCreator` cap
  (createGrain @0 — no popup) and only falls back to the interactive
  `HackSessionContext` path when no cap is granted. A held-but-failing cap fails
  fast (never hangs on a popup in an unattended context). Post-create work is
  shared via the new `finishCreatedProcess` helper.
- Build-liveness sentinel `AUTONOMOUS-CASE-SPAWN-v1` baked into the binary.
- Security unchanged: only autonomous CASE-grain creation is enabled (intended
  PSP behavior). The cap is admin-granted, per-grain, target-type fixed at grant
  time, rate-limited, and revocable from the shell admin panel. The four-eyes
  maker≠checker approval inside the case workflow is untouched.

Also: `capServer.SetProcessType(tmpl.ProcessType)` ride-along now runs at boot
(from the published template) and after both hydration paths, so
`resolveSpawnRule` resolves multi-rule Station profiles by process type instead
of relying on the single-enabled-rule fallback.

## 0.1.33 — 2026-06-06 — Config-station bind SEND-side trigger (appVersion 37)

Ships the missing SEND half of the config-station GrainFactory bind. The
ccashconfig admin pearl already shipped the full RECEIVE side (NewOfferSession
→ POST /__offer/confirm → BindOfferedStation → BindProcessStation), but no
grain ever OFFERED the Station's GrainFactory to it, so `account-opening`
never bound and popaye's `SpawnCase("account-opening")` failed with
"broker: processType has no station factory in the directory".

- `pkg/station/server.go`: new admin-gated `POST /api/offer-grain-factory`
  → `handleOfferGrainFactory`. It mints a live GrainFactory cap (identical to
  `serveGrainFactoryToken`'s mint) and routes it to the Sandstorm shell
  powerbox via `SessionContext.Offer()` tagged `GrainFactory_TypeID` — the
  exact descriptor `fulfillGrainFactoryRequest` uses, the exact Offer shape
  `handleOfferGrain` uses. The shell then delivers the offer to ccashconfig
  (matchOffers{GrainFactory_TypeID}), which opens its bind-confirm page. The
  cap never leaves the trusted shell membrane (no sturdyref pasted over the
  wire); ccashconfig mints its own durable sturdyref inside BindOfferedStation
  so restart-rehydration still works. Admin-gated (mirrors the
  `serveGrainFactoryToken` `isAdmin` guard); fails closed on no live session.
- `pkg/station/templates/settings.html`: operator "Offer GrainFactory →"
  button in Station Overview so the bind is driveable from the admin UI
  (not just curl).
- `pkg/station/offer_grain_factory_test.go`: in-proc acceptance — a recording
  capnp SessionContext proves the offered cap is a LIVE GrainFactory
  (answers ListRules) tagged GrainFactory_TypeID, and that the trigger fails
  closed with no SessionContext. Pairs with ccashconfig's
  TestBindOfferedStation_OneClickFullBind (RECEIVE side) to close the full
  cross-grain bind.

## 0.1.30 — 2026-06-04 — Rebuild pre-stage (appVersion 34)

Version bump + clean rebuild of the active Process and Station binaries so
the current source — including the audited disposition-HMAC + maker/checker
ed25519 adjudication path — ships into the packed SPK. No source-logic
change; QC audit confirmed the disposition-integrity + 4-eyes role-gating
path sound. packageId resynced to sha256(app.spk)[:32].

## 0.1.29 — 2026-06-03 — Demo UI/UX polish (appVersion 33)

Compliance-console polish for the demo, UI/copy/wiring only — no auth,
four-eyes, ed25519 verification, or screening-verdict logic touched:
- Sanctions sign-off now uses an explicit "Connect wallet" Solflare control
  (replacing the raw prompt() base58/signature paste fallback).
- User-facing "Sandstorm" → "Melusina" terminology sweep.
- Merged the duplicate Settings/Workflows sidebar nav entry.
- Humanized the raw kanban card status token (in_progress → In Progress).
- Case-detail header now leads with the subject name; raw UUID demoted to a
  click-to-copy affordance.

## 0.1.20 — 2026-05-25 — Swiss→US-MSB regulatory purge (cycle14)

Swiss regulatory citations replaced with US-MSB equivalents across all
15 workflow YAML templates. EU AMLD5 and GDPR references also removed;
replaced with FinCEN, BSA, and 31 CFR citations per the PSP compliance
alignment.

Workflows affected (all 15 under `domains/msb/workflows/`):
- account-opening, pep-recheck, travel-rule (send/receive),
  account-decommission, onboarding, CDD, migration, risk-assessment,
  screening, transaction-monitoring, STR, trade-lifecycle, complaints,
  funds-safeguarding
- pep-recheck: AMLD5 → CDD Final Rule 31 CFR 1010.230
- account-opening: Swiss circular + AMLA → 31 CFR + BSA + FinCEN E-Filing
- travel-rule: Swiss jurisdiction thresholds removed
- account-decommission: Swiss Art. 22 + GDPR → BSA 31 CFR 1010.430

## 0.1.13 — 2026-05-24 — Cycle10 maker/checker + override-reason + HT13 wallet-sig

Closes the largest remaining compliance-officer wedge from the Pass-3
walkthrough (`PSP_COMPLIANCE_WALKTHROUGH_2026_05_24.md` §A.4 / Net
verdict #1): the Station approval form is no longer notes-only.

Three load-bearing additions to the approval surface:

1. **Maker/checker (4-eyes) banner.** When a workflow step's approval
   block declares `min_approvers >= 2` and `unique_reviewers: true`,
   the approval card now renders an explicit banner. The maker sees
   *"Maker step — Approval 0 of N. Your decision opens the four-eyes
   ceremony."*  The checker sees *"Approval 1 of N — awaiting checker.
   Original approver: @{handle} at {time}. The checker MUST be a
   different operator."* The maker is blocked client-side from acting
   as checker (matched by Sandstorm handle), and the server rejects
   any second submit from the same identityID.

2. **Override-reason capture.** When the case carries any open
   finding — `screening.overall_risk >= elevated`, `sanctions_score >=
   0.5`, `aml_hit`, `osint_red_flag`, `pep_match`, `payment_block.flagged`,
   `quarantine.flagged` — APPROVE now requires a free-text override
   reason ≥ 30 characters. Server-side enforced in
   `pkg/process.SubmitApprovalSigned` and
   `pkg/station.ApproveCaseSigned`. Audit row + approval history
   render the reason next to the verdict.

3. **HT13 wallet-signature capture.** Every approval (approve OR
   reject) submitted through the operator console must carry an
   ed25519 signature over a canonical JSON payload
   `{approver_pubkey, case_id, decision, nonce, override_reason,
   step_id, ts}`. The server rebuilds the payload independently from
   the request fields and verifies the signature against the claimed
   pubkey using `crypto/ed25519` — drift is rejected. The form's
   "Connect wallet" + sign-on-submit flow uses Solflare/Phantom
   `signMessage`; pubkey, signature, payload, and nonce are persisted
   to the per-step ledger + a new `ApprovalAudit` event row that
   regulator-facing exports can stream without walking the full
   process journal.

API additions (engine):
- `process.SignedApproval` struct
- `process.ApprovalGate.{FourEyes, Maker, AwaitingChecker, CanCurrentUserApprove}`
- `process.HasOpenFinding`, `process.FindingSummary`,
  `process.MinOverrideReasonLen`
- `process.BuildApprovalPayload`, `process.VerifyApprovalSignature`,
  `process.HashApprovalPayload`
- `Engine.SubmitApprovalSigned`, `Engine.ListApprovalAudits`
- `station.ProcessRunner.ApproveCaseSigned`,
  `station.caseFindingFields`
- `Approval` struct extended with `OverrideReason`, `Pubkey`,
  `Signature`, `Payload`, `Nonce` (all `omitempty`; pre-cycle10 rows
  decode cleanly).

Backwards compatibility: the legacy `SubmitApproval` wrapper still
accepts notes-only inputs and routes through `SubmitApprovalSigned`,
so existing callers compile. HT13 verification is skipped at the
engine layer when pubkey/signature are absent (legacy tests + the
Cap'n Proto write paths); the Station console handler enforces it
strictly up-front with a clean 422.

## 0.1.12 — 2026-05-24 — Grapple context on station setup (pass-4)

The Station first-launch setup screen's "Pick a Procedure..." action
now sends its `powerboxRequest` with a Melusina-Grapple-compliant
`context` string (10-256 chars) explaining why the Templates capability
is needed. Before this fix, the request fired the Melusina shell
warning `pearl sent powerboxRequest WITHOUT context` (FINALE2E Pass-3
audit step 0025), which is on track to become a hard error in the
Grapple shell. Operator-facing flow is unchanged; only the missing
context field was added. Also adds a `saveLabel` so the Melusina
picker labels the cap as "Compliance procedure template" in the user's
saved-caps list.

## 0.1.11 — 2026-05-24 — PSP lexicon rename (pass-4)

Bazaar action labels and pearl nounPhrases harmonized to the canonical
PSP/MSB vocabulary in `agentchat/PSP_LEXICON_2026_05_24.md` §2.3. Action
titles are sentence-case per the lexicon. The "client portal" action is
relabelled `Open KYC intake portal` with nounPhrase `KYC intake portal`,
naming the regulated function it serves (Sumsub "KYC Portal" / Onfido
"Verification flow"). Action[1]'s nounPhrase drops the "compliance"
prefix to land on the bare `case` industry standard (ComplyAdvantage,
NICE Actimize, Hummingbird; FATF Rec. 10/12 documentation). No
application-logic changes — operator-facing copy only.

## 0.1.5 — 2026-05-06 — icon hi-res

Standardised icon embeds via the spkmodule v0.6.0 pre-pack hook. The
pkgdef now carries 128/256-px PNGs in both `appGrid` and `pearl` slots
and 150/300-px in `market`, regenerated from the canonical PNG. No
application-logic changes since 0.1.4.

## 0.1.0 — 2026-04-15

Initial dev build of the DueProcess pearl for the ccash constellation.
