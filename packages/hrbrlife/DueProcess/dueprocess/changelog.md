# Changelog

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

Version bump + clean rebuild of all four binaries (dueprocess-process,
dueprocess-station, dueprocess-client, dueprocess-screening-sidecar) so the
current source — including the audited disposition-HMAC + maker/checker
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

Initial dev build of the DueProcess pearl for the ccash
constellation. Ships the Station operator console plus the standalone
dueprocess-screening-sidecar binary cyberteller drives for M3/M4 deposit
screening. (Historical: the sidecar binary was named
`aitx-screening-sidecar` in pre-rename dev builds.)
