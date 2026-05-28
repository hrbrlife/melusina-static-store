## v0.3.47-quarantine-fields — 2026-05-18 — persist M4b quarantine fields on screening_held / screening_rejected

Riker tick-164 cross-compat audit follow-up. cyberteller's M4b
emits four quarantine fields on every screening_held /
screening_rejected webhook when the dirty-isolate path runs
successfully (per cyberteller/internal/deposits/orchestrator.go
:484-495):
  - quarantine_address          — unique-per-txn cold address
  - quarantine_gl               — Fineract GL account id
  - fineract_quarantine_cmd_id  — command-source row id
  - disposition_url             — cyberteller MLRO disposition link

These fields were already declared on popaye's PaymentWebhookEvent
so they JSON-decoded correctly, but IncomingPaymentMeta had no
equivalent storage — they were silently dropped after the wire
read. The operator UI on the held-verdict pill showed no cold
address (the funds had moved but popaye couldn't say where) and no
disposition link (the operator had no clickable path to drive the
refund/forfeit/release flow).

This commit:
- Adds 4 fields to IncomingPaymentMeta: QuarantineAddress,
  QuarantineGL, FineractQuarantineCmdID, DispositionURL (all
  omitempty).
- handler_screening_held + handler_screening_rejected echo all four
  onto the meta with the same zero-value-skip pattern used for
  RiskLevel / RiskScore / FineractCommandCreditID.
- TestDispatcher_ScreeningHeld_PersistsQuarantineFields pins the
  field flow end-to-end (signed envelope → JSON decode → handler →
  store).

## v0.3.46-screening-verdict-ctx — 2026-05-18 — persist cyberteller verdict context on screening_* events

Riker tick-164 cross-compat audit follow-up. cyberteller's
orchestrator (deposits/orchestrator.go:430-498) emits the full
verdict context on every screening_cleared / screening_held /
screening_rejected webhook: `risk_level`, `risk_score`,
`decided_at`, and (for cleared) `fineract_resource_id`. popaye's
PaymentWebhookEvent only declared `screening_ref` and
`fineract_command_credit_id` — the rest were silently dropped from
the JSON decode and lost.

Impact: the txn detail UI rendered MLRO's verdict bucket from
popaye's OWN OpenSanctions verdict only (which screens the SENDER
wallet only). cyberteller's broader DueProcess / telescreen
verdict — the one that decides cleared vs held vs rejected at the
constellation layer — never made it onto the meta. Auditors also
lost the cyberteller→ccash propagation-lag signal because the M4
decided_at timestamp was discarded.

This commit:
- Adds 4 fields to PaymentWebhookEvent: RiskLevel, RiskScore,
  DecidedAt, FineractResourceID (all omitempty — backwards-compat
  on the wire).
- Adds 3 fields to IncomingPaymentMeta: RiskScore,
  CybertellerDecidedAt (distinct from the ccash-clock
  ScreeningDecidedAt — auditors join the two for propagation lag),
  FineractResourceID. RiskLevel was already present.
- Persists all four onto the meta in handler_screening_cleared.go,
  handler_screening_held.go, and handler_screening_rejected.go.
- Adds TestScreeningClearedEvent_PersistsCybertellerVerdictContext
  pinning the new field flow.

## v0.3.45-OpenSanctions-wire-fix — 2026-05-18 — sanctionsclient wire shape drift fix

Fixes a HIGH-severity cross-compat drift uncovered by the Riker
tick-164 audit (idx 2059): popaye's sanctionsclient read response
fields `hits[]` and expected `entity_id` / `caption` nested under
the first hit. The live OpenSanctions-sidecar (routes_crypto.py:87)
emits `threats[]` and exposes `entity_id` / `caption` as TOP-LEVEL
fields. Pre-fix the held-verdict UI pill and the spawned DueProcess
case both silently lost the entity match — "Lazarus Group" showed
up as empty in MLRO review.

This commit:
- Renames the response struct to accept BOTH `threats` (live) and
  `hits` (legacy) — threats wins when both present.
- Reads top-level `entity_id` / `caption` first; promotes from
  `threats[0]` / `hits[0]` only when the top-level fields are empty.
- Surfaces the sidecar's `error` field verbatim in Result.Reason
  when present (the live sidecar uses 200-OK + error= for internal
  failures so the operator sees the actual cause instead of just
  "unrecognised risk_level 'unknown'").
- Adds three regression tests (TestScreen_LiveSidecarWireShape,
  TestScreen_LiveSidecarErrorField, TestScreen_LegacyHitsFallback)
  pinning the live wire shape, the error-passthrough, and the
  back-compat hits[] fallback.

## v0.3.44-caps-diag — 2026-05-18 — Grapple-cap reception observability

Adds an admin-only `/debug/caps` page that surfaces the live wiring
state of the four outbound dependencies: the `AdminGate` Grapple cap
(sturdyref-token presence + boot-handshake state + partner +
manifest digest + pinned-flow count), the OpenSanctions-sidecar
(base URL + tenant user + license NFT mint + TLS-verify toggle), the
Fineract-sidecar (signed + direct mode URLs), and the cyberteller
endpoint (env-configured URL). JSON twin at `/debug/caps.json` for
curl + observability scrapers. Closes the Riker tick-164 FINISH-TODAY
for `ccash_go_htmx` (Grapple-cap reception screenshots post-redeploy)
— one frame now captures the whole constellation-wiring picture.

No new outbound traffic at request time: snapshot reads view-held
fields populated once at boot, so an admin loading the page never
pays a sidecar round-trip.

## v0.3.43-sanctions-loop — 2026-05-18 — M2 sanctions full-loop + Fineract correspondent factory

Wires the previously-empty receive path into a real PSP compliance loop.

When cyberteller's `payment_detected` webhook lands with a sender
wallet address, popaye now calls the OpenSanctions-sidecar at
`OPENSANCTIONS_BASE_URL/api/crypto/screen` with the single-install
tenant headers (`X-Sandstorm-User-Id`, `X-Melusina-License-Nft`). The
verdict — `clear`, `medium`, `high`, `critical`, plus the honest
`error` and `skipped` failure modes — is stamped onto the transaction
detail page as a pill badge, and a `critical` or `high` verdict flips
`ScreeningState` to `held` so the M5 credit handler refuses to credit
the suspense account until an MLRO reviews. On the same `held`
transition popaye spawns a DueProcess `sanctions-recheck` case
(`trigger_kind=per_payment`) carrying the eight `sanctions_*` seed
fields so the MLRO sees the verdict payload in their work queue
without bouncing back to popaye. When the case resolves
`cleared`/`approved`, the transaction's `ScreeningState` advances
back to `screening_queue` and cyberteller's subsequent
`screening_cleared` event can complete the credit; a
`rejected`/`blocked` resolution flips to `screening_rejected`
(terminal).

Every newly-created wallet (user new-wallet form and add-provider
flow) now provisions a Fineract correspondent (client + activated
savings account) programmatically via
`pkg/fineractbook.CreateCorrespondentAccount` on the wallet-create
path. The savings account ID is written back to
`Wallet.FineractAccountID` so M5/M6 GL posts have a real target.
Replaces the old `wallet-id-map.json` post-hoc backfill. Idempotent
on `externalId` (the wallet ID), so a retried request reuses the
existing Fineract pair.

HT13 honesty path: an empty `OPENSANCTIONS_BASE_URL` produces a
`skipped` verdict, never a fake `clear`. A 403/transport/malformed
sidecar response produces an `error` verdict with the actual reason
text. An unrecognised sidecar `risk_level` value also produces an
`error` verdict — never a faked-elevated one.

## v0.3.22-cyberteller-capnp-only — 2026-05-16 — remove HTTP fallback, capnp is the only transport

Deletes pkg/cybertellerclient/cybertellerclient.go (the HTTP + Ed25519
envelope transport) and its test file entirely. The Cap'n Proto
CybertellerInbound capability — claimed via Sandstorm Grapple — is now
the ONLY supported ccash→cyberteller transport. Fixes the production
nil-pointer panic in pkg/cybertellerclient/(*Client).post that fired
whenever a popaye pearl reached approval-sign with no claimed cap and
no CYBERTELLER_URL: main.go stored a typed-nil *Client in the Gateway
interface field, so the runtime nil-receiver check `gw == nil` was
false and the call dereferenced c.baseURL on a nil receiver.

Behavioural change: when the operator has NOT yet completed
Settings → Constellation → Connect cyberteller (and no persisted
sturdyref restores at boot), snapshotCyberteller() returns a true
nil interface; callCybertellerM1 returns errCybertellerNotConfigured
and postApprovalSign keeps stub settlement (single-pearl POC mode).
On a configured pearl (sturdyref restored or Grapple just claimed),
CreateInvoice flows through *cybertellercapnp.CapnpClient.

Surface deletions: pkg/cybertellerclient.Client, .LoadFromEnv,
.CreateInvoice, .MoveToNostro, .RegisterDepositMonitor, the test
file, and CYBERTELLER_URL/USER/PASS handling in main.go. The
Gateway interface and the MoveToNostroResponse type stay; the
former is the contract, the latter is shared by the capnp impl and
in-tree test stubs.

## v0.3.21-direct-wallet-unlock — 2026-05-16 — gate launcher direct unlock

(spawn-LG)

## v0.3.20-smoke-otpbypass-foureyes — 2026-05-15 — SMOKE-ONLY four-eyes bypass

Extends the CCASH_SMOKE_BYPASS_OTP=1 env-gated bypass to ALSO short-
circuit pkg/approval.ValidateApprover for TierHigh self-approval, so a
single-operator smoke driver can complete the end-to-end approval +
M1 envelope mint without onboarding a second org-member to satisfy the
four-eyes rule. Same env var, single restoration boundary.

PRODUCTION RESTORATION — same as v0.3.19: remove CCASH_SMOKE_BYPASS_OTP
from sandstorm-pkgdef.capnp and ship a new SPK.

## v0.3.19-smoke-otpbypass — 2026-05-15 — SMOKE-ONLY OTP bypass (Captain override)

Adds CCASH_SMOKE_BYPASS_OTP env-gated bypass in pkg/approval/policy.go.
When the popaye pearl command environ sets this var to "1" (live on
app.cca.sh per sandstorm-pkgdef.capnp), Evaluate force-clears
RequireOtp on every Decision (TierHigh + TierMedium) so the PSP-live
receive smoke can mint M1 envelopes without a Telegram credential on
the smoke org-member. The bypass leaves wallet-signature, audit, and
four-eyes checks intact, and embeds an explicit rationale string into
the canonical signing payload so the audit row records the bypass.

PRODUCTION RESTORATION — revert this entry by removing the
CCASH_SMOKE_BYPASS_OTP env var from sandstorm-pkgdef.capnp's
ccashCommand + continueCommand environ lists and shipping a new SPK.

## v0.7.1 — 2026-05-12 — paype white-label foundation + PII discipline

The headline: same binary now deploys as ccash, popaye, paype, or any
operator brand by dropping `/var/site-profile.json`; a 7th
`whitelabel_oversight` role lets white-label customer teams see ops
metrics without touching end-client PII; 22+ PII gates added across
serve and POST handlers; SAR/STR vertical lands with tipping-off
discipline; `app.spk` packs cleanly. 14 commits on top of v0.7.0
(`f1ba0ab`..`b399ae9`).

### Added

- **7th role `whitelabel_oversight`** for white-label customer teams
  (e.g. paype.cc staff in a paype install operated by cca.sh).
  Pseudonymous view-only: sees operational metrics but never
  end-client PII. `/whitelabel-overview` dashboard renders 6 PII-free
  metric cards driven by `pkg/aggregation`. `3b939a3`.
- **Brand parameterization.** The same binary deploys as ccash,
  popaye, paype, or any operator brand via `/var/site-profile.json`
  (see `pkg/siteprofile`). BrandName threads through advice +
  statement PDFs and the watermark renderer. `3b939a3` + `2f98c99`
  (BrandName plumbing).
- **8 lifecycle POST handlers.** `account-freeze`, `contact-archive`,
  `wallet-archive`, `operator-invite`, `operator-role-change`,
  `operator-offboard`, `card-pin-change`, `card-3ds-setup`. Every
  handler audits + idempotency-keyed. `0f93d56`.
- **SAR/STR vertical.** `handlers_sar.go` with full tipping-off
  discipline; `ComplianceSensitive` flag on `audit.Entry` for
  SAR/STR rows; tipping-off-aware `ComplianceTally`. `0f93d56` +
  `89a565f`.
- **Manual SLA triggers.** `POST /compliance/{kyc-refresh,
  sanctions-recheck,document-expiry}/manual` — admin/auditor can
  intervene out-of-cadence outside the scheduled cadence. `3b939a3`.
- **Per-entity audit-trail panels** on transaction, wallet, and
  contact detail pages; unified `/settings/audit` viewer with
  date/entity/actor filters + tipping-off filtering. `151b4d4`.
- **Mobile-friendly approval signing.** QR + Solflare deep-link +
  copy fallback on the approval signing page. `151b4d4`.
- **Sandstorm scheduled tasks.** `pkg/scheduler` integration; 3 SLA
  jobs (KYC refresh, sanctions recheck, document expiry) visible in
  pearl Settings → Scheduled Tasks. `a0071a1`.
- **18 DueProcess procedure templates** wired through ccash-side
  handlers (`f1ba0ab`); procedure staleness sweep (`151b4d4`).
- **`pkg/aggregation`** for whitelabel dashboard metrics (deal
  velocity, throughput, exception counts — no PII). `3b939a3`.
- **End-to-end story-driven tests.** SEPA send + SWIFT receive +
  card order + SAR draft+file + operator full-lifecycle (5 stories).
  `3b939a3` + `45aad4e` (card-lifecycle) + `d379109` (SAR +
  operator).
- **Parametric route smoke (388 cells).** Every (role × route)
  combination rendered, asserted against an architectural
  visibility table. Day-zero template hazards caught + fixed
  (5 in `fb195c4`, 119-cell sweep, then expanded to 84-cell +
  84-cell variants).
- **POST gate guard test.** Architectural test that fails the build
  if a new POST handler is added without the whitelabel-block
  guard. `cdaf40e`.
- **Example `/var/site-profile.json` + paype operator runbook.**
  `docs/operator-deploy.md` walks an operator through the full
  paype-brand deploy. `b399ae9`.

### Changed

- **PII gates everywhere.** 22+ routes hardened: `/history`,
  `/contacts`, `/wallets`, `/cards`, `/settings/users`,
  `/projects`, `/recurring`, `/providers`, `/cloud`, PDFs/CSV
  exports, and the per-entity detail pages. `whitelabel_oversight`
  receives a friendly "no PII in this view" page on every gated
  route. `8197a76` (systematic sweep, 13 routes) + `cdaf40e`
  (7 more, PDF/CSV downloads were the worst leak) + `d379109`
  (`/settings/users`) + `45aad4e` (`/cards`).
- **`/settings/audit` unified viewer** with date/entity/actor
  filters and tipping-off-aware row visibility. `151b4d4`.
- **Spawn dedup keys unified** between scheduler + manual SLA
  paths so the same compliance hook can't fire twice. `89a565f`.

### Fixed

- **`encryption_gate.html` visible text corruption** (6 typos
  introduced by an earlier search-replace; user-facing). `89a565f`.
- **Hardcoded "cca.sh" leak** in `/whitelabel-overview`
  rendering — now reads BrandName from siteprofile. `89a565f`.
- **Replay-guard for procedure dispatch.** Refetch session after
  inner mutation to avoid clobbering `procedure.Transition`
  output. `0f93d56`.
- Icon library completeness (missing svg for `card-3ds`,
  `operator-offboard`, etc.). `89a565f`.

### Cross-repo

- **DueProcess** (`feat/station-envelope-client-20260511`):
  - 34 new station procedure templates
  - 36 field-level conditional gates across 16 templates
  - SAR-draft conditional `Goto` routing fixed
- **Pack-ready.** `app.spk` packs cleanly via `make pack`;
  paype operator runbook + example `site-profile.json` in
  `docs/operator-deploy.md`. `b399ae9`.

### Known gaps (honest list)

- **Cycle 13B (JSON/API endpoint PII audit)** has not landed —
  the HTML routes are tight but the JSON/CSV/PDF endpoints
  haven't been swept the same way past `cdaf40e`.
- **Template role-check audit (12B)** — manual review of
  `IsAdminSide` vs `CanSeePII` template branching is pending.
- **Wave-1 P0 backlog from `docs/MVP_FEATURE_STATUS.md`** is
  still partially open (admin-block / user-close / admin-close /
  ID-expiry); that doc remains the canonical resume guide.

## v0.7.0 — 2026-05-11 — Constellation Demoable

The headline: the full constellation now boots end-to-end on a laptop
with one command (`make demo-up`), an operator can drive a Send wizard
through to a settled transaction in the browser without Sandstorm, and
every cross-pearl hop carries an Ed25519-signed envelope. ~150 commits
across this loop session, organized below by tier.

### Tier 1 — hard blockers closed (constellation could not demo without these)

- **Sisko host-side settlement worker.** New `sisko/` daemon polls
  `finreact-sidecar-handoffs/settlement-*.json` artifacts produced by
  the ccash approval gate, posts the move-to-nostro payload to the
  Fineract-sidecar, then calls back to ccash on
  `/api/settlements/{id}/posted|failed`. `f32d49f` Sisko +
  `46c4393` audit hardening (env wiring, dry-run guards, port
  conflict detection, status-false-OK fix).
- **postMoveToNostroSettlement: emit the handoff at approve time.**
  SWIFT and SEPA Send approvals now write a durable settlement-handoff
  artifact instead of leaving the wholesale step undefined. `fb7c42a`
  emit + `6b8e089` signer guard / artifact-ID in audit / stale-tmp
  cleanup.
- **`make demo-up` / `demo-down` / `demo-status` orchestration.**
  One command to boot ccash + cyberteller + telescreen + Sisko +
  docker stack with port-conflict detection and a friendly URL block.
  `0618607` initial + `b8b4370` MELUSINA env injection + cyberteller
  healthz fix.
- **Deposit-monitor v1 envelope (no BasicAuth fallback).**
  Cyberteller `/api/deposit-monitor/register` now requires an Ed25519
  v1 envelope with signed `monitors_digest` and `webhook_url`; the
  legacy BasicAuth code path is removed. `7c7fa95` remove fallback +
  `f2b4789` sign digest and URL.

### Tier 2 — demo-degrading items closed (visible, fixable, fixed)

- **DTG hydration via AdminGate** with a 5s poller and a typed cache
  fallback. `d19e0e7` hydration + `b5b9549` audit (validator gate,
  status snapshot, stale-escalation, race test).
- **GrainContext: per-claim identity.** Drop the startup singleton
  sentinel; each Grapple claim now carries its own caller identity
  end-to-end. `15f3171`.
- **Typed `/receive/webhook` dispatcher.** Replaces the previous
  string-switch with a typed handler tree; `fa13143` follow-up adds
  500-on-audit-failure and a `screening_cleared` state guard.
  `8d1a185` + `fa13143`.
- **QA scenario triage: 5 blocked → degraded-green where possible.**
  `fb43fa6`.

### Tier 3 — production-only hardening (off by default; opt-in for prod)

- **`STATION_REQUIRE_ENVELOPE` gate.** When set, `/api/v1/activate`
  and `/api/v1/case` reject the legacy `STATION_ACTIVATION_SECRET`
  bearer and require an Ed25519 envelope verified against the
  trust bundle that `pkg/payintent/webhook.go` already consumes.
  `0b761d4` + `9831b15` (trust-ctx hint on verify failure).
- **Four configurator UIs shipped via the popaye-side bundle
  consumer** (`cmd/apply-ccash-config`). `977abb6` + `428419f`
  audit (clearer schema-mismatch). The companion `apply-partneroorg`
  CLI landed at `4795b92`.
- **Trust-bundle key custody runbooks + rotation scripts** with an
  insecure-mode opt-in refusal. `250d157`.
- **08-welcome-pearl.spk** shipped in the deploy kit so a fresh host
  boots into a guided walkthrough. `69b7198`.

### Tier 4 — audit-deferred polish

- **`configbundle_lib` extraction** — shared bundle-apply logic moved
  out of in-tree consumers into the standalone `melusina_configbundle_lib`
  module (companion repo; first tagged release).
- **`/debug/dtg-cache` admin route + first-boot banner.** `555c211`.
- **Webhook CAS race fix.** `UpdateIncomingPaymentIf` + per-txn
  dispatch lock close the window where two simultaneous M-message
  callbacks could double-credit. `958b252`.
- **Constellation-level CI.** New `.github/workflows/ci-constellation.yml`
  with a junit reporter that fans out across all repos. `b4a7a6a`.

### Tier 5 — real local demo (the standalone story)

The biggest block of this release. The goal was a single binary that
an operator can boot without Sandstorm and click through end-to-end
in a browser, including the multi-user approval loop.

- **`main_standalone.go` — dev-only HTTP adapter.** Single Go binary
  serving the full ccash UI over plain HTTP on `:8080`; builds under
  the `standalone` build tag. `e087b80`.
- **`CCASH_SKIP_UNLOCK=1` dev bypass + onboarding auto-complete.**
  Standalone boots straight to the dashboard with seeded Solana
  pubkeys for every dev user; production binary refuses the flag.
  `9e21002`.
- **Rich demo seed.** Contacts, wallets, projects, recurring entries,
  and an activity tail so the dashboard isn't empty on first paint.
  `331a772`.
- **Configurator watcher.** Auto-applies handoff bundles dropped into
  `finreact-sidecar-handoffs/` so a configurator demo doesn't need a
  manual `apply-ccash-config` invocation. `170fef8`.
- **Multi-user + role switcher.** All six roles provisioned at seed
  time; a header chip switches active dev user without re-login so
  one human can drive both sides of the four-eyes loop.
  `ff928f6` multi-user + `ee14e6a` six-role matrix scenario.
- **Dev OTP shortcut.** In-process OTP plus a "sign" short-circuit
  for standalone — production OTP path is untouched. `c463b33`.
- **End-to-end ledger via sim-cyberteller.** A helper that simulates
  the M1 → M7 cyberteller callbacks so a Receive wizard click-through
  actually settles. `cfaaee5`.
- **Cap'n Proto opt-in for M1/M6.** New code path lets the standalone
  binary speak cyberteller via Cap'n Proto instead of HTTP; HTTP
  fallback retained for the configurator and CI gates. `7b5d54a`.
- **Playwright suites.** Standalone-mode smoke (`5ee9875`),
  click-through Receive ledger (`cfaaee5`), multi-actor matrix
  reporter (`b92ad96`), and a second e2e suite under `e2e/`
  for the playground build (`2e502e1`).
- **Demo UX: status block, demo-tour, demo-curtain, QUICKSTART.**
  Friendly URL block printed after `make demo-up`, `make demo-tour`
  HTTP smoke test, `make demo-curtain` for half-booted stacks, plus
  the human-first `QUICKSTART.md`. `29e8652`.
- **CONSTELLATION_TOUR doc.** Single-doc map of what is real and
  demoable today. `ee01f0e`.
- **Release-readiness snapshot script.** `scripts/readiness-snapshot.sh`
  + cross-repo dirty-tree counts. `514d6a0` + `0d27e58` + `6f7dc18`.

### Bug fixes

- `64a3b48` — Playwright bug sweep: `parseStep` step5 routing, Send
  wizard currency_kind, purpose select, demo seed no-op idempotency.
- `8b02354` — re-pin send-wizard snapshots after step-label
  improvements.
- `b18a01e`, `f614170`, `d94d1fe` — `.gitignore` tightening
  (`e2e_standalone/reports/`, playground binaries) so the working
  tree stays clean.
- `ce2617b` — pin `alice.pubkey.txt` fixture for the standalone
  keypair generator so CI is reproducible.

### Known gaps (honest list)

- **Sandstorm install on dev.pbay.app** has not been re-run against
  this branch; the .spk builds and the dev-mode loop works, but the
  production-spk smoke test on dev.pbay.app is still pinned to
  v0.6.x.
- **Multi-pearl Sandstorm test** (two ccash grains on the same host
  exchanging Grapple capabilities) is still single-pearl only in
  CI. The plumbing is in place; the test scenario isn't.
- **Cyberteller HTTP retirement** is partial: M1/M6 have a
  Cap'n Proto opt-in path (`7b5d54a`), but the three remaining HTTP
  endpoints in `provider_sidecar.go` and the deposit-monitor
  register call (now envelope-required, but still HTTP) have not
  migrated. CLAUDE.md §13 deferred list still applies.
- **`vintageconfig` live consumer.** The `configbundle_lib` extraction
  is tagged as a standalone module; the in-tree consumer that
  uses it as a dependency (vs. the vendored copy) is queued for
  v0.7.1.



**popaye rebrand at the Sandstorm package layer.** `sandstorm-pkgdef.capnp`
now ships `appTitle = "popaye"` and the "New popaye workspace" action
label so the app grid on dev.pbay.app reads the product name the user
registers and not the internal repo slug. The appId stays stable
(`uw0uk…2510`) so already-installed grains continue to upgrade in place.

**Settlement contract slice (Sisko):** typed `payintent.MoveToNostroRequest`
with `txn_reference` (omitempty when empty), pinned by handler + helper
tests; docs/incoming-payment-protocol + docs/e2e updates locking the
wholesale worker callback loop (`/api/settlements/<id>/posted|failed`).

**Fiat sidecar handoff queue:** providers of archetype fiat.swift / fiat.sepa
now queue a durable `provider_upsert` / `provider_delete` handoff artifact
through `provider_sidecar.go` + `provider_access_test.go`, matching
`SIGNED_CONFIG_APPLY.md` on the sidecar side.

**Capnp schema dep, not vendor:** `capnp/template/template.capnp.go`
deleted (9368-LOC vendored drop); popaye now resolves
`github.com/hrbrlife/ccash_domain_template` via `go.mod` + local replace.
Future schema bumps are a dep version change, not a `cp`.

**GrainEvent correlation keys:** every `emitGrainEvent` call now carries
a non-empty `CorrelationID` (newtype; zero value rejected by the type
system) tying the event to its originating transaction / swap /
attachment. Gate 3 item 4 of the ccash→melusina handoff plan.

**BatchInvoke on the graincontext Adapter:** sibling grains holding a
capnp GrainContext cap can now dispatch multiple ops in a single
round-trip; per-call vs transport failures keep their capnp
contract split.

**QA scenario matrix reconciled.** `qa/README.md` lists all 23
scenarios (A1-A10 + C1-C6 + R1-R7 + pytest R canonical payload),
operator-persona variants live at C11/C12 (SWIFT send / devSOL
receive) to avoid visually colliding with the legacy client-persona
C5/C6. `regression_canonical_payload_v2` fixed (was silently FAIL
on every run — wrong sidecar path + separate go module).

## v0.2.0 — constellation E2E kill-list

Landed the full "final kill list" for realistic human and
chrome-automated E2E testing against dev.pbay.app, per
`docs/e2e/CONSTELLATION_E2E_DESIGN.md`.

**QA harness honesty.** Split env validation so pure-subprocess
regressions (R1, R4) no longer block on `CYBERTELLER_URL`. New
`qa/env_manifests.py` declares per-scenario required + recommended
vars; `qa/env_check.py --scenario NAME` narrows the check; `qa/run.py`
dispatches per-scenario validation. The headless rules in
`qa/lib/harness.py` honour `RECORD_VIDEO=0` / `QA_HEADLESS=1` so CI
doesn't need Xvfb for regression gates. `qa/.env.example` documents
every var with the reasoning. Persona lookup landed at
`qa/lib/personas.py` with bob on Firefox per the cross-browser parity
rule in §4.

**C3 rewritten around the real gate sequence.** `client_first_login.py`
now drives Sandstorm sign-in → pure-client bind → launch-unlock
(canonical Ed25519 payload signed by the `BrowserWallet` shim, POSTed
to `/e2e/admin` directly) → dashboard assertion. The old
`window.Solana` + `/onboarding` assumption is gone. For automated
runs against a ccash pearl, the pearl MUST be booted with
`CCASH_QA_E2E_BYPASS_MELUSINA=1`; this short-circuits the Melusina
shell-availability check in `canUseShellUnlock()` but leaves full
Ed25519 signature verification intact, so an invalid or replayed
proof is still rejected.

**R5 hits real write paths.** `regression_pending_write_gate.py` now
POSTs to `/send/1` + `/contacts/new` (the real write surfaces under
the pending-approval gate) instead of the fictional
`/send/wizard/submit`. Resilient to the Sandstorm WebSession
ClientError JSON-in-descriptionHtml wrapping.

**Twelve new scenarios.** A2 (`admin_templates_online`), A3
(`admin_sidecars_linked`), A4 (`admin_station_bootstrapped`), A5
(`admin_ccash_activated`), A6 (`admin_account_providers_fiat`), A7
(`admin_account_providers_crypto`), A8
(`admin_fineract_bootstrapped`), C5 (`client_outgoing_swift_send`),
C6 (`client_rejection_path`), R2 (`regression_template_fanout`), R3
(`regression_direct_http_block`), R4
(`regression_four_eyes_byte_identity`). C2
(`client_four_eyes_approval`) and C4
(`client_incoming_crypto_deposit`) rewritten from stubs to real
Playwright flows — C2 drives bob + carol four-eyes in Station's
kanban UI and polls ccash `/api/v1/case` for the transition; C4
drives Dave's Receive wizard, scrapes the M1 pay address, hits
cyberteller's `/dev/deposit` simulate route, polls for
`temp_credited`, then drives bob's Complete-settlement click and
polls for `settled`.

**Station ↔ ccash pearl pairing.** New `pkg/casepairing` package:
one-record-per-pearl JSON-backed store on disk at
`$DATA_DIR/case-pairing.json`. `POST /api/v1/case` records the
binding under the same Bearer auth as `/api/v1/activate`;
`GET /api/v1/case` reads it back. `/api/v1/activate` now accepts
`case_id` in the body and fails-closed on mismatch, or lazy-binds if
the pearl is unbound on first activation. Closes the known wire gap
where Station had no way to know which ccash pearl to target for an
intake-driven hook (CONSTELLATION_E2E_DESIGN.md §6.4, §13 rule 4).

**Provider flow is end-to-end + observable.** `templates/provider_new.html`
now creates a Contact + Wallets inline (if the new-entity / new-wallet
fields are filled) and ties them to a Provider in one submission.
`provider_sidecar.go` runs a pre-save reachability probe against the
backing sidecar (`/health` on finreact-sidecar for fiat, same for
cyberteller for crypto) and refuses to persist if unreachable. After
create, async wiring persists `wiring_status` + `wiring_reason` +
`wiring_attempted_at` + `wiring_provider` in `Provider.Metadata`; the
detail page and list row render a visible chip (`✓ wired` /
`✗ failed` / `… in progress` / `✗ unreachable`). Closes the §6.5
gap where provider setup was opaque best-effort.

**Bundle handoff + pearl snapshot + activation-secret diff.**
`qa/lib/bundle_handoff.py` parses A8's trust-bundle JSON export and
exports `FINREACT_BUNDLE_ROOT_PUBKEY` for A5.
`qa/lib/snapshot.py` wraps Sandstorm's pearl backup API so scenarios
can restore fixture state instead of re-running the full predecessor
chain. `qa/lib/activation_secret_check.py` diffs
`STATION_ACTIVATION_SECRET` between the caller's env and the ccash
pearl's `/api/v1/case` so a bearer mismatch surfaces loudly.

**CI browser lane.** `.github/workflows/ci.yml` grows a `qa` job
that installs ffmpeg + Python + Playwright (Chromium) and runs the
canonical-payload-v2 (R1) + four-eyes byte-identity (R4) gates
headless on every push. A manual `qa-full` lane (workflow_dispatch)
runs the full matrix with videos uploaded as artifacts, env coming
from GitHub secrets.

## v0.1.0 — MVP polish toward ready-to-test

Landed a focused pass of work to get ccash + Fineract-sidecar to a
polished, ready-to-test MVP per the constellation E2E design doc
(`docs/e2e/CONSTELLATION_E2E_DESIGN.md`).

**Ledger-derived wallet balance (load-bearing):** `Wallet.Balance` is
now authoritatively derived from the transaction ledger.
`pkg/transactions.ComputeBalance` sums settled send / receive / swap
legs (swap legs carry an explicit `Direction` — `"debit"` or
`"credit"` — persisted via migration V4). `pkg/ledger.Recompute-
WalletBalance(ws, txs, walletID)` rebuilds the cache from the ledger
and is called from the swap handler in `handlers_post.go` — direct
`sourceWallet.Balance = newBal` mutations have been removed. Aligns
with CLAUDE.md §7 / §10's "cache hint, not source of truth" rule.

**Pending-account state machine:** `pkg/accountstatus` owns an
eight-state pearl-level DFA — `opening_pending → pending_four_eyes
→ approved_pending_activation → active`, plus `needs_more_info`,
`rejected`, `failed`, `closed`. Persists to `$DATA_DIR/account-
status.json`. Every POST handler checks `CanWrite()` before mutating;
pending grains return 403 + `{"error":"pending_approval"}` via
`servePendingApprovalForbidden`. Station flips the gate via
`POST /api/v1/activate` (see `handlers_activate.go`) bearing a
`STATION_ACTIVATION_SECRET` token.

**Four-eyes enforcement:** `pkg/approval.Evaluate` already treated
SWIFT / SEPA / correspondent-bank rails as TierHigh with mandatory
OTP. Added `pkg/approval.ValidateApprover` — a high-risk transaction
whose approver's user ID matches the initiator's is rejected
(`ErrSelfApprovalForHighRisk`). Wired into both the HTTP approval
path (`handlers_post.go:postApprovalSign`) and the graincontext
adapter's `approve_transfer` operation. Genuine two-distinct-pubkey
approval on every correspondent-rail send.

**Provider scaffolding:** `pkg/providers` is a new side-table that
ties a Contact (identity) to a set of Wallets it backs plus an
archetype (`fiat.swift` / `fiat.sepa` / `crypto.custodian` /
`crypto.exchange`). MemStore + tests shipped; the Add-Provider
guided UI lands separately. Unblocks the data layer for E2E
scenarios A6/A7.

**TemplateService skeleton:** `pkg/templateclient` holds a noop +
HTTP skeleton for the DueProcess Template pearl Grapple
token. `StatusProbe` returns nil when a token is mounted so health
reporting can tell the two client kinds apart. Real wire protocol
TBD — contract is not finalized.

**Regression gates:** Added R4 (`pkg/approval/regression_r4_test.go`
— approval chain Challenge.BuildJSON + SignEnvelope is byte-identical
across replays) and R5 (`pkg/accountstatus/regression_r5_test.go` —
only `active` status is writable; every other state refuses). R3 is
already locked in DueProcess. R1/R2 remain Playwright-side and
wait for the QA harness port.

**CI:** `.github/workflows/ci.yml` runs vet + test + static build
for ccash, Fineract-sidecar, and Fineract-setup on every push and PR.

**Documentation:** CLAUDE.md §12 "Still deferred" corrected —
`/receive/webhook` and M1 caller are both wired (env-gated on
`CYBERTELLER_URL` + `FINREACT_BUNDLE_ROOT_PUBKEY`); template packs
at `DueProcess/domains/ccash/{accounts,portal,providers,risk,
welcome}/*.yaml` are all on disk.

---

## Unreleased — six-role permission model

The permission model has been restructured from a four-role set
(admin / operator / viewer / auditor) to a six-role model split
explicitly across an **admin side** (the MSB staff running the
pearl) and a **client side** (the account owner and their
delegates). Auditors straddle both sides — they read everything
and write nothing. See CLAUDE.md §8 for the full table and
`pkg/users/users.go` for the predicates.

**The six roles:**

1. **Admin** — full access, including user management and
   fundamental settings (fee schedule, pricing, pearl-wide policy).
2. **Collaborator** — normal admin-side flow: initiate / draft /
   approve transactions, manage contacts and wallets. Cannot manage
   users; cannot change fundamental settings. MSB day-to-day staff
   role.
3. **Auditor** — read-only across both sides. Audit trail, approval
   history, contacts, wallets, transactions, settled activity. No
   mutations at all.
4. **Client** — the account owner. One or multiple real people may
   hold this role per the ownership contract. Initiate / draft /
   approve their own activity.
5. **Client Assistant** — can draft transactions on the client's
   behalf. Every draft they create waits for the client's explicit
   confirmation before it enters the approval gate. Cannot approve,
   cannot settle.
6. **Client View-Only** — read-only on the client side. The role
   held by external accountants, bookkeepers, and auditors-of-
   record. No action buttons anywhere in the UI.

**What changed in code:**

- **`pkg/users`** — the `RoleID` constant set is `RoleAdmin`,
  `RoleCollaborator`, `RoleAuditor`, `RoleClient`, `RoleClient-
  Assistant`, `RoleClientViewOnly`. `AllRoles()` returns the six-role
  set in display order with each row carrying a `Side` (admin /
  client / both).

- **New capability predicates** on `*User`: `CanWrite`, `CanDraft`,
  `CanApprove`, `CanManageUsers`, `CanChangeFundamentalSettings`,
  `IsAdminSide`, `IsClientSide`, plus `PrimaryRole()` and
  `BootView()`. Handlers should gate on these predicates instead
  of matching on `RoleID` directly so a future role mix (e.g. a
  user with both `client` and `auditor`) keeps working without a
  handler edit. `CanWrite` now permits `admin ∪ collaborator ∪
  client` with the onboarding gate still mandatory on top.

- **Boot-view dispatcher** (`handlers_get.go:serveDashboard`) now
  routes on `User.BootView()` which returns one of
  `admin_dashboard` / `collaborator_dashboard` / `auditor_dashboard`
  / `client_dashboard`. The three client-side roles share one
  template (`templates/client_dashboard.html`) with server-side
  conditionals on `CanDraft` / `CanApprove` /
  `IsClientAssistant` / `IsClientViewOnly` passed through the
  render data — the Client sees Send / Receive / Add-money /
  Request, the Assistant sees Draft-only buttons, the View-Only
  user sees no action row plus a read-only banner.

- **`templates/client_dashboard.html`** is the new client-side
  dashboard. It reuses every design token and component from the
  existing admin-side dashboards so the visual identity stays
  consistent across the two consoles. The read-only banner, the
  assistant-drafts card, and the role-aware empty state are the
  three bits that are unique to the client side.

- **`pkg/graincontext/permissions.go`** — seven permission bits
  (`admin`, `collaborator`, `read`, `client`, `auditor`,
  `client_assistant`, `client_view_only`) and six named roles in
  the share dialog. Each client-side role has its own dedicated
  permission bit so `rolesFromBits` maps them unambiguously.

- **`server.go:rolesFromBits`** maps all seven Sandstorm permission
  bits to the corresponding internal `RoleID` on first contact.

**Tests:** `pkg/users/users_test.go` has
`TestSixRoleCapabilityMatrix` pinning the capability matrix for
every role × predicate, `TestSixRolePendingOnboardingNeverWrites`
covering the onboarding gate for all six roles,
`TestPrimaryRolePriority` for multi-role collapse, and
`TestAllRolesCoversAllConstants` reflection guard. Render tests
verify `client_dashboard_content` for all three client-side role
flag combinations (Client / Assistant / View-Only).

## In flight — incoming-payment protocol (ccash ↔ cyberteller ↔ AITX ↔ finreact)

Spec-complete and partially implemented on the ccash side. Tracked in
`docs/incoming-payment-protocol.md` (the four-party M1–M7 authoritative
spec). None of this is shipped — the HTTP webhook endpoint is not wired
into the router yet and the M1 caller in receive-wizard step 4 still
redirects to the standard approval page.

**What has landed on the ccash side:**

- **`pkg/payintent`** (new, unwired) — shared wire-type contract for the
  protocol. `types.go` mirrors every message struct and enum (Create-
  InvoiceRequest/Response, PaymentWebhookEvent, ScreenDepositRequest/
  Response, ScreeningDecision, ApproverHeaders, the `StateXxx` /
  `EventXxx` / `DecisionXxx` / `ChainXxx` constant families). `webhook.go`
  is a `Handler` that verifies v2 envelopes, dispatches on event type
  (`payment_detected`, `settlement_complete`, `screening_held`,
  `screening_rejected`, `refund_initiated`), updates
  `Transaction.IncomingPaymentMeta`, and manages the nonce replay cache.
  Unit tests in `webhook_test.go` + `types_test.go` cover every branch.
  **Not yet routed** — no handler in `handlers_post.go` calls it.
- **`pkg/transactions.IncomingPaymentMeta`** — 14-field struct capturing
  incoming-payment screening sub-state (invoice id, pay address, chain,
  token, tx hash, sender address, screening ref, screening state,
  decision, reason, risk level, Fineract credit/nostro command ids,
  timestamps). Nine screening-state constants from `address_pending`
  through `nostro_moved`.
- **`pkg/Solana` v2 primitives** — `PayloadContextV2` struct (trust
  bundle digest, install id, app hash, license entry id),
  `CanonicalPayloadV2`, `EnvelopeV2` type, `VerifyEnvelopeV2`,
  `SignEnvelopeV2`. Byte-aligned with the sidecar and cyberteller so
  the three implementations sign the same bytes.
- **`pkg/finreact` command-param routing** — `RoutePolicy` grew a
  `CommandParam` field so route matching can distinguish
  `?command=deposit` from `?command=holdAmount` on the same path.
  `preflight.go` runs a two-pass resolver (explicit command param
  wins over catch-all). Mirrors the sidecar's `ResolveRequest` exactly.

**Remaining work on the ccash side:**

- Wire `/receive/webhook` into the POST router and hand off to
  `payintent.Handler.Process`.
- Implement the M1 (CreateInvoice) call in receive-wizard step 4: POST
  to cyberteller with a v2-signed envelope, store the returned invoice
  id + pay address + expiry onto the in-progress transaction.
- Build the M6 four-eyes UI in transaction-detail: capture the
  approver's wallet co-signature and forward to cyberteller as
  `ApproverHeaders`.
- Add a `ScreeningState → Transaction.Status` mapping pass so the
  primary status advances as the sub-state progresses.
- Register cyberteller service signers in the trust bundle and add
  the M5/M6 resource policies for gate enforcement.
- Cross-language parity test for the v2 canonical payload (Go vs Java),
  a restart-durability test for `IncomingPaymentMeta`, and an end-to-end
  integration test that exercises every state transition.

See `docs/FINAL_E2E_PRODUCT_PLAN.md` and
`docs/TEAM_B_AUTONOMOUS_PROMPT.md` for the coordinated work stream.

## Unreleased — add-money wizard, devnet currencies, role-tailored boot

Two commits past the v0.5.0 tag, not yet cut as 0.5.1.

**Add-money wizard (commit `45566f1`).** New three-step self-receive
flow that lets the operator credit the workspace's own wallets without
going through the regular receive wizard. Step 1 picks amount +
currency, step 2 picks funding method + purpose, step 3 reviews and
confirms. Templates at `templates/add_money_step{1,2,3}.html`.
Backend: a new `GrainContext.add_money` operation, self-contact
support via `contacts.Self()`, and a self-addressed transaction
(`Type: TypeReceive`, `ContactID` = self-contact id) that lands in
`awaiting_approval` like every other receive. Dashboard quick-action
button added.

**Devnet currencies (same commit).** `pkg/currency` picked up devSOL
(precision 9), devETH (precision 6), and devUSDC (precision 2)
alongside the nine production currencies. `Currency.IsDev()` and
`Currency.MainnetEquivalent()` helpers map a devnet coin to its
mainnet sibling for display. FX rates pegged to the mainnet
equivalents. Dashed-border CSS badges distinguish dev currencies from
production ones in the UI.

**Role-tailored boot views + legacy purge (commit `1ac59ed`).** The
first view an operator sees after unlock is now role-specific — admins
land on the workspace dashboard, operators on the send/receive hub,
viewers on a read-only summary. Backward-compat scaffolding from the
pre-Solana era was deleted outright: no `Legacy` fields, no
`SkipOnboarding` bypass, no `// removed` comments left behind.

## 0.5.0 — GrainContext alignment with openclaw + instaco

This pass lands the cross-pearl integration surface that lets ccash
receive transfer intents from instaco and publish status updates
that any sibling pearl (notably openclaw's agent runtime) can poll.
Everything in this pass is implemented in Go in-process today;
the Cap'n Proto wire attachment to fd3 is stubbed pending the
upstream openclaw-bridge bindings work.

### The integration contract

Rather than invent a ccash-specific cross-pearl schema, v0.5.0 adopts
**openclaw's universal `GrainContext` interface** verbatim. The same
Cap'n Proto schema, the same Go type shapes, the same Adapter
interface. openclaw's design decision — `MELUSINA_OPENCLAW_INTEGRATION_FINAL.md`
and `openclaw-main/capnp/graincontext.capnp:1-36` — is that every
Melusina-ecosystem pearl implements the same describe/invoke/poll
surface. ccash borrowing this shape means:

- **openclaw's runtime drives ccash with zero per-pearl code.**
  Its agents hold a Cap'n Proto `GrainContext` capability and
  dispatch against the catalog ccash publishes in `describe()`.
- **instaco's future Phase 4 backend pushes transfer intents via
  the same capability type.** No instaco↔ccash schema.
- **Tests use the same mock shape across all three grains.** A
  scenario test can construct a real ccash adapter in-process and
  treat it exactly like openclaw's `StaticAdapter`.

### What landed

**`capnp/graincontext.capnp`** — byte-for-byte copy of
`openclaw-main/capnp/graincontext.capnp`. File ID
`@0xb7c5e2f1a9d30468` is preserved so wire identifiers match. A
`capnp/README.md` explains the sync policy: when openclaw updates
its schema, diff and port; field IDs are append-only so the merge
is always additive.

**`pkg/graincontext`** is the new Go package that mirrors the
schema and implements the interface. Key pieces:

- **`types.go`** — Go mirror of every struct and enum in the
  `.capnp` file, aligned field-for-field with
  `openclaw-bridge/types.go`. Includes `AccessLevel`,
  `EffectClass`, `ApprovalMode`, `SideEffectKind`, `CostHint`,
  `Severity`, `EventKind`, `PermissionDef`, `RoleDef`,
  `OperationDescription`, `GrainDescription`, `ConnectedGrain`,
  `InvokeRequest`/`ToolCall`, `InvokeResult`/`ToolResult`,
  `GrainEvent`, `PollResult`, and the `Adapter` interface itself.
  Error sentinels `ErrInvalidOperation`, `ErrPermissionDenied`,
  `ErrGrainNotFound` match openclaw's contract.

- **`permissions.go`** — ccash's Sandstorm-native permission
  vocabulary: `admin` (index 0), `operator` (index 1), `viewer`
  (index 2). `CcashAvailableRoles` declares the three named roles
  with their parallel bitsets. `GrantedPermissionsForRole` looks
  up a role title and returns a defensive copy of its bitset.

- **`adapter.go`** — `CcashAdapter`, the concrete Adapter
  implementation. Wraps the existing ccash stores
  (transactions, contacts, wallets, audit). Built via
  `NewCcashAdapter(CcashAdapterConfig)` with per-role scoping:
  the constructor filters the operation catalog to only those
  whose `RequiredPermissions` are satisfied by the granted
  bitset, then describe() returns the filtered view and
  invoke() re-validates per-call as belt-and-braces against
  stale caches. Events live in a 1,024-entry ring buffer with
  cursor-based Poll semantics identical to openclaw's
  `StaticAdapter.Poll`.

- **`operations.go`** — the 9-operation catalog. Each op has a
  full `OperationDescription` with declared
  `RequiredPermissions`, `EffectClass`, `ApprovalMode`,
  `UserPrompts`, `Idempotent`, `CostHint`, and JSON Schema
  strings for input and output:
  1. `start_transfer` — primary integration point. Creates a
     transaction in `awaiting_approval`. Used by instaco to
     push a transfer intent.
  2. `approve_transfer` — transitions to `approved` AND mints
     `SettlementInstructions` in one atomic step.
     **Idempotent**: retrying returns the same settlement
     instead of re-minting.
  3. `cancel_transfer` — idempotent cancel from any non-terminal
     state.
  4. `settle_transfer` — transitions approved → settled. Called
     by the sibling pearl that actually moves the funds.
  5. `get_transfer_status` — read one transaction, including
     settlement block if present.
  6. `list_pending` — list transactions awaiting approval or
     approved-but-unsettled.
  7. `list_contacts` — identity-only contact search. Returns
     only the v0.4.5 identity fields, never anything that looks
     like a payment instrument.
  8. `get_contact` — read one contact.
  9. `list_wallets` — list the workspace's own wallets, with
     optional currency filter. Used by agents to pick a funding
     source before calling start_transfer.

  Every handler:
  - decodes its params from the JSON map (using `UnmarshalParams`
    or inline field extraction)
  - validates required fields and returns a descriptive error
  - calls into the existing ccash store layer — NO duplicated
    business logic
  - emits `GrainEvent`s via `a.EmitEvent()` for every state
    change, carrying the caller's `callID` as `correlationKey`
  - returns a JSON-serialisable result body that matches the
    declared `OutputSchemaJSON`

- **`adapter_test.go`** — full test suite matching openclaw's
  `adapter_static_test.go` pattern. 17 tests covering:
  - Describe surfaces all ops for Operator
  - Describe hides write ops from Viewer
  - Permission vocabulary stability
  - start_transfer happy path
  - start_transfer rejects unknown currency / missing contact
  - approve_transfer mints SEPA settlement instructions
  - approve_transfer is idempotent on retry (same reference)
  - cancel from awaiting_approval
  - settle rejects unapproved transactions
  - settle happy path
  - list_pending returns multiple created transactions
  - list_contacts with search query
  - get_contact returns identity only (explicit guard test that
    NO forbidden fields — `iban`, `account_number`, `routing`,
    `card_number`, `wallet_address` — appear in the response)
  - unknown operation returns `ErrInvalidOperation`
  - Viewer cannot start_transfer (permission denied)
  - Poll emits `itemCreated` + `approvalRequired` on start
  - Poll emits `statusChanged` on approve
  - Poll events carry the correlation key from the original call
  - Meta strips the full description per openclaw's convention

### Event emission in existing HTML handlers

The HTTP flow and the GrainContext flow share the same underlying
stores, and both must produce events so agents see the state change
regardless of who initiated it. v0.5.0 adds a small helper —
`CcashWebSessionServer.emitGrainEvent(kind, summary, payload)` — and
sprinkles it into every state-changing HTTP handler:

- `postApproveTransaction` emits `statusChanged` with the
  minted `SettlementInstructions`
- `postCancelTransaction` emits `statusChanged` with `cancelled`
- `postSettleTransaction` emits `statusChanged` with `settled`
- `postSendSubmit` emits `itemCreated` + `approvalRequired`
  after the send wizard creates a new transaction
- `postReceiveSubmit` emits the same pair per created receive
- `postAttachInvoice` emits `documentChanged` with the
  attachment id, filename, and content type

The helper writes after the state change is persisted (audit row
+ store write already succeeded) and logs but does not propagate
marshal errors — a stale GrainContext poll is never allowed to
break a human operator's HTTP flow.

### Server wiring

`CcashViewServer` now has a `graincontext *graincontext.CcashAdapter`
field. It's constructed once at startup in `main.go`:

```go
gcAdapter, err := graincontext.NewCcashAdapter(graincontext.CcashAdapterConfig{
    GrainID:          "ccash-pearl",
    Title:            "ccash workspace",
    GrantedRoleTitle: "Operator",
    ActorID:          ids.ID("agent_sibling_grain"),
    Transactions:     txnStore,
    Contacts:         contactStore,
    Wallets:          walletStore,
    Audit:            auditLog,
})
```

The synthetic `actor_id` on audit rows written by adapter-driven
mutations is `agent_sibling_grain` so they're distinguishable from
human-operator-driven mutations in the audit log. A production
multi-tenant build would mint one actor_id per connected sibling
pearl via the Grapple handshake.

### Integration documentation

`docs/INSTACO_INTEGRATION.md` (new, ~650 lines) walks the full
round-trip end-to-end:

- The picture (ASCII diagram showing instaco + openclaw + ccash)
- Why one universal interface beats per-pearl schemas
- ccash's operation catalog in a single reference table
- Lifecycle mapping between instaco's draft-centric states and
  ccash's awaiting_approval/approved/settled states
- A step-by-step walkthrough of a full transfer: bot draft →
  user approval → `start_transfer` → ccash approval gate →
  settlement instructions → instaco poll sees `statusChanged` →
  ledger update
- The mock pattern: how openclaw's `bridge.Adapter` interface maps
  1:1 onto ccash's `graincontext.Adapter`, so cross-pearl scenario
  tests can wire real ccash + fake instaco in one process
- Deferred items: Cap'n Proto Go bindings, fd3 attachment,
  callback capabilities, Grapple UI for ccash to claim sibling
  capabilities
- Invariants that must stay true: no stored payment instruments,
  every transaction through the approval gate, audit-before-persist,
  double permission checks, correlationKey threading through events

### CI

`make ci` clean: go vet, go test -count=1 across all packages,
static linux/amd64 build, launcher permission check. Binary size
up to 8.6 MB from 8.5 MB (the adapter package is ~1,600 LoC).

### What's explicitly NOT in this pass

- **No Cap'n Proto Go bindings generated** from
  `graincontext.capnp`. openclaw itself is at the same
  "bindings pending" stage per its sidecar README. The ccash
  `pkg/graincontext` types are hand-written mirrors that match
  the schema field-for-field. When bindings land upstream, the
  Go mirror becomes a thin translation layer.
- **No fd3 wire attachment** for an incoming `GrainContext`
  capability. ccash's current `MainView` slot serves the HTML UI.
  A future pass exposes GrainContext via a sibling `UiView` or
  via a Grapple-offered capability.
- **No callback capabilities** — ccash does not hold a capability
  on instaco to push status updates. Status flows via `poll()`
  from instaco's side, which keeps the v0.5.0 surface symmetric
  with openclaw's universal interface.
- **No Grapple claim UI** for ccash to request capabilities from
  sibling grains. v0.5.0 is sink-only: ccash receives invokes,
  instaco polls.

## 0.4.5 — contact enrichment + invoice attachments

Two features. First, `pkg/contacts.Contact` grew a reasonable set of
identity fields split cleanly between persons and entities. Second,
every transaction can now carry uploaded invoice documents stored as
real files on disk under `{DATA_DIR}/invoices/{att_id}`.

### Contact enrichment

`pkg/contacts.Contact` picked up the following fields. None of them
are payment instruments — the architectural guard test in
`pkg/contacts/contacts_test.go` still passes untouched.

**Universal (both types):**
- `Phone` — free-form, max 32 chars, rendered as a `tel:` link on the
  detail page.
- `Address` — unified — shown as "Home address" for persons and
  "Registered address" for entities via CSS `:has()` conditionals.
- `Website` — entity only in the form, but the column is universal
  on the struct.
- `TaxID` — labelled "Tax ID / SSN" for persons and "Tax
  identification number" for entities.
- `Notes` — 1 KB free-form operator memo, rendered as
  `white-space:pre-wrap` on the detail page, invisible to the
  counterparty.

**Person-only:**
- `DateOfBirth *time.Time` — HTML5 `<input type="date">`, optional,
  but flagged as "required downstream if you ever enable KYC via a
  sibling pearl" in the form helper text.

**Entity-only:**
- `TradingName` — DBA / "trading as" name. Rendered in italics under
  the legal name on the detail page.
- `RegistrationNumber`, `VATNumber` — already existed, now
  promoted out of the generic identity block into a dedicated
  "Entity details" card.
- `LEI` — ISO 17442 Legal Entity Identifier. 20-character
  uppercase, validated server-side. Form helper links out to
  `gleif.org` for lookups.

**Form UX:**
- A single `contact_new.html` template now drives both `/contacts/new`
  (create mode) and `/contacts/{id}/edit` (edit mode). The `Mode`
  data key + the `Action` + `Title` + `Submit` labels differ; every
  field is shared.
- CSS `:has()` conditionals on `.contact-form` show/hide
  person-only vs entity-only sections based on which radio is
  checked. Zero JS.
- Edit mode pre-fills every field from the existing record.
- `parseContactForm` in `handlers_post.go` is shared between
  `postNewContact` and `postEditContact` — identical validation
  (required name, email shape via `net/mail.ParseAddress`, ISO-3
  country, 20-char LEI, length caps on phone/address/notes).
- Every field round-trips through the inline-error re-render
  pattern — no silent bounces.
- New GET/POST `/contacts/{id}/edit` routes; Edit pencil-icon
  button on the contact detail app bar (write-gated).
- Quick-actions row on contact detail ("Send to them" / "Request
  from them") when `CanWrite`.

**Seed data** gained realistic values for the new fields: Alice has
a San Francisco phone number and a date of birth; Global Tech Corp
has an LEI, a VAT number, a registration number, and a trading
name; Acme Logistics has an LEI and a net-30 note; etc.

### Invoice attachments

**New `pkg/attachments` package** owns operator-uploaded invoice
documents that belong to a transaction. Full source is under
`pkg/attachments/attachments.go`.

Key pieces:
- `Attachment` type: `{ID, TxnID, Filename, ContentType, Size,
  UploadedBy, UploadedAt}`.
- `MemStore` — in-memory metadata index + on-disk file storage
  under `{DATA_DIR}/invoices/{att_id}`. Consistent with every
  other store in ccash: restart loses metadata, files survive
  until GC'd.
- `MaxSize` — 10 MB hard ceiling. Enforced twice: once via the
  declared `Size` field (rejected pre-open if too big) and once
  via `io.LimitReader` during the write (partial writes are
  cleaned up).
- `AllowedContentTypes` — PDF, PNG, JPEG. Anything else is
  rejected with `ErrUnsupportedType`.
- `IsImage()`, `Extension()`, `HumanSize()` helper methods for
  template rendering.
- `Save(*Attachment, io.Reader)` streams the file bytes to disk,
  never trusts the user-supplied filename for path construction
  (everything is keyed off the opaque `att_` ID), cleans up
  partial writes on error.
- `Open(id)` returns a read handle for streaming back to the
  browser.
- Full test suite in `attachments_test.go` covering save/open
  round-trip, oversized rejection by declared size, oversized
  rejection by streamed bytes (with cleanup), unsupported-type
  rejection, newest-first ordering, delete cleanup, unknown-id
  delete, malicious filename path-traversal defence, and the
  helper methods.

**Multipart upload pipeline in `handlers_post.go`:**
- `Post()` now reads `content.MimeType()` and detects
  `multipart/form-data` before the urlencoded parser runs, because
  the multipart body can be large and double-buffering would be
  wasteful.
- Multipart requests routed to `postAttachInvoice(txnID, mimeType,
  body, results)` which:
  1. Confirms the target transaction exists.
  2. Parses the multipart boundary from the content type via
     `mime.ParseMediaType`.
  3. Walks the parts looking for the first `FileName()`-bearing
     part (the form uses `<input name="invoice">`).
  4. Checks the part's Content-Type against
     `attachments.AllowedContentTypes`.
  5. Writes the audit row BEFORE any bytes touch disk (the
     audit-before-persist contract).
  6. Calls `attachments.MemStore.Save()` which streams the reader
     directly to disk — zero full-body buffering at the
     package boundary.
  7. On any failure, re-renders the transaction detail page with
     the specific error inline, never a silent bounce.
- `postDeleteAttachment(txnID, attID, form, results)` handles
  removal — audit-before-persist, txn-ID match check (so a
  mismatched URL can't delete from the wrong transaction), then
  `Store.Delete` which removes both metadata and the on-disk file.

**Download route:** `GET /attachments/{id}` via
`serveAttachmentDownload`. Serves the raw bytes with the stored
`ContentType`, adds a `Content-Disposition` response header
(on `WebSession_Response.AdditionalHeaders`, not on the Content
struct — the latter has no header support) with a sanitized
filename so the browser displays/downloads with the original name.
`sanitizeFilename` strips path separators, control chars, and
quotes.

**UI on transaction detail:**
- New `Invoices & supporting documents` section below the
  transaction details list.
- `.attachment-grid` — responsive grid of per-file cards.
  Minimum 220px wide, auto-fill columns.
- `.attachment-card` — thumbnail + metadata + action row.
  Image uploads show a lazy-loaded `<img>` thumbnail; PDFs show a
  generic `#i-file` icon with a small `PDF` extension badge in the
  corner.
- Per-card actions: Download (opens `/attachments/{id}` in a new
  tab) and Delete (write-gated, red hover). Both are JS-free
  forms.
- `.attachment-dropzone` — big dashed-gold drop target below the
  grid with a hidden native file input, a tap-to-browse label,
  and helper copy: "PDF, PNG, or JPEG · up to 10 MB · one file
  at a time". Uses `:has()` to tint green when a file is
  selected.
- Inline error banner at the top of the section when
  `UploadError` is set — the re-render path from the upload
  handler on validation failure.
- Both templates render empty state copy when zero attachments
  exist.
- Write-gated: viewers see the grid and can download, but don't
  see the dropzone or delete buttons.

### Render test fixtures

`render_test.go` was updated for every new data shape:
- `contact_new_content` tested in both create and edit modes
  with the new `Form` / `Mode` / `Action` / `Title` / `Submit`
  data keys.
- `transaction_detail_content` tested twice: once with zero
  attachments, once with a PDF + PNG pair and a populated
  `UploadError` so both the card-grid render and the error
  banner are exercised.
- New `ccash/pkg/attachments` import.

### CI

`make ci` (vet + test -count=1 + build + launcher perms) clean.
Static linux binary 8.5 MB.

## 0.4.4 — UX audit implemented end-to-end

All 91 findings from `docs/UX_AUDIT.md` landed in one pass across 8
blocks. The user's three headline pain points are fixed, plus the
full P1/P2 polish tail.

### Block 1 — in-flow entity creation

- **`+ New contact` row** at the top of send/receive step 1 pickers.
  Dashed gold border + plus tile so it reads as an action, not a
  list row. Empty-state CTA when zero contacts exist.
- **`?next=` query-param plumbing** through `serveNewContactForm`,
  `serveNewWalletForm`, `postNewContact`, `postNewWallet`. After
  success, the user is bounced back to the wizard and the new
  entity is pre-selected on the draft (contact → `Draft.ContactID`,
  wallet → `Draft.WalletID` + `FundingMethod = "wallet"`).
- **`safeNextPath`** whitelist allows only the 8 wizard step URLs;
  rejects absolute URLs, protocol-relative URLs, and anything
  else.
- Receive step 3's "no matching wallet" callout now uses
  `/wallets/new?next=/receive/3` — opens the form, then returns.

### Block 2 — recurring in wizards + management hub

- `SendDraft` + `ReceiveDraft` gained `Frequency string` +
  `RecurringEnd *time.Time` fields.
- **Recurring toggle** on send step 3 and receive step 3 — a
  switch-style `<input type="checkbox">` that uses CSS `:has()`
  to reveal a frequency radio (daily / weekly / monthly) and an
  optional end date. Zero JS, native form controls.
- `postSendSubmit` / `postReceiveSubmit` mint a fresh
  `RecurringID` (`ids.New("rec")`) and attach
  `Frequency` to the created transaction when the draft is
  recurring.
- Confirm screens (send + receive step 4) render a `Recurring ·
  monthly` row with the repeat icon.
- **`pkg/transactions.NextRunFromFrequency(last, freq)`** helper
  for the recurring hub to compute the next scheduled run.
- **New `/recurring` hub** with rich per-series rows: next-run
  date, settled count, cancelled state, recurring badge. Empty
  state has big CTAs to start a recurring send or request.
- **New `/recurring/{id}` detail page** with hero, status pill,
  full series metadata, cancel-series button (write-gated), and
  full instance history via the `activity_row` partial.
- **New `/recurring/{id}/cancel` POST route** that cancels every
  non-terminal instance in the series, one audit row per
  instance, best-effort across failures.

### Block 3 — dropdown explainers + currency button grid

- **`pkg/fees.Description`** strings rewritten with operator-
  friendly language: settlement timeline, geography, fee in
  concrete terms, and a "use this when…" hint. "SWIFT" →
  "International bank wires via the SWIFT network. Settles in
  3–5 days. Use this for cross-border transfers outside the EU…"
- **Currency `<select>` → button grid** on send step 2, receive
  step 2 (and wallet-new kept its radio-card list). New
  `.btn-grid` + `.btn-grid-scroll` CSS — horizontal scrollable
  row of large tappable cells with currency code in Inter Tight
  and full name below. Active cell flips to gold.
- **Quick-amount chips** (`.quick-amounts`) on both wizard amount
  inputs — 100 / 500 / 1,000 / 5,000. Tiny inline onclick sets
  the input value (no external JS file). The `.quick-amounts`
  CSS class was defined in v0.4.2 but never used; now it is.
- **Per-method fee preview** on send step 3. `serveSendStep` now
  computes the actual fee for the current draft amount against
  every rail and passes a `FeePreviews` map to the template, so
  the operator sees "$25.00 fee" instead of "0.5% + $15" and
  doesn't have to do mental math.
- Helper text under every form select and amount input
  explaining what the field is for.
- Note field labels changed to "Note (for your records — not sent
  to recipient)" to remove the ambiguity about who sees the note.

### Block 4 — approval discoverability

- **Dashboard pending-approval card** (`.pending-card`) — big
  gold card under the balance hero, shows `{count} transactions
  awaiting your approval`, links straight to
  `/history?filter=pending`. Only rendered when count > 0.
- **Resume-draft card** on the dashboard when the operator has
  an unfinished send/receive draft in session state — "Resume
  your unfinished wizard" with a link back to `/send`.
- **Left-border visual cue** on activity rows where
  `t.AwaitsApproval()`: `box-shadow: inset 3px 0 0 var(--gold-500)`.
- **Warning-style Pending chip** on `/history` when `PendingCount
  > 0` — amber tint, pulsing dot. Keeps the neutral style when
  zero.
- **Recurring / group badges** inline on activity row sub-lines
  with tiny repeat / group icons.

### Block 5 — empty states

- **Every list page** now has a real empty-state card with icon
  + heading + explainer + CTAs: wallets, contacts, history (per
  filter), recurring, requests (per filter), wallet detail,
  contact detail, send step 1, receive step 1, dashboard recent
  activity.
- History empty state is **filter-aware**: the `pending` filter
  shows "All caught up ✓" with no CTAs; the other filters show
  the standard send/request buttons.
- Contact detail empty state renders a pre-filled
  `Send to {name}` / `Request from {name}` action pair.
- `.empty-card-cta` and `.empty-card-icon` are new on
  `.empty-card` (defined in v0.4.2 but only used on the support
  page back then).

### Block 6 — inline errors on every form

- **Wizard POST handlers** now re-render the step via
  `serveSendStepWithError` / `serveReceiveStepWithError` instead
  of silently redirecting on validation failure. Every step has
  an `Error` data key and the template renders a
  `.form-error-banner` with an alert icon + the specific error
  copy (e.g. "That wallet is in USD but you're sending EUR. Pick
  a EUR wallet or an external rail.").
- **`/contacts/new`** — inline errors for missing name, invalid
  email (via `net/mail.ParseAddress`), and invalid country code.
  Preserves every typed value. Country is auto-uppercased.
- **`/wallets/new`** — inline errors for missing nickname,
  missing currency, audit failure, store failure. Preserves
  inputs.
- **`/settings`** — inline errors + a `?saved=1` success
  callout (moss-tinted `.info-callout-success`).

### Block 7 — two-tap confirmations

- **JS-free two-tap confirm** on approve, cancel, and mark-
  settled. Pattern: first `POST` without `confirm=1` redirects to
  `/history/{id}?confirm={action}`, the template renders the
  button in a red `confirm-btn-prompt` state saying "Tap again
  to confirm approval", a sibling "Not now" link, and a red help
  line explaining the consequence. Second tap includes
  `<input type="hidden" name="confirm" value="1">` and actually
  performs the action.
- **Viewer callout** on awaiting-approval transactions when the
  user doesn't have write permission: "This transaction is
  waiting for a workspace admin or operator to approve it. Your
  role is Viewer — you can read the details but can't approve…"

### Block 8 — P2 polish

- **Server-side email validation** via `net/mail.ParseAddress`
  on `/contacts/new`.
- **ISO-3 country `<datalist>`** with 36 common countries on the
  contact form — native autocomplete, no JS, no library.
- **`/activity/{id}` alias** for `/history/{id}` so both URLs
  work; templates all point to `/history/` for now but either is
  accepted.
- **`/requests` filter wiring** — Incoming / Outgoing / Paid /
  All chips all live, `serveRequests` reads the filter query
  param.
- **Recurring icon** in the More menu (was using the generic
  refresh icon).
- **More menu sub-copy** rewritten: "Incoming, outgoing, paid"
  for Requests; "Default currency, display name, your role" for
  Settings; etc.
- **About card** in Settings explains ccash's model in plain
  language and links to Support.
- **Contact-new form** — country input is `text-transform:uppercase`
  client-side, handler also uppercases server-side.
- **9 new SVG icons** in the sprite: `#i-pause`, `#i-play`,
  `#i-edit`, `#i-skip`, `#i-calendar`, `#i-repeat`, `#i-trash`,
  `#i-alert`, `#i-sparkle`, `#i-file`.
- **New template helpers** in `template_funcs.go`: `inIDs`,
  `dict`, `mul`, `queryEscape`, `nextHref`, `multAmount`.
- **`net/url.QueryEscape`** exposed to templates for safe
  `?next=` URL building.

### Tests

- `render_test.go` updated for the new data shapes: dashboard
  gets `PendingApprovalCount` + `HasDraft` + `Now`; send step 3
  gets `FeePreviews`; settings gets `Error` + `Saved`; wallet_new
  gets `Next` + `Error` + echoed form values; contact_new same;
  recurring_detail is tested against a seeded rent series.
- `pkg/contacts/contacts_test.go` architectural guard unchanged
  (still ensures no payment-instrument fields are re-added).
- `pkg/transactions/transactions_test.go` unchanged (state
  machine tests still pass).
- `make ci` (vet + test + build + launcher perms) clean. Static
  linux binary 8.4 MB.

### Things deferred

A few P3 items from `docs/UX_AUDIT.md` are explicitly deferred to
v0.5+: swipe gestures, pull-to-refresh, multi-axis history filter
with date range, global search, sparkline balance trend, real
audit-log viewer, theme toggle, multi-language. None are load-
bearing.

## 0.4.3 — no-stored-accounts model + approval gate + readable digits

Three architectural shifts in one pass.

**1. Money digits are finally readable.** Fraunces (the warm serif
display font) is OFF every numeric surface. Added a third typography
token, `--font-numeric: 'Inter Tight', 'Inter', system-ui, …`, set
to weight 600 with `font-variant-numeric: tabular-nums` and
`font-feature-settings: "tnum" 1, "ss01" 1`. Updated:
`.balance-card .amount`, `.amount-input .value`, `.amount-input-digits`,
`.list-item .trailing .amount`, `.accounts-list .list-item .trailing
.amount`, plus a new `.hero-amount` / `.hero-amount-md` class shared
by `transaction_detail.html`, `send_step4.html`, and
`receive_step4.html`. Fraunces stays in `--font-display` for headings
only — section titles, the dashboard greeting, the app-bar brand,
the contact-card title. The Google Fonts link in `shell.html` was
extended to load Inter Tight 400/500/600/700.

**2. Contacts are identity-only — no stored accounts, ever.**
`pkg/contacts.Contact` lost its `[]Account` slice and the entire
`AcctType` / `Direction` / `Account` family. The reasoning is in the
package doc and CLAUDE.md §1's new "no-stored-accounts rule"
section: ccash doesn't keep durable counterparty payment instruments
on file (compliance reality + PII hygiene + initiation discipline).
A Contact is now `{Type, Name, Country, Email, Website, Address,
RegistrationNumber, VATNumber, IsSelf}` and that's it. The new
`pkg/contacts/contacts_test.go::TestContactHasNoAccountFields` is an
architectural guard — it inspects the `Contact` struct via
reflection at test time and fails if anyone re-adds a field whose
name contains "account", "iban", "routing", "wallet", or "card".

**3. Every transaction goes through an approval gate.**
`pkg/transactions` got a new lifecycle:

```
initiated → awaiting_approval → approved → settled
                        ↓             ↓
                    cancelled       failed
```

`MemStore.Approve(approverID, now)` is the load-bearing call: it
transitions the transaction AND mints its `SettlementInstructions`
in the same atomic step. `SettlementInstructions` is a new type on
the package, populated only post-approval, single-use per
transaction, with a 48h expiry. The stub generator
(`Transaction.IssueSettlementInstructions`) builds deterministic
placeholder rail+address+reference based on the transaction's
funding method — POC only; v0.5+ replaces it with a sibling
Cap'n Proto Grapple call into a real settlement grain. The legacy
`pending` / `completed` / `scheduled` statuses are accepted on read
for audit-log compat but no new code path emits them.

**Wizard refactor** to match the new model:

- **Send** still 4 steps. Step 1 unchanged (recipient picker —
  every contact is now a valid send target, no per-contact filter).
  Step 2 dropped its account dropdown; it's just amount + currency
  now. Steps 3 + 4 unchanged. Submit creates a transaction in
  `awaiting_approval`.
- **Receive** still 4 steps but redesigned. Step 1 unchanged
  (sender picker). Step 2 is amount + currency (was the method
  picker — gone, the rail is decided at approval time). Step 3 is
  the **destination wallet picker** (your wallet that will hold the
  funds when settled — only wallets matching the requested currency
  are shown, and an info-callout pushes the user to open one if
  none match). Step 4 confirms and submits. Each sender becomes
  one `awaiting_approval` receive in a shared multi-payer group.

**Approval / cancel / settle actions** on the transaction-detail
page. Three new POST routes: `/history/{id}/approve`,
`/history/{id}/cancel`, `/history/{id}/settle`. All audit-write-
before-persist, all gated on `CanWrite`. The approve button is
the prominent primary CTA on any awaiting_approval transaction;
mark-settled appears on approved transactions; cancel is available
in any non-terminal state. Settlement instructions render in a
gold-tinted card directly under the approval gate, with rail,
reference, address (in the new monospace numeric font), memo,
issue time, and 48h expiry.

**Status pill copy** updated everywhere — `awaiting_approval` →
"awaiting approval", `approved` → "approved · awaiting settlement",
`settled` → "settled", `cancelled` → "cancelled". The legacy
"cleared" / "review" labels are mapped over for backwards compat
in `template_funcs.go::tmplStatusPillClass` and `tmplStatusLabel`.

**Seed data rebuilt** (`pkg/seed`) without contact accounts.
Mixed lifecycle: 2 awaiting_approval (so the dashboard has
something to demo the approval gate on), 1 initiated draft, 1
approved-but-not-yet-settled (shows the settlement instructions
card on first click), 1 cancelled, 1 failed, ~17 settled
historical transactions covering all 9 currencies, plus a
recurring rent series and a multi-payer group.

**Tests:** `pkg/transactions` got a full new test suite for the
state machine — happy path, terminal-rejection, approval-issues-
settlement, cancel-from-initiated, IsPending / AwaitsApproval
helpers. `pkg/contacts` got the architectural guard test. All
existing render tests still pass. `make ci` (vet + test + build)
clean. Static linux binary 8.2 MB.

**CLAUDE.md updates:** §1 has the "no-stored-accounts rule" as a
load-bearing subsection. §6 typography rewritten around the
three-family split (display / numeric / body). §7 domain code blocks
updated to drop `Account` and add `SettlementInstructions`. §7 has
a new "Transaction lifecycle" ASCII diagram. §8 permission table
fixed (operator can approve transactions). §10 has new "never do"
entries about stored accounts, the approval gate, settlement
reuse, and the Fraunces-on-numbers ban.

## 0.4.2 — support page implemented end-to-end

The `support.md` spec is now real Go code and a real page. No stubs,
no openclaw, no LLM, no chat, no outbound HTTP. Pure local FAQ +
contact form, recorded to memory and the audit log only.

- **`pkg/support`** is the new package: `SupportMessage`, `FAQEntry`,
  `ContactInfo`, `MemStore` (concurrency-safe, newest-first ordering,
  defence-in-depth length caps at 80/2000 chars), and a hand-curated
  `DefaultFAQ()` of 9 entries covering send/receive, contacts, audit,
  pearl restart, roles, compliance scope, the no-chat decision, and
  Sandstorm sharing. Full unit-test coverage in `support_test.go`.
- **GET `/support`** wired in `handlers_get.go` as `serveSupport`.
  Admins see every workspace message; everyone else sees their own.
  Capped at 20 newest. Re-renderable from POST with inline error +
  preserved form input — no validation-bounce redirects, no lost text.
- **POST `/support`** wired in `handlers_post.go` as `postSupport`.
  Audit-write-BEFORE-persist, fail-closed: if the audit row can't be
  written, the message is rejected and the form re-renders with an
  inline error. Validation distinguishes empty-subject vs empty-body
  vs both, with copy that says exactly which field is missing.
- **`templates/support.html`** is the new page template: contact card
  at the top (mailto: + tel: links), FAQ accordion built on native
  `<details>`/`<summary>` (zero JS, keyboard-accessible by default),
  contact form gated on `CanWrite()`, and a "your messages" list with
  empty-card fallback copy.
- **CSS additions** in `static/css/components.css`: `.contact-card`
  + sub-elements, `.faq-accordion` + `.faq-row` + open-state chevron
  rotation, `.support-form` textarea styling, `.info-callout-danger`
  variant for the inline-error slot, `.empty-card` for the no-messages
  fallback, and a 2-line clamp on `.support-msg .body .sub`.
- **Icons added** to `templates/_partials/icons.html`: `#i-help`,
  `#i-mail`. Both stroke-only, currentColor.
- **More menu** (`templates/more.html`) gains a Support row above
  Settings.
- **Render tests** in `render_test.go` cover the empty/populated/
  inline-error/viewer-no-form variants, plus a round-trip test that
  asserts the form body survives a validation bounce, plus a
  rendered-FAQ test that asserts every default question shows up.
  HTML-escaping handled via `html.UnescapeString` so the matches
  aren't masked by `&#39;`.
- **Wired into the bootstrap path** (`main.go`, `server.go`): a new
  `*support.MemStore` field on `CcashViewServer`, allocated in `run()`
  alongside the other stores. No persistence beyond the in-memory
  store + the audit log on disk — matches the v0.4 substrate story.

Build: `go vet ./...` clean, `go test ./... -count=1` all green
(ccash, pkg/fees, pkg/money, pkg/support, pkg/transactions, pkg/users).
Static linux binary: 11.9 MB.

## 0.4.1 — v0.4 reversal: chat and openclaw removed

A previous v0.4 spec pass explored a chat-with-personas surface
fronting an openclaw HTTP bridge. **That entire direction has been
removed.** ccash is back to a proof-of-concept, single-pearl-per-client
Sandstorm app that talks to nothing but itself. Sibling-pearl
integration is a v0.5+ aspiration and, when it ships, will go through
**raw Cap'n Proto Grapple capabilities only** — never HTTP, never a
bridge, never a sidecar.

What changed in this pass (no Go code touched):

- **MONTANADAO.md** rewritten end-to-end. Removes openclaw, removes
  the persona cast (Clara / Spencer / John / Mira / Theo / Rashid),
  re-frames the constellation as the POC reality (one pearl per
  client) plus a future v0.5+ aspiration. Locked decisions documented
  in §6. Names ai-lagoon as the reference pattern for raw Cap'n Proto
  WebSession.
- **CLAUDE.md** unified. Tab bar locked at **5 items** (Home /
  Wallets / Send / Activity / More) — no 6th Chat tab. Persistence
  claim corrected: `pearl-crypto-journal` is **not** in `go.mod` and
  is a v0.5+ target. `pkg/` tree updated to match the actual
  v0.3 packages (no `customers/`, no `accounts/`). Page list
  extended to 16 routes including the new `/support`.
- **`docs/pages/`** cleaned up. Three chat spec files
  (`chat-list.md`, `chat-thread.md`, `chat-operations-catalog.md`)
  deleted entirely. `_components.md` §10 (the v0.4 chat CSS surface)
  replaced with a small Support component section. `_state-machines.md`
  §6 (the v0.4 chat thread state machine) cut. Every page MD's
  v0.4 future-hooks section was replaced with the locked
  v0.5+-via-Cap'n-Proto-only language. The 6-tab-bar references in
  every visual-reference section now point to the standard
  `design/preview.html` 5-item bar.
- **`docs/pages/support.md`** is the new page spec for `/support` —
  a tiny local FAQ + contact form. **Not a chat. Not powered by an
  LLM. Not powered by openclaw.** Lives behind the More tab. Only
  surviving piece of the v0.4 exploration.
- **`design/preview_v04.html`** deleted. The locked
  `design/preview.html` is the only visual ground truth.

## 0.3.0 — polished MVP, post-audit hardening

- Stable identity at the pearl boundary (UserInfo.IdentityId hex, not handle)
- Per-session mutex on wizard drafts (no torn writes on concurrent POSTs)
- 3 permission bits → 3 roles in GetViewInfo, role-bit mapping locked
- All POST routes gated on `User.CanWrite()`
- Audit-write-BEFORE-persist contract enforced; audit log re-hydrated on
  startup so a restart isn't a clean slate
- pkg/money rewritten on math/big.Rat — no float64 in any money path
- pkg/transactions: state-machine validation in Create + dedicated Seed bypass
- pkg/fees rewritten via pkg/money — no float64 in fee math
- Send wizard step 3: phantom hidden `wallet_id` removed, single radio
  carries `wallet:<id>` value
- Wizard chrome conflict fixed: shell skips bottom tab bar when Page=send|receive
- /wallets/new and /contacts/new forms wired (GET + POST)
- History filter chips wired via `?filter=sent|received|pending`
- Settings actually persists `default_currency`
- 44px tap targets, focus-visible rings on inputs/selects/textareas
- New CSS classes: `.avatar-initials`, `.radio-mark`, `.form-row/input/label`,
  `.info-callout`
- Test coverage: pkg/money, pkg/fees, pkg/transactions, pkg/users, plus a
  whole-template render test that asserts wizards do not contain a tab bar
  and send_step3 has no phantom wallet_id

## 0.2.0 — rich operator workspace

- Domain mirroring INSTACO_REMIT_FRONTEND: wallets / contacts / transactions
  with sub-account model, recurring + multi-payer groups
- 9 currencies (USD, EUR, GBP, JPY, INR, USDT, USDC, BTC, ETH)
- 9 funding methods with fee schedule (wallet, bank, ACH, SEPA, SWIFT, card,
  crypto, mobile, Western Union)
- 12 mobile-first pages: dashboard, wallets, wallet detail, contacts, contact
  detail, send (4 steps), receive (4 steps), history, transaction detail,
  recurring, requests, more, settings
- Bottom tab bar: Home / Wallets / Send / Activity / More
- Rich seed data: 8 wallets, 8 contacts, ~22 transactions

## 0.1.0 — initial scaffold

- Sandstorm pearl skeleton (raw Cap'n Proto WebSession)
- Locked design system (beige on soft brown, Fraunces + Inter)
- Dashboard, send-money wizard step (mock data)
