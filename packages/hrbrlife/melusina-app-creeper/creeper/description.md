# melusina-app-creeper — OSINT Consumer Grain

Identity: **melusina-app-creeper** (Sandstorm consumer grain SPK).
AppId: `jkt51nyrcp2wk6n4atseexddjv9wnyrzu3ypmdp2qzk6d9n2q4eh`
Version: v1 (`0.1.0`, initial split from telescreen).
Stack: Go grain (Cap'n Proto UiView under `-tags=melusina`, FD3), no
bundled sidecar.

## PSP Role

This grain is the **consumer-grain front for OSINT** in the Melusina
PSP stack. It exposes a `CreeperService` Powerbox capability that
foreign Sandstorm grains (notably DueProcess case routing and popaye
onboarding flows) claim to drive the live `creeper-sidecar` over a
cap-routed HTTPS transport. It closes the missing wiring between the
sidecar (live on cca-sh-vm) and the grains that need web search,
page scrape, handle lookup, and contact validation during PSP
lifecycle steps 2 (sanctions screening, escalations) and 4
(DueProcess case enrichment). Without this grain, the sidecar has
no in-Sandstorm consumer surface.

**Closes governance task #76** — `close-creeper-wiring`. The
consumer-grain piece (this SPK) is the link that was missing; the
sidecar already runs as a systemd unit at `creeper.sidecar.host`.

## Architecture

- Native Cap'n Proto UiView grain (no `sandstorm-http-bridge`).
- Single Go binary at `cmd/grain/`, foregrounded via `start.sh`.
- `grain/creeper_service.go` implements `CreeperService_Server` with
  the four PSP verbs: `searchWeb`, `scrapePage`, `lookupHandle`,
  `validateContact` (plus `getResult` for async retrieval).
- `grain/creeper_subcap.go` issues team-share sub-caps for
  inside-install bytes-in / bytes-out delegation.
- `grain/sidecar_client.go` — cap-routed HTTP-out to
  `https://creeper.sidecar.host`; **no `X-API-Key`, no
  `X-Install-Mint` headers** (mTLS-CN is the only tenant signal,
  per PLAN §4.2 / Inv 1).
- `grain/httpout_*.go` — slim port of `melusina-http-component`
  (cap-routed transport; never stdlib `net/http` to non-loopback).
- `grain/proof_builder.go` — ed25519 grain key at
  `/var/melusina-app-creeper/grain.ed25519.key`, schema
  `creeper-proof-v1`.
- Persistent stores at `/var/melusina-app-creeper/`:
  `core.db` (SQLite + grain-crypto-journal), `claims/`, `caps/`.

## Deps + Exports

**Depends on:**
- `creeper-sidecar` (systemd LXC at `https://creeper.sidecar.host`)
  via Powerbox HTTP-out cap. Endpoints: `POST /search/web`,
  `POST /scrape/page`, `POST /handle/lookup`, `POST /validate`,
  `GET /admin/status`.

**Exports:**
- `CreeperService` Powerbox capability (capnp typeID
  `0xbf27299ef0d0be0b`) — outbound cap that foreign Sandstorm grains
  claim via Powerbox to drive OSINT primitives.
- `CreeperSubCap` — team-share sub-cap for inside-install
  delegation.

## Governance

- Multi-agent governance, Hard Truths, tick cadence, chain of
  command, and v2 agentchat protocol: see
  `/home/user/Desktop/agentchat/CLAUDE.md`.
- Full Hard Truths 1–13 and crew rules: see
  `/home/user/Desktop/agentchat/CHARTER.md`.

## pearl Onboarding — TODO (task #94)

Not yet pearl-onboarded. Needs (a) master-NFT-mint, (b) Squads
vault, (c) signed on-chain `ReleaseEntry` verified against quorum
before it can publish under the pearl-only `make publish` model.
Until then, this app cannot ship through the migrated static_store
catalog. Tracked org-wide as task #94.

## Pre-Publish TODO (from README)

- Regenerate capnp `@id`s for `CreeperService` + `CreeperSubCap`
  (placeholders today).
- Wire `melusina-solana approve-local-sidecar --sidecar-id creeper`
  cascade (deployer Agent D scope, PLAN §5.3).
- pearl onboarding (above).

## Hard Truths (Apply Here Verbatim)

- **HT5 — Announce destructive changes in chat first.** Schema
  changes to `core.db`, capnp `@id` regeneration that breaks
  in-flight claims, deletion of `claim_store` / `cap_token_store`
  rows, history rewrites — all named with paths in `/msg` to Riker
  before the keystroke.
- **HT12 — No Sandstorm bypass.** This SPK ships through the
  Sandstorm admin UI: login as admin → Admin panel → App sources →
  Update / Refresh → install from market. No
  `loginDevAccountFast`, no direct Mongo `packages` inserts, no JS
  bundle hot-patches, no `Meteor.users.isAdmin` flips to make a
  consumer-grain claim succeed. Local testing uses `sandstorm
  dev-shell` from `/home/user/Desktop/Melusina/sandstorm`.
- **HT13 — Offline wallet signing.** Any `ReleaseEntry` mint for
  this grain (pearl onboarding) routes through the Squads /
  offline-wallet path; no hardcoded keypairs, no devnet hot-key
  fallbacks.

## App-Specific NOT-To-Do

- Do NOT leak PII into OSINT queries. The grain must scrub /
  pseudonymize before forwarding to the sidecar; persons under
  DueProcess review must surface only stable case IDs to upstream
  search engines, never raw KYC fields.
- Do NOT bypass the authz path. Every verb is fail-closed: if the
  Powerbox cap is not held, return `Status_failed` (CLAUDE.md
  Inv 5). Do not add a "test mode" that skips the cap check.
- Do NOT fabricate search results. No canned / stub / fixture
  responses returned through `CreeperService` — every result must
  trace to a live sidecar call (real-not-stub). If the sidecar is
  down, fail-closed; do not synthesize.
- Do NOT call out to non-loopback over stdlib `net/http`. All
  outbound HTTP is cap-routed through `httpout_*.go`.
- Do NOT hardcode `X-API-Key` or `X-Install-Mint` headers. mTLS-CN
  is the only tenant signal.
- Do NOT write SPKs directly into `static_store/packages/*` — notify
  the static_store crew via `/msg` per agentchat/CLAUDE.md.
