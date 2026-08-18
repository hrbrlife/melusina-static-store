# melusina-app-OpenSanctions — Sanctions Consumer Pearl

**App**: `melusina-app-OpenSanctions` (consumer pearl)
# melusina-app-OpenSanctions — Sanctions Consumer Pearl

**App**: `melusina-app-OpenSanctions` (consumer pearl)
**appId**: `msgn23jkp96yrup53t1yv71ens7kpda7yw10p8aepdzg7rhqssdh`
**Version**: v1 (marketing `0.1.0`)
**Language / runtime**: Go 1.22, Sandstorm pearl (capnp + go-sandstorm bridge)
**Catalog**: `https://bazaar.melusina-os.org/apps/index.json`

## PSP Role

This pearl is the **sanctions consumer front** in the Melusina PSP lifecycle.
It is one of two SPKs that replaced the old monolithic **telescreen-pearl**
per PLAN §0 — the sibling is `melusina-app-creeper` for the search / scrape
/ handle / contact OSINT half. (`pr_ninja` is a separate sibling-successor
TeleScreen Hub, not the predecessor.) The pearl itself does no
screening logic; it is a UI surface + per-tenant capability broker over the
`OpenSanctions-sidecar` LXC (192.168.122.250, systemd unit, nginx 443 → uvicorn
127.0.0.1:8000). It complements popaye's **direct** sidecar HTTP call wired in
`pkg/sanctionsclient/` — that direct path is the v1.0 happy-path for the
account-opening + receive screening leg of the PSP cycle (see
`/home/user/Desktop/agentchat/CLAUDE.md` step 2). The cap-routed
`SanctionsSubCap` this pearl exports is the **v1.1 migration target** that
popaye and any other consumer can claim once Grapple-out is the preferred
transport.

## Architecture (Brief)

- **Pearl**: `cmd/grain/main.go` → `pearl/*.go`. Owns SQLite at
  `/var/melusina-app-OpenSanctions/grain.db`, pearl ed25519 identity key,
  caps / claims dirs.
- **Outbound HTTP**: cap-routed via `melusina-http-component` (vendored at
  `third_party/melusina-http-component/go`). No stdlib `http.Get` — every
  egress is fail-closed until the operator claims the Grapple cap
  (CLAUDE.md §2.13).
- **Sidecar URL**: pinned in `sandstorm-pkgdef.capnp` env
  `OPENSANCTIONS_SIDECAR_URL=https://OpenSanctions.sidecar.host`. The
  hostname resolves inside the Sandstorm pearl via the cap-routed
  transport; outside, it's the same nginx 443 LXC entry.
- **Capnp schema**: `capnp/OpenSanctions/OpenSanctions.capnp` defines
  `SanctionsService` with `screenPerson` / `screenEntity` / `screenWallet` /
  `lookupCompany` / `getResult` / `listHistory`. TypeIDs are placeholders
  pending `capnp id` rotation before merge (PLAN §2.2).
- **Persistence**: SQLite + pearl-crypto-journal pattern (`claim_store.go`,
  `cap_token_store.go`, `core_db.go`, `state.go`).
- **Admin function-tester UI**: `pearl/static/` + `pearl/templates/` +
  `admin_*.go` — a debug shell for invoking `SanctionsService` methods
  directly inside the pearl.

## Deps + Exports

**Depends on**:

- `OpenSanctions-sidecar` over HTTPS (cap-routed). Sidecar provides
  `/api/screen/{person,entity}`, `/api/sanctions/*`,
  `/api/crypto/{screen,trace}`, `/api/{eth,btc,sol,tron}/reputation`.
- `melusina-http-component` (vendored) — cap-routed HTTP-out transport;
  no `X-API-Key` / `X-Install-Mint`, tenant identity is the sidecar's
  mTLS-CN (Inv 1).

**Exports**:

- `SanctionsService` Cap'n Proto capability via Grapple-out
  (`main_capnp.go` `GetViewInfo.matchRequests`).
- `SanctionsSubCap` — per-tenant sub-capability (`sanctions_subcap.go`,
  mirrors the old TelescreenSubCap pattern). This is the v1.1 cap-routed
  channel popaye is expected to migrate to from its current direct HTTP
  path in `pkg/sanctionsclient/`. Until then, both paths co-exist.

## Governance

- Governance + Hard Truths: `/home/user/Desktop/agentchat/CLAUDE.md`
  (PSP lifecycle, sidecar inventory, server / restart rules) and
  `/home/user/Desktop/agentchat/CHARTER.md` (Hard Truths 1-13).
- Doctrine library: `/home/user/Desktop/top_priority_doctrine/`.
- Product home: `/home/user/Desktop/Melusina/CLAUDE.md`.

The three Hard Truths that bite this app most:

- **HT5** — announce destructive pearl / SPK / schema changes in
  `agentchat` before doing them. Names + paths.
- **HT12** — no Sandstorm bypass. SPK installs go through the canonical
  `static_store` → admin UI → install-from-market path. No direct Mongo
  `packages` inserts, no `loginDevAccountFast`, no JS bundle hot-patches.
- **HT13** — any on-chain signing for pearl onboarding goes through Squads
  / offline-wallet; no hardcoded keypairs.

## pearl Onboarding — TODO (task #94)

This app is **not pearl-onboarded** (no master-NFT mint, no Squads vault,
no signed on-chain ReleaseEntry). It currently publishes through the
legacy static_store flow. The org-wide pearl-only `make publish` migration
is tracked centrally; until this app onboards, it cannot publish under
the new model. Task #94 captures the master-NFT + Squads + ReleaseEntry
work needed here.

## App-Specific NOT-To-Do

- Do NOT fabricate clear / hit verdicts for testing. Sanctions outcomes
  are load-bearing for the PSP cycle; a stubbed "all-clear" can mask a
  real-world hit downstream in popaye + DueProcess routing.
- Do NOT bypass the authz gate. Cap-routed access is gated through the
  `melusina-http-component` transport and the sidecar's mTLS-CN check;
  the 2026-05-18 live test surfaced a 403 because the `cca-sh-vm` admin
  pubkey wasn't in the keyholder registry — that is the **correct**
  failure mode, register the key, do not loosen the gate.
- Do NOT add stdlib `net/http` egress. Every outbound call routes through
  the cap-routed transport (CLAUDE.md §2.13).
- Do NOT hardcode `X-API-Key` or `X-Install-Mint` headers. Tenant identity
  is the sidecar's mTLS-CN (Inv 1).
- Do NOT write into `static_store/packages/*` directly when publishing
  this SPK — concurrent writes wedge stubs. Notify the `static_store`
  crew member via `/msg` instead.
- Do NOT restart the live `OpenSanctions-sidecar` LXC without Riker's
  say-so; popaye's direct screening path depends on it for the PSP
  account-open / receive demo.

## Build / Test

```bash
make dev    # plain build
make test   # unit tests
make pkg    # spk pack
make capnp  # regenerate capnp/OpenSanctions/OpenSanctions.capnp.go
```
