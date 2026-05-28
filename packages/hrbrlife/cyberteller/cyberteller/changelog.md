# Changelog

## v0.1.40-fleet-parity (appVersion=46) — 2026-05-18

Fleet-parity cleanup batch — 11 supporting commits, no user-visible
slip-render changes. Brings cyberteller into structural alignment with
sister grains shipped this session.

- `/version` and `/health` HTTP endpoints (public, no-auth) — matches
  the convention proven by ailagoon, OpenSanctions, mermail, dns,
  vintage, creeper, ccash_domain_template. `/version` returns
  `{app, commit, time, branch, go, hostname}` with ldflag-injected
  build metadata; `/health` returns `{app, status, checks{db}}` with
  a 2-second SQL ping probe (HTTP 503 when degraded). wolfdog
  reporter picks both up opportunistically (per wolfdog idx 1883).
- Makefile `build-source` now injects BuildCommit / BuildTime /
  BuildBranch via `-ldflags='-X main.BuildX=...'`. Defaults derive
  from `git rev-parse --short HEAD` / `git rev-parse --abbrev-ref
  HEAD` / `date -u +%FT%TZ`. `runtime/debug.ReadBuildInfo` backfills
  commit + time when ldflags are absent.
- pearl-mode publish wiring in Makefile: `PEARL_LIVE_MASTER_NFT_MINT`,
  `PEARL_LICENSE_MINT`, `PEARL_RELEASE_VERSION`, `PEARL_APP_ID`,
  `TEAM_LIVE_SQUADS`. Singleton-master pattern (license-registry
  v104 hard-codes the master mint). Matches the recipe proven by
  `melusina_ccashconfig_app` on 2026-05-18.
- Spkmodule submodule bumped twice (`2ee80d2 → 579da4a → 048d11f`)
  to pick up the greenfield pearl pipeline + parse-time PEARL_*
  gating fix (so `APP_PEARL_ENABLED:=no` apps still pass check-drift).
- Admin `/admin/config` UI honesty fix: the previous template's raw
  YAML textarea was unpopulated by the handler and the form POSTed
  a shape `ConfigSave` doesn't accept. Now renders a read-only view
  of the three settable fields (invoice expiry, price-feed enabled,
  price-feed currency) plus the live config hash, plus an explicit
  pointer to the canonical save path (cybertellerconfig wizard or
  apply-cyberteller-config CLI → signed POST /admin/config).
- 20 `// e2e:none reason=...` annotations across aitxbridge / capgrain
  / httpout / price / webhook / webhookoutbox + chainwatch sidecar
  chain.go. Closes the check-e2e-envelope tripwire (0 FAIL); every
  annotation carries an honest reason (in-band-envelope, internal-
  dispatch, Grapple-attested, public-rpc-read, relay-presigned-tx,
  public-priceapi). Documents existing trust posture without code
  change.
- `chainwatch/internal/chain.ProofPayload` added — byte-identical
  mirror of `internal/checker.ProofPayload`. Unblocks
  `depositproof_test.go` (orphaned since a2f25c3 WIP). Wire format
  pinned both sides: `tx_signature:slot:lamports`.
- `chore`: `.chatpid` untracked + added to `.gitignore` (per-session
  agent state).

## v0.1.39-authz-sock-mount (appVersion=45) — 2026-05-18

Two-part fix landed live via Sandstorm App Sources earlier today
(SPK sha256 `f7b1815a10353ecc71d9616269e7a7034a18eb047ddde256774821b481d094cb`)
but left uncommitted on the worktree; commit captures + documents.

- `sandstorm-pkgdef.capnp` + `run/melusina/.placeholder`:
  `alwaysInclude=[run/melusina/.placeholder]` forces an empty `run/`
  tree into the SPK so Sandstorm's supervisor (supervisor.c++:1370,
  `access("run", F_OK)` gate) mounts a tmpfs at `run/`, mkdirs
  `run/melusina/`, and bind-mounts the host `/run/melusina/authz.sock`
  onto `run/melusina/authz.sock`. `main.go:366` dials
  `grainauth.DefaultSocketPath` cleanly. Without the bind, every
  authz-gated handler (admin/onboard, capgrain inbound.invoke, the
  popaye→cyberteller `createSlip` RPC) returned
  `forbidden:transport-error` → Peer disconnected and the PSP M2→M5
  cycle died silently.
- `internal/capgrain/inbound.go`: `Inbound.invoke()` synthesises
  `X-Sandstorm-Permissions = create,read,notify,admin,deposit-monitor,
  static-publish` so chi's `RequirePermission` middleware accepts the
  capnp Grapple caller. The peer is already authenticated by the
  Grapple claim that vended the Inbound cap; granting it the
  permission strings the routes need is the correct scope
  (CreateSlip→create, GetSlipStatus→read, NotifyPayment→notify,
  MoveToNostro→admin).
- `CLAUDE.md` rewritten to the PSP-canonical framing (Pass-2 audit,
  Riker idx 1414): payment slips ledger + on-chain settlement
  sidecar role; M1/M2/M5/M6/M4b lifecycle; load-bearing pkgdef
  invariant documented; Hard Truths 5/12/13 as they bind cyberteller
  daily; PSP-app-specific "NOT to do" list.

## Older — see git log

Commits before this changelog landed are described in their commit
messages (`git log` is the source of truth). Pre-v45 marketing
versions were named `spawn-CYB2 passN: <short desc> (0.1.X /
appVersionN)` per the spawn-era convention.
