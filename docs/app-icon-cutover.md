# App icon cutover

Two icon paths exist right now, deliberately and temporarily. This is the order
that retires the first without a visible regression.

## Why there are two

The bazaar rendered a letter tile for every app because the served
`apps/index.json` carried no `imageId` — `build-store.sh` was the only producer
that ever set one, and the sidecar-composed generation replaced it. The flicker
was the SPA painting stale `imageId`s from its bundled `apps.json` at
`/images/<md5>` paths that 404 on the served tree.

Fixing what users see and fixing the pipeline have different lead times, so they
shipped separately:

1. **Live now** (`d66bf85`) — `scripts/build-app-icons.sh` extracts each app's
   icon from its published `.spk` and commits them as `public/icons/app/<appId>.<ext>`
   plus `src/app-icons.json`. `AppIcon` resolves that map. Works for all 34 apps
   today, but a newly published app has no icon until the script is re-run.
2. **Deployed 2026-07-31** (`37618da`, release `1.0.13`) — `projectCatalogIndex`
   extracts the same icon through the same `internal/spkicon` library at publish
   time, records `imageId`, and writes `images/<imageId>` into the generation.
   Self-maintaining, and it backfills rows published before the change. The
   binary is live; the generation gains `images/` when it next composes one,
   which happens on the next app publish.

Both read the same authoritative bytes through one extractor. Path 1 is a
build-time snapshot of what path 2 does continuously.

## Release 1.0.13

Built from pushed commit `37618da`, two byte-identical builds:

```
572143daf3ea8c65891f3664d52eb96a362ccf91549ecba7af6b4abe77206dcb  melusina-store-sidecar
ce66ea2c6ea2ac8c47a8e5906ee9a1505fb98ee90df0383de69b59877a64ebf0  boot-identity-prep
2de8c53f8b439bb373d8ae120f7b917134b191917c6df4236b05c797ca695246  store-generation-1.0.13.tar.xz
```

Artifact kept at `/home/user/Desktop/store-generation-1.0.13`.

## How 1.0.13 was deployed (2026-07-31)

Per `runbooks/HOW_TO_UPDATE_SHELL_AND_SIDECARS.md` §3, with one correction the
runbook does not make: it prescribes **three** re-pins, but the store needs
**two**.

The store's boot gate is `SidecarIdentityEntry.binary_hash` only —
`boot_identity.go` never calls `binhash.AttestSelfHashWith`, and mentions
`GlobalSidecarApproval` solely to say the identity check is its analogue. The
Local PDA (`9NjQULhN…`) exists with its `binary_hash` unset, and an unset-but-
present Local pin passes, so `update_local_sidecar_binary_hash` was not needed.
The executed 1.0.11 ceremony did the same two writes.

Order actually run — reverse instructions for **both** writes were emitted first,
so rollback was armed before any chain write:

1. **Global** `update_global_sidecar_binary_hash` → Core-App-Team multisig
   `4sPNmdcS` / vault `3jfN9rcS`, 3 approvals, tx index 1436
   (`2XTrtirm5Su6RrPupQRVTEs6…`).
2. **Identity** `update_sidecar_identity` → OWNER multisig `DeHGGjbK` / vault
   `FQFAyzgr`, 2 approvals, tx index 364 (`PMFfqmioLYTBrAT1zN6b3qU7…`).
3. Verified both PDAs hold `572143da…` and `6319d2f1…` is gone.
4. Installed per the DEPLOYMENT-CONTRACT: archive sha verified, extracted to
   `/opt/melusina-store/releases/1.0.13-2de8c53f…`, extracted ELF sha checked
   against the on-chain pin, bundled unit confirmed byte-identical to the running
   one, `current` repointed atomically, then restart.

Instructions, execute logs, and both reverse instructions are in
`Melusina/deployer/state/tenants/melusina-os.org/release-inputs-1.0.13-app-icons/`.

Two things worth knowing for next time:

- `melusina-solana.py` reports `Squads vault … holds no token account for master
  NFT` when its RPC call merely *fails* — the lookup swallows the exception and
  returns None. The vault did hold the NFT; the default public devnet endpoint
  was the problem. Export `SOLANA_RPC_URL` at the Helius endpoint before emitting.
- `squads-vault-exec.js` resolves relative `--member` paths against
  `TEST_WALLETS_DIR`. Pass absolute paths.

Result: `1.0.13 starting`, `boot identity: operator 4J2hbufi… bound to on-chain
SidecarIdentityEntry (Active) — /publish enabled`, no "legacy static recovery"
line, catalog intact at 34 apps, DesiredGeneration still id 43 with all 34
components (checked, not assumed — §4 says a redeploy can silently strand it).

The service restarted once during boot on a pre-existing `SPK bytes differ from
exact staged candidate` recovery error. That is **not** from this change: the same
error first appears in the journal on 2026-07-29 under 1.0.12 and has fired five
times in seven days. It self-resolves on the automatic restart, as it did here.

`validateCatalogTree` tolerating an absent `images/` is what let this binary
resolve the live pre-images generation at all — without it the store would not
have started.

## Then cut over

The generation only gains `images/` when the new binary composes one, which
happens on the next publish. Until that has actually happened, path 1 is still
what renders.

Once `/apps/index.json` shows `imageId` on the rows and `/images/<imageId>`
returns the bytes:

1. Point `AppIcon` at the row's `imageId` instead of the generated map.
2. Delete `public/icons/app/`, `src/app-icons.json`,
   `scripts/build-app-icons.sh`, `docs/app-icon-coverage.json`, and this file.
3. Rebuild and redeploy the SPA.

Retiring path 1 before that regresses every app to a letter tile.

## Apps that will still show a letter

Six ship no `icons` block in their pkgdef, so neither path can find one:
Bureau Calendar, Bureau Contacts, Creeper, InstaDAO, OpenSanctions, Sheets
Bureau. InstaDAO added icons after `v1.0.9` was published and only needs a
republish. The rest need an `icons` block first. That is app-side work — the
store correctly reports what the package contains.
