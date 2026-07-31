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
2. **Built, not deployed** (`37618da`, release `1.0.13`) — `projectCatalogIndex`
   extracts the same icon through the same `internal/spkicon` library at publish
   time, records `imageId`, and writes `images/<imageId>` into the generation.
   Self-maintaining, and it backfills rows published before the change.

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

## Deploy, in order

Per `runbooks/HOW_TO_UPDATE_SHELL_AND_SIDECARS.md` §3. The boot gate compares the
on-disk ELF sha against the on-chain Active `SidecarIdentityEntry.binary_hash`,
and it runs **once at boot** — so the running 1.0.12 process is safe until it
restarts. The brick moment is a restart while those differ.

1. Publish `1.0.13` as an `InstallerReleaseEntry` (`cmd/submit-installer`). The
   sanctioned apply helper requires that receipt; it will not take a hand-staged
   ELF.
2. Three ordered Squads v4 re-pins of `572143da…`, all before any restart:
   **Global** (`update_global_sidecar_binary_hash`, 3-of-4 Core-App-Team,
   multisig `4sPNmdcS` / vault `3jfN9rcS`) → **Local**
   (`update_local_sidecar_binary_hash`, OWNER 2-of-2, needs an active Foundation
   approval for the new sha) → **Identity** (`update_sidecar_identity`, same
   OWNER multisig, must follow Local).
3. Verify all three PDAs hold the new sha and the old sha is gone.
4. Arm the reverse ceremony **before** restarting. Rolling back the ELF alone
   does not work: once the chain names `572143da…`, the old binary fails the same
   boot gate. Rollback is another three-write ceremony, so stage it first.
5. Apply via `cmd/apply-store-update prepare-store-update` — never `cp` +
   `systemctl`; that side-load bricked the box on 2026-07-13.
6. Restart. The journal must show identity bound and `/publish enabled`, with no
   "legacy static recovery / publishes disabled" line.
7. Regenerate the DesiredGeneration (§4). A redeploy can leave
   `/update/generation.json` stale while the index looks complete, and every
   absent app then fails install with `generation-app-component-missing` [403].

Deploying alone changes nothing users can see — icons already render. The gain is
that publishes stop depending on a script anyone can forget.

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
