# Target-scoped app delisting

This design removes one exact app release from one store's visible catalog. It
does **not** revoke a global `ReleaseEntry`, mutate release history, hand-edit
`apps/index.json`, or use a catalog-shrink override.

## What the transition binds

`delist_store_release_listing` mutates only the exact
`StoreReleaseListing` PDA derived from:

```text
["store_release_listing", store_authority, app_hash]
```

The instruction requires Master-NFT custody and verifies the listing's exact
`ReleaseEntry`, `StoreOperatorAuthorization`, domain hash, and PDA seeds. It
sets the listing state to `Delisted`; the global `ReleaseEntry` remains
unchanged and may stay Active for other stores.

After the governed listing bootstrap is complete, operators explicitly set
`store_authority` and the sidecar verifies that same exact listing for every
served package and each catalog row. A `Delisted` listing is then the only
condition that omits a row. Missing records, RPC errors, an unknown status, a
wrong PDA, domain, app hash, release entry, authorization, or store authority
all fail closed. Before that explicit configuration, the established global
`ReleaseEntry` gate remains in force; a partial listing deployment must never
silently become the active serve policy.

## Required ceremony order

This is source-only work until all of the following are complete. Do not deploy
the sidecar first and do not run the delist instruction early.

1. Build and govern the smart-contract upgrade that adds
   `delist_store_release_listing` and `StoreListingStatus::Delisted`.
2. Inventory every currently served catalog row from the exact sidecar source
   tree. For each row, derive and confirm an Active `StoreReleaseListing` PDA
   for this store authority, exact release entry, license, and domain. A missing
   listing is a blocker, not an implicit Active state.
3. Set `store_authority` in sidecar configuration to the exact configured store
   signing public key. The matching local operator identity is required only
   when a delist changes catalog bytes, so surviving catalog pointers can be
   re-signed over the new catalog hash. A missing or different key returns 503;
   it must not produce an unsigned filtered catalog.
4. Deploy the governed sidecar build with a live read-only RPC connection only
   after steps 1-3 are independently verified. Confirm all existing rows and
   their signed pointers still serve through the listing gate.
5. In the custody ceremony, independently derive the DEV app hash from the
   exact current release artifacts, derive its listing PDA, and invoke
   `delist_store_release_listing` with the Master-NFT holder. Do not call
   `revoke_release_entry`.
6. Confirm only that DEV listing reads `Delisted`; PROD's listing, package,
   pointer, and both global `ReleaseEntry` records remain active. Then the
   sidecar's rendered catalog may omit DEV dynamically.

## Deliberate properties

- The source catalog and source pointer files are never rewritten during a
  request. A changed catalog is an in-memory projection only.
- While no listing is Delisted, the source `apps/index.json` and pointers are
  served byte-for-byte, preserving existing catalog signatures.
- Once one listing is Delisted, every surviving pointer is verified against the
  source catalog then re-signed in memory against the projected catalog hash.
- `Delisted` is terminal in this transition. Re-listing is intentionally not an
  implicit rollback path; it needs a separately governed, audited transition.
