# Store release recall drill receipt

`estate_drill_producer.py` attests `4.17::title-claim` and the ReleaseEntry
case of `4.18::title-claim` after the governed `revoke_release_entry` ceremony.
The actual recall remains the owner authorized Store/chain operation. The
producer consumes its `melusina-revoke-release-receipt-v1`, pre and post
`/apps/index.json` bytes, and a signed installed scope naming `storeOrigin`.
It then reads that Store origin itself: the catalog must match the post bytes,
the recalled pointer must be 404, the survivor pointer must be 200 and bind
the new catalog hash, and the recalled package must refuse with 403. KIT reads
the catalog again and joins the exact post byte hash to the owner signed drill
receipt.

For `4.18`, the scope also names `chainRpcOrigin` and `genesisHash`, and the
after state names `releaseProgramId`. The producer reads the exact PDA from
the revoke receipt at finalized commitment, checks the genesis, program owner,
Anchor discriminator, ReleaseEntry byte layout, `app_id` hash for the recalled
app, `Revoked` status, and non-null `revoked_at` within the drill window. Its
signed `chain` object binds
the account hash and finalized slot. KIT independently reads that PDA again
and requires the same account bytes at a slot no earlier than the producer's.

The JSON manifest fields are `clause`, `operation`, `estateId`, `installId`,
`profileSha256`, `cutDigest`, `planStepSha256`, `startedAt`, `completedAt`,
`beforeObservedAt`, `afterObservedAt`, `beforeState`, and `afterState`. The
states name `catalogSha256`; the after state also names `recalledAppId`,
`survivorAppId`, `recalledPackageId`, `releaseEntryPda`, `status=Revoked`,
`revokedAt`, and the exact transaction signature. The producer derives the
catalog membership delta from the raw catalogs and refuses any extra removal.

```sh
python3 scripts/estate_drill_producer.py \
  --manifest /private/manifest.json --scope /private/verified-scope.json \
  --before /private/catalog-before.raw --after /private/catalog-after.raw \
  --native-receipt /private/revoke-receipt.json \
  --owner-key owner-a=/private/owner-a.pem \
  --owner-key owner-b=/private/owner-b.pem \
  --out /private/4.17__title-claim.json
```

Use `--ca-file` when the Store or RPC endpoint has a private CA. Owner key
files must be mode 0600. Output is created exclusively. KIT verifies the signatures against the
installed signed owner policy; the scope passed to the producer is not an
independent authority.
