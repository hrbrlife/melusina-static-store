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

Use `--ca-file` when the Store has a private CA. Owner key files must be mode
0600. Output is created exclusively. KIT verifies the signatures against the
installed signed owner policy; the scope passed to the producer is not an
independent authority.
