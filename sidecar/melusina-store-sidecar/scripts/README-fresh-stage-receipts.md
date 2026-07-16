# Fresh deployment app/store stage receipts

`emit_fresh_deployment_stage_receipt.py` is the read-only bridge between the
real app release/publish ceremonies and the deployer's
`melusina-fresh-deployment-stage-receipt-v1` finalizer.

The signed genesis public input `appReleaseInventory` must resolve below
`--artifact-root` to this exact, appId-sorted schema:

```json
{
  "schema": "melusina-fresh-app-release-inventory-v1",
  "apps": [
    {
      "appId": "<52-char Sandstorm app id>",
      "appHash": "<64 lowercase hex>",
      "releaseHash": "<64 lowercase hex>",
      "version": "1.2.3",
      "releaseEntryPda": "<fresh-program-derived PDA>"
    }
  ]
}
```

After the governed release registrations finalize:

```sh
python3 scripts/emit_fresh_deployment_stage_receipt.py app-releases \
  --genesis "$GENESIS" \
  --expected-root-key "$ROOT_KEY" \
  --artifact-root "$ARTIFACT_ROOT" \
  --rpc-url "$RPC_URL" \
  --output "$STAGES/appReleases.json"
```

The command verifies the genesis signature and signed inventory bytes, checks
the live RPC genesis before any account read, derives every ReleaseEntry PDA
under the fresh program, and emits finalized byte-hashed account proofs.

Capture every already-verified `cmd/submit` promotion response at
`$PROMOTION_RECEIPTS/<appId>.json`. `cmd/submit --receipt-out` can write either
the raw `melusina-app-promotion-receipt-v1`, or the existing self-publish flow
can write the complete `melusina-app-publish-receipt-v1` wrapper. When
`publish-supersede` drives the operation, its `--promote-cmd` should invoke
`submit --receipt-out "$PROMOTION_RECEIPTS/$MEL_APP_ID.json"`; the WAL already
exports `MEL_APP_ID` to that command.

After all signed-inventory apps are live:

```sh
python3 scripts/emit_fresh_deployment_stage_receipt.py store-publish \
  --genesis "$GENESIS" \
  --expected-root-key "$ROOT_KEY" \
  --artifact-root "$ARTIFACT_ROOT" \
  --rpc-url "$RPC_URL" \
  --promotion-receipt-dir "$PROMOTION_RECEIPTS" \
  --output "$STAGES/storePublish.json"
```

This second mode re-reads every ReleaseEntry and the root
StoreOperatorAuthorization at `finalized`, verifies all store signatures against
the on-chain/signed store authority, fetches the exact signed HTTPS store origin
without accepting redirects, and requires live `apps/index.json` plus every
`apps/pointers/<appId>.json` to match the signed promotion evidence.

Both modes are read-only. They issue only Solana JSON-RPC reads and HTTPS GETs.
They never register/revoke a release and never POST to the store.
