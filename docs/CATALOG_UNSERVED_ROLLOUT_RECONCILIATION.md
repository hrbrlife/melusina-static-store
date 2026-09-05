# Catalog unserved-rollout reconciliation

`catalog-reconcile-unserved` is the narrow Store-owned recovery rail for one
durable rollout that is already absent from the active immutable catalog. It is
not an app publish, a catalog editor, or a replacement for a visible-release
retirement.

Use it only when a normal governed promotion refuses because an existing private
rollout has no matching public catalog row or signed pointer, while the active
catalog remains valid for every other durable rollout. Do not edit a catalog
generation, a rollout JSON file, or a staged artifact to make that condition go
away.

## Preconditions and proof

Run the command only with the active boot-identity-bound Store binary and its
exclusive writer lock. The command requires the exact current immutable
`apps/index.json` SHA-256 and exact app count, then verifies all of the
following before it can write a receipt:

1. The named app is absent from the active index.
2. Its durable rollout and private staged bytes are exact and valid.
3. There are no other quarantined rollouts.
4. The active catalog has a valid operator-signed pointer, selected bytes, and
   active governed release for every remaining durable rollout.

### Planned maintenance boundary

The serving Store deliberately holds the writer lock for its whole lifetime.
`catalog-reconcile-unserved` therefore must not be run beside the listener: it
will refuse rather than compete with a live publisher. Use one approved, short
Store maintenance window **after** the boot-identity pin and the new Store
binary have passed their ordinary release acceptance.

1. Record the live generation name, index digest, app count, and healthy serve
   surface before stopping anything.
2. Stop only the Store systemd service through the normal host change procedure;
   never remove the lock, edit catalog files, or copy a receipt into place.
3. Run the exact installed binary with `--dry-run` and retain its JSON report
   for independent review.
4. If it is accepted, rerun the identical command with `--apply` and retain the
   resulting receipt/report.
5. Start the service through the same normal procedure. Prove its health and
   publish-readiness endpoints, and prove that the active generation, public
   index digest, and public app count did not change. Only the signed private
   reconciliation receipt may be new.

The command's writer-lock refusal is a safety result, not a reason to work
around it with a second writer or a hand-edited lock file.

Always begin with a dry run, retaining its JSON report as the operator record:

```sh
melusina-store-sidecar catalog-reconcile-unserved \
  --config /etc/melusina/store/store.config.json \
  --app-id <immutable-app-id> \
  --reason '<bounded factual reason>' \
  --expected-index-sha256 <exact-current-sha256> \
  --expected-app-count <exact-current-count> \
  --dry-run
```

Only after the report is independently reviewed may the same exact command use
`--apply` instead. A successful apply creates one mode-0600, operator-signed
receipt in `catalog-unserved-rollouts-v1/`; it does not switch `current`, change
`apps/index.json`, alter package bytes, or change on-chain release state.

## Boundary with other operations

- If the app is selected by the active catalog, use the existing
  `catalog-retire` rail; this command refuses it.
- If staged bytes are malformed, missing their claimed runtime contract, or the
  rest of the catalog cannot be fully verified, this command refuses it.
- The receipt binds the exact rollout stage, app hash, version, source catalog
  generation, and index digest. Any drift fails closed on later classification.
- The reconciliation deliberately removes that exact rollout from future
  mandatory pointer planning. Reintroducing the app needs a separately governed
  new release/re-activation procedure; never delete or hand-edit the receipt.
