# Default Bazaar source recovery queue

The authoritative release scope is the 32-app ledger in
`fleet/bazaar-catalog.yaml` for `https://bazaar.melusina-os.org`. Historical
catalog scans, old Store rows, and preserved branches are evidence only.

## Current queue

- 31 apps have a source-pinned, `direct-dev-verified` selection receipt and
  are eligible for their individual package and governed-release controls.
- InstaDAO is the sole source-selection hold. Its record is
  `fleet/prepublish-holds/gcm92hhzx20xgtfakp0kpdywmav49m2p9wnq75rv35fez680j9k0.json`;
  its on-chain program/artifact mismatch must be repaired before a source pin
  or publish attempt.

Do not restore retired identities from this document. Each current app's
selection receipt is the complete branch-review record, and every release must
still prove clean source, package bytes, signatures, governed receipts, served
catalog state, tenant pin, and fresh installation.
