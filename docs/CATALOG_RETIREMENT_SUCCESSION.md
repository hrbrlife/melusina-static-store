# Published successors of retired releases

A signed catalog retirement withdraws one exact release selection. When an
ordinary governed publish selects a strictly newer release of the same app,
startup validates its complete stage and signed catalog through the ordinary
path. The old receipt remains intact. Equal or older versions, reused hashes
or stages, and activations at or before the retirement are refused.

The original withdrawn version stays retired. This rule does not change app
membership, bypass live release checks, or recall any historical release.

## Repairing an already-published succession

`catalog-reconcile-retirement` is a bounded Store maintenance operation for a
published successor whose old receipt prevents an earlier Store binary from
starting. It validates the complete current catalog against all serving
rollouts, every staged artifact and signed pointer, the configured Squads
authority, and the successor's live chain release. Quarantined or incomplete
cohorts are refused.

The operation requires the existing boot-identity-bound Store operator and
the existing exclusive catalog writer lock. Administration must use a reviewed
browser action with the exact root InstallAdmin; the CLI is its backend, not
an alternative authorization path. Only a chain-approved Store binary may run
it. It accepts exact expected digests of the current index, rollout and old
retirement, plus the complete serving app count. Use `--dry-run` for inspection
and `--apply` only behind that browser authorization.

The backend copies the original signed retirement byte for byte into
`catalog-retirement-successions-v1/<appId>-<retirementSha256>/retirement.json`,
writes and syncs an operator-signed `succession.json`, then removes only the
superseded active retirement entry. Interrupted runs resume after re-verifying
the same inputs; a completed run verifies its existing signature and returns
the same receipt. Existing archives cannot be overwritten.

This operation does not change a catalog selector, package, rollout, signed
generation, runtime marker, configuration, service or chain account. A
controller rollback and its chain reconciliation remain separate governed
operations. Never edit the failed generation or delete its terminal receipt.

The focused `TestCatalogRetirement*` and `TestCatalogReconcileRetirement*`
tests cover strict succession, missing package bytes, original evidence and
public-byte preservation, interrupted writes, idempotence, changed inputs,
revoked authority, invalid signed pointers, unsafe archives and receipt tampering.
