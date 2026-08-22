# Bazaar Control onboarding and cutover

## Purpose

This is the human-facing path for a governed Bazaar app release. It deliberately
does **not** ask an operator to run a publish script, understand a generation,
construct an envelope, write a WAL, or operate a PDA.

The normal lifecycle is:

```text
Draft → Ready to approve → Waiting for signatures → Publishing → Verifying → Live
                                      ↘ Needs attention
```

The Bazaar Control Pearl presents that lifecycle. The Store sidecar, Store Link,
workers, constrained listing signer, and governance adapters carry out the
mechanical work behind it.

This document is a source-and-pilot runbook. It is **not** evidence that the
required services or governance policy are deployed on any particular Store.

## Authority boundaries

Normal people may create a release, review and sign an exact release, resume a
genuine hold, and separately operate delist/rollback-selection/publisher
lifecycle/global recall. They do not publish with a terminal command.

An LLM, terminal, or CI task may receive a short-lived, sender-bound submission
capability for one Store and app. It may create one Draft and correct only
source intent before a build starts. It cannot publish, approve, reach Store
Link, manage publishers, sign a transaction, or access a Store key.

A release source intent contains a source reference, version, and a resolved
lowercase 40-character Git commit. The reference is context for the fixed build
profile; the commit is the immutable source that the build, review, and Store
Link bind.

## Required before a pilot

Do not enable the direct-route retirement switch just because the Pearl UI
builds. The selected Store needs all of the following, with their ownership and
file permissions checked during installation:

1. A packaged Bazaar Control Pearl, bound to exactly one selected Store through
   Store Link and its own mTLS identity.
2. Fixed build, preparation, finalization, and tenant-proof workers. Each must
   have its dedicated TLS identity, owner-only state, result key, and only the
   narrow route defined for that worker. No worker may accept a shell command,
   checkout path, caller-selected profile, publisher key, or arbitrary URL.
3. The Store-side constrained listing signer on a same-user, owner-only Unix
   socket. The Pearl never holds the Store-authority key. The signer may sign
   only the canonical listing registration for the exact verified release.
4. Governed `StoreControlPolicy` and exact Store/app `StorePublisherGrant`
   records, plus the Pearl routing and offline-approval public keys expected by
   the selected Store.
5. A dedicated authenticated QA tenant/browser adapter for proof. It must prove
   catalog → Store UI install/upgrade → `db.userActions` and `db.grains` pin
   agreement → Upgrade Pearls → fresh grain → visible runtime.
6. A scheduled maintenance window and rollback owner for the final retirement
   configuration/restart. This is a deliberate operational decision, not an
   automatic retry.

## Pilot one low-risk app

1. In Bazaar Control, create the release by selecting the app, resolved commit,
   version, and notes. A terminal-originated Draft is acceptable only through
   the bounded submission capability.
2. Wait for **Ready to approve**. The system has built, independently observed,
   checked package/runtime facts, and frozen the candidate. Review the source,
   version, artifact facts, diff, and the current selected release.
3. Use the normal offline signing screen. The signer must see the exact app,
   Store, version, source commit, candidate, expected predecessor, and expiry.
   The human then supplies the required Squads approvals. A review does not
   expose a Store or publisher private key.
4. Wait for **Publishing**. The finalizer and sidecar perform the gated work.
   The sidecar must verify the candidate and authority, create and read-back
   verify `StoreReleaseListing`, then switch the catalog selector last.
5. Wait for **Verifying**. The tenant-proof worker runs the fixed browser and
   database proof. Existing Pearls are upgraded through the product's own
   control before the fresh-grain runtime assertion.
6. Mark the pilot successful only when the Pearl displays **Live** and the
   evidence shows the catalog, tenant pin, existing Pearls, fresh grain, and
   runtime all agree.

If a listing cannot be registered, the correct result is **Needs attention**:

> Publishing paused: listing registration was not confirmed. The live catalog
> is unchanged. Retry safely.

The correct response is to diagnose and resume the persisted release; do not
stop the Store, run a listing bootstrap ritual, hand-edit state, or bypass the
sidecar.

## Prove the F-257 safety boundary

Before legacy route retirement, exercise a controlled negative case in the
pilot environment: make listing registration fail after all preceding release
checks. The selected catalog must remain readable at its old release; there
must be no new selector and no partial release made public. Restore the
dependency and resume the same persisted release. The already-active listing
may be reused, but selector movement must occur only after a successful
read-back verification.

Record the Pearl release ID, sidecar receipt, old and new catalog pointers, and
the tenant-proof result. This is release evidence, not a replacement for it.

## Retire legacy direct app publishing

Only after the pilot and the negative listing case pass, make the separate
operator-approved configuration change:

```json
{
  "policy": {
    "require_pearl_control_for_app_publish": true
  }
}
```

The sidecar rejects this cutover configuration unless its private Store Link
mTLS listener is complete. A listing-enforcing Store also requires the
constrained `listing_signer_socket`. Apply it in the planned restart window,
then verify:

- `POST /publish` and `POST /publish/stage` return `410 Gone` before parsing
  request data, allocating a nonce, or touching stage state;
- the public listener does not expose `/control/v1/*`;
- the private Store-Link mTLS listener still accepts only the typed Pearl
  control routes; and
- a normal Pearl release and tenant proof remain possible.

System-update endpoints are not part of this app-release retirement.

Do not silently turn the switch back off to repair a release. A failure after
cutover belongs in **Needs attention** and follows the persisted Pearl release
and governed recovery path. Re-enabling legacy direct publishing is a separate
break-glass change with its own approval and audit record.

## Deprecated procedure

The former instructions to use `melusina-pearl-tool onboard`, share a developer
Solana key, collect Squads browser URLs manually, then run `make publish` are
retired for Bazaar app releases. They combine preparation, approval, and
publication in a terminal-driven flow and can recreate the F-257 catalog
outage. They are not a fallback for the Golden path.

For the detailed product boundary, see the Bazaar Control Pearl's
`docs/RELEASE_AUTHORITY_MODEL.md`, `docs/AGENT_SUBMISSION_API.md`, and
`docs/WORKER_SERVICES_REQUIREMENTS.md`.
