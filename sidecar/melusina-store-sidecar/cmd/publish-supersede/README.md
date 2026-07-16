# publish-supersede — the no-gap app republish orchestrator (card 0055)

Replaces an app's Active on-chain `ReleaseEntry` with a strictly-greater one
**without ever leaving the app with zero Active releases**.

## The defect (card 0055)

The prior `self-publish.sh --revoke-stale` path ordered:

```
ceremony -> REVOKE old Active -> durable /publish (promote)
```

It flipped the live Active `ReleaseEntry` to `Revoked` **before** the replacement
was durably promoted. If the process died in that window the app had **0 Active
servable releases** — `serve_gate.go` refuses to serve any SPK whose AppHash
lacks an Active `ReleaseEntry`, so the app went dark and every republish was
blocked. The later ailagoon "stage-before-revoke" reorder
(`register -> stage -> revoke -> promote`) narrowed the window but still revoked
**before** promote, so the `revoke -> promote` gap remained.

## Why a compensating WAL, not an atomic on-chain supersede

The license-registry program (verified from
`programs/license-registry/src/instructions/attestation.rs`) exposes **no atomic
app-release supersede instruction**:

- `register_release_entry` (→ `Active`) and `revoke_release_entry`
  (`Active` → `Revoked`) are **separate, single-account instructions**.
- The `ReleaseEntry` PDA is seeded by `app_hash`
  (`[b"release_v2", master_nft_mint, app_hash]`), so a new version is a
  **distinct PDA** — old and new can be `Active` at the same time.
- The app publish gate (`release_version.go` `verifyReleaseVersionForward`)
  **deliberately permits that 2-Active rollout window**: it only requires the
  submitted version be strictly greater than every *other* Active version; it
  does **not** require the old to be revoked first. (`errSupersedeRequired` is
  enforced on the installer path only.)

So there is no single instruction that revokes-prior-and-activates-new. The fix
is option **(b)** from the ticket: a durable compensating state machine that
promotes the new release into service **first** (a gate-legal 2-Active window)
and revokes the old **last**.

## The no-gap ordering

```
INIT -> REGISTERED -> STAGED -> PROMOTED -> REVOKED -> DONE
```

| state | on-chain Active | served bytes | app dark? |
|-------|-----------------|--------------|-----------|
| INIT | old (1) | old | no |
| REGISTERED | old + new (2) | old | no |
| STAGED | old + new (2) | old | no |
| PROMOTED | old + new (2) | **new** | no |
| REVOKED | new (1) | new | no |
| DONE | new (1) | new | no |

The only `Active → non-Active` transition (revoke old) happens at
`PROMOTED → REVOKED`, strictly **after** the new release is both `Active` and
served. On-chain Active count moves `1 → 2 → 2 → 2 → 1`, **never 0**, and at
every observable instant the bytes the store serves are backed by an Active
`ReleaseEntry`.

## Durability + idempotent forward recovery

Every transition is journaled to a write-ahead receipt (`--wal`) with an atomic
temp+rename+fsync, mirroring `cmd/apply-store-update`. On restart the WAL is read
and the pipeline **resumes forward** from the recorded state — it never rolls
back and never revokes before promote. Every mutating step is idempotent
(re-checks live on-chain / served state before acting), so a crash mid-step plus
a re-run converge to exactly-1-Active (the new release).

## Orchestrator signs nothing (HT13)

`publish-supersede` writes no chain state directly. It coordinates
operator-supplied governed commands in the crash-safe order above:

- `--register-cmd` / `--revoke-cmd` are the **off-box Squads ceremonies** — keys
  never touch the box.
- `--stage-cmd` / `--promote-cmd` drive the existing gated `/publish` routes.
- `--active-cmd` (wrap `list-active-releases`) / `--served-cmd` are read-only.

`--stale-pda` is the **exact, pre-declared** set of prior Active PDAs to retire;
the orchestrator revokes exactly those and refuses to touch the new release.

## Proof

`supersede_test.go` injects a crash at **every** interruption point
(before/mid/after register · stage · promote · revoke) and asserts the
Active-release invariant held at the crash instant, then that a re-run recovers
to exactly-1-Active (new) + served=new. `TestSupersede_HarnessDetectsBuggyRevokeFirstGap`
proves the invariant check is not vacuous: the buggy revoke-first ordering leaves
`onChainActive=0`, which the check catches.

```
go test -v ./cmd/publish-supersede/
```
