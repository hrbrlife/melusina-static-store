# publish-app-release — fast v2 app publisher contribution

The candidate operator entry point is `scripts/publish-app-release.sh`. It builds this
vendor-pinned Go command and then holds one per-app lock across the complete
release:

```
INIT -> BUILT -> REGISTERED -> STAGED -> PROMOTED -> REVOKED -> VERIFIED -> DONE
```

This branch is an isolated contribution. Riker and
`SYSTEM-RELEASE-RAIL-SHELL` own review and integration into the one canonical
production publisher; this branch does not merge or deploy itself.

It supports both a first publication (`--stale-pda` omitted, initial Active set
must be zero) and a supersede (every initial Active PDA must be declared with a
repeatable `--stale-pda`). There is no Publish Tzar and no revoke-first mode.
The authorized vertical supplies local allowlisted command adapters; remote
store data never supplies a command, unit name, path, or credential.

## Native receipt contract

The command adapters are invoked with fixed environment variables and must
atomically materialize JSON files. Operation banners on stdout are ignored.
Every adapter is born atomically inside its own delegated cgroup-v2 subtree.
`--adapter-cgroup-root` must name the publisher service's `Delegate=yes`
subtree. Missing delegation, cgroup-v2, or writable `cgroup.kill` is a hard
refusal; there is no process-group-only fallback. Thus timeout and nominal
success both reap `setsid`/double-fork descendants before the publisher returns.

| adapter | required output |
|---|---|
| `--build-cmd` | `$MEL_CANDIDATE_RECEIPT_OUT`, schema `melusina-app-candidate-receipt-v1`, binding absolute SPK + metadata paths, sizes and SHA-256 values |
| `--register-cmd` | finalized `$MEL_RELEASE_JSON_OUT` plus `$MEL_REGISTER_RECEIPT_OUT`; consume the WAL-pinned `$MEL_RELEASE_NONCE` |
| `--stage-cmd` | raw verified `cmd/submit --stage --receipt-out "$MEL_STAGE_RECEIPT_OUT"` receipt |
| `--promote-cmd` | raw verified `cmd/submit --receipt-out "$MEL_PROMOTE_RECEIPT_OUT"` receipt |
| `--revoke-cmd` | `$MEL_REVOKE_RECEIPT_OUT`, bound to the exact `$MEL_PDA` |

`cmd/submit` is therefore integrated through its receipt-file API, never by
scraping human stdout. The WAL hashes the candidate receipt, exact SPK and
metadata bytes, recomputed canonical appHash, finalized `RELEASE.json`,
register/stage/promote receipts, and every exact-PDA revoke
receipt. A successful invocation emits exactly one strict
`melusina-app-publish-terminal-receipt-v1` JSON document and durably writes the
same document as `<receipt-dir>/terminal.json`.

Before stage, the publisher independently recomputes the canonical tree hash
over the exact candidate `{app.spk, metadata.json}` and requires it to equal
`--new-app-hash`. The stage adapter receives those exact paths and hashes in
`MEL_CANDIDATE_SPK`, `MEL_CANDIDATE_SPK_SHA256`,
`MEL_CANDIDATE_METADATA`, `MEL_CANDIDATE_METADATA_SHA256`, and
`MEL_CANDIDATE_APP_HASH`; a receipt for unrelated bytes cannot become a
terminal publish receipt.

The register adapter must make its operation idempotent. On restart it receives
the identical 32-lowercase-hex nonce stored before BUILD, so
`sha256(appHash||version||nonce)` reproduces the already-registered
`releaseHash`; this is the restart-safe rule from commit `7d9108a8`.

The read adapters are deliberately separate from mutators:

- `--active-cmd`: JSONL `{pda,version,appHash}` for every Active entry.
- `--status-cmd`: one `{pda,version,appHash,status}` for the exact `$MEL_PDA`.
- `--served-cmd`: the currently served appHash only.

`cmd/list-active-releases` supports both `-app-id` (including a zero-state first
publish) and `-status-pda` (including already-Revoked success). Before a revoke,
the engine requires the exact PDA's current identity to match its durable
initial Active snapshot; after the adapter returns it requires `Revoked`.

All paths (`--wal`, `--lock-dir`, `--receipt-dir`, `--release-json`) must be
absolute and clean. The same WAL may only resume the same appId, appHash,
version, nonce override, and stale-PDA set. Artifact drift fails closed.
WAL and native JSON reject duplicate keys and trailing values. Resuming from
any advanced WAL state revalidates every cumulative native artifact and the
live Active/served boundary before the next mutation; the state label alone is
never authority. Publisher-owned state directories and no-follow regular-file
opens prevent lock/WAL/receipt symlink substitution. The per-operation cgroup
prevents an adapter descendant from surviving timeout or returning success in
the background.

## No-gap supersede property (card 0055)

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
INIT -> BUILT -> REGISTERED -> STAGED -> PROMOTED -> REVOKED -> VERIFIED -> DONE
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
