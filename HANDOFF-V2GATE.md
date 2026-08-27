# v2 store gate — historical lineage note

> **Historical source-trace note; not a release instruction.** It records a
> past v2-envelope graft and its then-live lineage. The current Store release
> rail is governed by the selected default-Bazaar source, the signed desired
> generation, on-chain checks, and the current release-provider WAL. Do not
> copy a SHA, command, signer assumption, or on-box path from this document
> into a current release. The active MSB delivery contract is
> `agentchat/scratchpad/msb-run/MSB_ONBOARDING_PRODUCT_CANON_2026-08-27.md` and
> operational facts live in `RUNSTATE.md`.

## Read this before you publish anything

**The v2 gate is a COORDINATED WIRE BREAK.** envelope v2 RENAMED the transport kind:

| wire value | v1 meaning | v2 meaning |
|---|---|---|
| `artifact` | a publish request (transport) | a DURABLE EVIDENCE RECORD |
| `publish-request` | — | the publish transport |

Source: `Melusina/shared/melusina-attest/envelope/envelope.go:42-56`, DomainTag
`melusina-attest-envelope-v2`. Its own comment: *"Same name, OPPOSITE LIFETIMES."*

**Consequence:** once the v2 gate is live, any publish signed `KindArtifact` is refused
(`check=envelope`, 401). **12 of 15 static_store worktrees still sign KindArtifact today.**
Only `feat/federated-store-mvp` and `fix/ailagoon-ceremony-envelope-v2` are v2-ok.
`self-publish.sh:131` builds `cmd/submit` from YOUR tree — gate and client must ship from the
same lineage. Rebase onto this branch before publishing. No dual-kind shim will be added (greenfield).

## Why the previous v2 seal crash-looped (proven, not inferred)

`98677f06` "separate stable operator from binding rotation" **IS** an ancestor of the live
lineage `b825ec38`; it is **NOT** an ancestor of `d81b7d9a`. Without it the binary collapses the
operator onto `key_version=3` and derives `b1a171df`; the chain pins `f7c75a13` →
`check=sidecar_identity` → crash-loop. **The ceremony abort was CORRECT.**

## Do NOT cherry-pick d81b7d9a

It is a diff against a much older base and LACKS `handleStagePublish` / `preflightAppPublish` /
`claimAppEnvelope` / `appMutationStep` — which the live 1.0.5 store REQUIRES (verified
live=1 / v2=0 for all four). Applying it wholesale REGRESSES the live store. The graft goes the
other way: the narrow v2 gate onto the live lineage. Base = `b825ec38` = the EXACT running ELF bytes.

## Honest scope — do not overstate

The live v1 gate is **NOT exploitable**. `envelope.Verify` checked the signature against the
pubkey carried *inside* the payload (self-certifying), BUT `publisherIdentityAccepted` then
requires that pubkey be allowlisted, so a forger needs a key they do not hold. v2's own comment
concedes this: *"the only reason the live gate was safe before the signer authority existed."*
v2 is real HARDENING (policy pins the signer key; the payload's claim demotes to diagnostic).
It is NOT a fix for a live hole.

## Mandatory pre-seal control (NOT yet run)

Before ANY Squads write: the candidate ELF must re-derive `f7c75a13` from the LIVE on-box shards.
`ensureShards()` silently `rand.Read()`s NEW shards in an empty dir (it only refuses a PARTIAL
set) — both off-box candidates derived WRONG identity while producing a CORRECT binary_hash.
Only the on-box shards derive `f7c75a13`. Cheap control: run the candidate against the live
config in a throwaway sandbox and watch it fail its own boot check.

R2 rollback target: `d7ddff867b0d6e6b08b60e70705721e9aac275685930dd508bb87594339c1862`.
NEVER side-load (hand-cp + systemctl bricked it 2026-07-13). Use `apply-store-update`, which
verifies sha == on-chain Active BEFORE placing. Live ELF path is `/usr/local/bin/melusina-store-sidecar`
(the runbook's `/var/lib/melusina-store` path is WRONG).
