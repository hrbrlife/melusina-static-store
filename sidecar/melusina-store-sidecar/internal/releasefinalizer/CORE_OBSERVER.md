# Default Bazaar release observer

`NewCoreProposalObserver` is the production, read-only `ProposalObserver` for
the existing finalizer. Its only remote operation is `getMultipleAccounts` at
`finalized` commitment. The service configuration supplies one bare HTTPS RPC
origin and the independently provisioned four original Core member public
keys. Jobs cannot supply an endpoint, program, member, signer, instruction or
transaction to execute. Environment proxies and redirects are disabled.

The observer fixes the original default-Bazaar authority:

| Binding | Public identity |
| --- | --- |
| Registry | `7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb` |
| Master NFT | `B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe` |
| Squads v4 | `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf` |
| Core multisig | `4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V` |
| Index-0 vault | `3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3` |
| Release author | `ARX39MQQR1c7cT8L9ARbeg7AWw975gPGr9EE9oygKv1P` |

The release author matches the existing governed provider's accepted public
ceremony state. It is a separate authority check from the three-of-four votes.
The observer owns no private key and cannot create, approve or execute a
proposal. The Core member set must match the independently configured four
keys, the live threshold must remain three, and the stored creator must have
the original Core initiation permission.

## Preparation and browser digest contract

`ProposalReference` is the canonical base58 **VaultTransaction PDA**. The
corresponding Proposal PDA is derived from its parsed Core multisig/index.
`RegisterProposalDigest` computes lowercase hex SHA-256 over this exact byte
sequence:

```
UTF8("bazaar-control-register-release-proposal-v1\0")
|| Squads program public key (32 bytes)
|| VaultTransaction PDA (32 bytes)
|| complete immutable VaultTransaction account data
```

The preparation adapter and browser verifier must use those same bytes after
strictly verifying the account owner/PDA and exact register instruction. They
must not hash a reserialized JSON view, mutable Proposal votes/status, a
transaction signature, or an arbitrary receipt string. The preparation result
and stable human authorization separately commit the exact stage, candidate,
Store, app/release, predecessor and policy/grant. A stage identifier has no
on-chain field; the observer retains that already-bound context without
claiming to observe a private Store stage on Solana.

Discovery reads one account. A second, atomic finalized read obtains that same
immutable transaction, Core multisig, derived Proposal, and derived
ReleaseEntry with `minContextSlot` from discovery. The transaction bytes must
remain identical. Exactly one `register_release_entry` instruction is allowed,
with its canonical account privileges, no address tables or ephemeral signers,
and an independently verified release-author signature. The executed proposal
must have three valid Core votes and the matching Active ReleaseEntry must
contain the exact registered payload, authority, timestamp and PDA bump.

The finalizer compares the returned registration time, original author
signature, Master NFT, vault, multisig and quorum with the complete final
`RELEASE.json` before calling publisher-envelope custody. Unknown descriptor
fields, aliases and duplicates remain refusals. Exact retries re-read current
finalized accounts; there is no success cache that can conceal revocation.

## Immutable preparation to final descriptor

`bazaar-control-finalization-input-v2` carries `ceremonyB64`: the original full
`melusina-release-ceremony-v1` author state emitted by the governed provider.
It must omit `releaseB64`. The existing v1 input still accepts and preserves
complete final `RELEASE.json` bytes through `releaseB64`, and must omit
`ceremonyB64`. These are explicit alternatives; unknown, duplicate, aliased,
null and mixed-state fields are refused before decoding. The original
ceremony's nullable empty Ed25519 instruction account list is the one explicit
schema-defined null exception.

The prepared state includes its actual author signature and payload hash,
app/version/nonce, Master NFT, vault/quorum, registry, derived transaction and
Proposal PDAs, and the exact Ed25519 and register instructions. Each account
privilege and instruction byte is checked against the signed payload. The
author's `dry-run-prepared` status remains preparation context and cannot
assert chain execution. The worker retains the exact original ceremony bytes
in the approved content-addressed input; it verifies that input's hash again
when loading it. Candidate bytes, metadata, app hash and runtime contract are
revalidated before any chain observation.

After the fixed observer proves real execution, `Input.WithRegistration`
compares the prepared transaction, registry, author public key, payload hash,
original signature and authority with that observation. It creates a separate
complete descriptor using the observed `registered_at`, never `createdAtUnix`.
The runtime digest comes from the reviewed input and is rechecked against the
candidate; runtime claims are not represented as part of the older on-chain
author-signature payload. Only the final descriptor bytes enter publisher
custody and the final sidecar body. No original input, ceremony, request digest
or human authorization is rewritten. Pending work cannot export a final
descriptor or call custody; exact restart repeats the chain verification and
materializes identical descriptor bytes from identical observed facts.

## Remaining production composition

This source provides the actual chain observer, not a deployed worker or a
browser publication entrance. Complete the existing seams in this order:

1. The trusted build worker must run provisioned, named MSB source/profile
   builders with separate package custody and two independently signed
   source-to-package observations. Local verification SPKs do not replace it.
2. The constrained preparation adapter must verify that candidate and the
   selected predecessor, privately stage it, and create only its unexecuted
   register proposal. It freezes the original author-signed ceremony state and
   the digest above. It must not execute Core or return an expiring final
   publisher envelope before the human decision.
3. The browser flow must review and sign/execute that exact original Core
   three-of-four proposal. The existing Bazaar Control detached stable
   authorization form is a separate policy-bound human signature; attaching
   it does not execute Squads. There is currently no built-in Core browser
   execution join in that Pearl.
4. The preparation adapter must produce the v2 input above after its exact
   transaction index/PDAs are fixed. It retains the canonical author's prepared
   state rather than freezing a purported final timestamp. The finalizer's
   implemented observer/materializer then joins that state to real execution,
   following the existing `ApplyEntryToManifest` registration-time semantics.
5. Compose the observer/runner/mTLS handler with the fixed artifact vault,
   publisher-envelope Unix custody and worker result key; then bind existing
   Store Link and private Store control routes. Store policy, Pearl routing and
   human keys, app/publisher grants, worker certificates/leaf pins, listing
   custody and tenant proof still require governed provisioning. Store remains
   the independent publisher, chain, predecessor, runtime and listing verifier.

The SDK fixture generator is offline and pins `@sqds/multisig` 2.1.4 plus
`@solana/web3.js` 1.98.4. It uses explicit public test seeds and serializes real
SDK account layouts; no test fixture is a production authority or receipt.
