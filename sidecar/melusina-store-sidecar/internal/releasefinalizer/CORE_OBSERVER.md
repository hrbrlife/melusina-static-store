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
4. After the real execution, the finalizer must materialize the complete
   `RELEASE.json` using the observed `registered_at`, original author signature
   and independently checked authority. The canonical provider currently keeps
   `RELEASE.json` provisional until `ApplyEntryToManifest` after execution.
   Therefore the preparation adapter cannot freeze a purported final timestamp
   before it exists. The current finalization-input schema expects a complete
   final descriptor; its explicit prepared-state-to-final-descriptor join is
   still required before a native composition can run.
5. Compose the observer/runner/mTLS handler with the fixed artifact vault,
   publisher-envelope Unix custody and worker result key; then bind existing
   Store Link and private Store control routes. Store policy, Pearl routing and
   human keys, app/publisher grants, worker certificates/leaf pins, listing
   custody and tenant proof still require governed provisioning. Store remains
   the independent publisher, chain, predecessor, runtime and listing verifier.

The SDK fixture generator is offline and pins `@sqds/multisig` 2.1.4 plus
`@solana/web3.js` 1.98.4. It uses explicit public test seeds and serializes real
SDK account layouts; no test fixture is a production authority or receipt.
