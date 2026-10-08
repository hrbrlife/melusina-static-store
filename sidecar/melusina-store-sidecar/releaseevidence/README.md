# Original selected Core release evidence

This public Go adapter lets an independent worker reuse the existing strict
RELEASE decoder and `CoreProposalObserver`. It adds no alternate parser,
signer, RPC relay, proposal executor, Store writer or source authority.

The service provisions `NewCoreVerifier` with a fixed bare HTTPS RPC origin and
the independently selected original four Core member keys. Registry, Master
NFT, release author, Core multisig, index-zero vault and three-of-four policy
remain fixed by the original observer. A request cannot replace them.

`VerifySelectedRelease` takes the selected app ID, signed catalog-pointer stage
context, the retained original VaultTransaction PDA as a **locator**, and the
original complete RELEASE bytes. It strictly checks the original descriptor,
including exact field names, nonce-derived release hash and authority claims.
It reads the finalized transaction to derive the proposal digest, then invokes
the original observer to re-read the immutable transaction and an atomic
finalized Core/proposal/ReleaseEntry cohort. Exact instruction privileges,
PDAs, author signature, original member set and votes, executed state,
registration time and active release checks are unchanged.

The result must match the original descriptor's author signature, observed
registration time, ReleaseEntry PDA, vault, Master NFT and complete quorum.
Prepared or pending state cannot return a successful selected observation.
Every retry reads chain state again; a revoked release is refused. Original
public artifact bytes are neither rewritten nor signed again. Stage ID is
catalog context and is never described as an on-chain field.

The caller still independently verifies the selected Store/operator pointer,
listing and artifact tuple, actual SPK signature, metadata and runtime binding,
and historical source reproduction before assigning any source baseline. In
particular the older author payload does **not** sign runtime-contract fields;
the caller must compare those with the authenticated source template and
actual package facts. This adapter never accepts a saved successful-proof
object or returns source/publication authority.

`VerifySelectedArtifacts` independently checks the original operator pointer
against installed operator/domain scope, exact index bytes and its unique app
row, actual SPK/metadata canonical app hash, original RELEASE identity and
runtime declarations. It reuses the Store's extracted `catalogselection`
pointer message/signature implementation and existing app-hash/runtime
validators. The serving Store still performs its own fresh chain listing and
revocation checks; this read-only verifier does not replace them.

The pointer implementation is shared with normal Store signing and serving,
so workers do not carry a divergent copy. JSON duplicate/alias refusal also
remains shared. Typed array members preserve their exact field names. These
artifact checks authenticate the selection only; original executed Core,
actual SPK signature and exact source reproduction are separate requirements.
