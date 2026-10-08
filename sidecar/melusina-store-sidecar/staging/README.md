# Original private-stage contract

This package is the shared implementation used by the actual Store stage
handler and original submit client. `StageID` preserves their existing framing:
SPK and metadata hashes, optional tagged runtime-contract hash, release intent,
version and master hashes, and length-framed catalog locator components.
Provisional/final RELEASE byte changes and registration timestamps never alter
the stage identity. Original candidate, runtime, version and locator validation
still happens before this pure calculation in both callers.

`ReceiptMessage` and `VerifyWithAuthority` are the original private-stage
signature format and cryptographic check. `VerifyExpected` additionally binds
all returned tuple fields to the candidate fixed before staging. Callers must
obtain the active Store operator key and domain independently; the original
submit client's `receiptAuthority` still performs that chain check. A receipt
is private persistence evidence, with no Core execution or publication claim.

The public API makes these same operations available to the forthcoming
preparation challenge and Pearl command round trip without copying a parser or
hash algorithm. It does not add a staging endpoint or silently redirect Bazaar
preparation to the legacy `/publish/stage` route. The governed prepare endpoint
still requires its original exact Pearl command and active PREPARE grant.

Tests include the actual retained Welcome 0.1.31/v32 stage identity
`96c1af0e2835344d11b2ed3d97e84c38c82d85630e323c7017abd0ab25120178`,
every bound input, locator framing and independent authority/domain/candidate
refusals. That retained public tuple proves compatibility only; it is not
accepted as current source or publication authority.
