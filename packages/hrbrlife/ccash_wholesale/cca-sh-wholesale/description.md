cca.sh Wholesale is the institutional Pearl of the cca.sh constellation. It owns the four correspondent relationships — SWIFT, SEPA, crypto-custodian, crypto-exchange — at the Fineract / sidecar boundary, and grants per-sub-account capabilities to whitelabel-partner operator Pearls (the popaye / cca.sh-Admin family) over Grapple. End-clients never see this Pearl directly; their operator sees it as a Grapple-grant of "settle this envelope to that correspondent at this rate".

## Why cca.sh Wholesale

- **Pinned settlement envelopes** — every settlement request is signed at draft time, pinned to the operator's Solana wallet at approval time, and recorded as an immutable, citable artifact. Disputes between wholesale and a whitelabel partner are resolved against the signed envelope, not a database row that either side could mutate
- **Per-correspondent Grapple capability scoping** — a whitelabel partner's operator Pearl claims a sub-account capability scoped to one correspondent + one rate sheet. They cannot see other partners' correspondents; they cannot escalate to the wholesale-admin role; they cannot enumerate the full correspondent topology. Capability surface is enforced at the Cap'n Proto boundary, not at a SaaS endpoint
- **Operator-accountability through wallet signatures** — every wholesale-admin action (correspondent CRUD, rate-sheet edit, sub-account grant) is non-repudiable; the wholesale operator's Solana wallet signs the change. The audit log is provably theirs, not a vendor-database table they can claim was tampered with

## Topology

```
G-ccash Wholesale (this Pearl) ─── grants sub-account caps ──▶ G-organization (whitelabel partner)
     │                                                                   │
     ▼                                                                   ▼
finreact-sidecar                                                  G-popaye (operator console)
     │                                                                   │
     ▼                                                                   drafts sends
Fineract GL                                                       emits envelopes
```

## Status

*Pre-release v0.2.0.* The institutional correspondent surface and sub-account grant flow are scaffolded; first end-to-end SWIFT settlement against the live finreact-sidecar lands in v0.3.
