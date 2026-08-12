# melusina-Solana-primitives

Thin shared Go package with Solana helpers that both
`melusina-identity-gate` (HTTP-level authorization) and
`grain-e2e-binding` (per-grain DEK wrapping) import. Exists so the
two modules never drift on Solana-side primitives.

Scope is intentionally narrow:

- **base58** — Bitcoin-alphabet codec matching the Solana wire format.
- **PDA derivation** — `FindProgramAddress`-shaped helpers for every
  Melusina PDA (InstallAdminEntry, OrganizationMemberEntry,
  LicenseEntry, GlobalAppApproval, ResellerAppApproval, LocalAppApproval,
  GlobalSidecarApproval, ResellerSidecarApproval, LocalSidecarApproval,
  ContractWhitelist, AppContractPair, DomainClaim).
- **Ed25519 thin helpers** — type aliases + base58 round-trip utilities.

Non-goals:
- **No JSON-RPC client.** Solana RPC lives in each service's
  HTTP-client layer or in `melusina-identity-gate/verify`.
- **No Borsh decoders for PDA account data.** Each consumer decodes
  the fields it cares about; this package does not pin the struct
  layouts. Layout drift is caught by on-chain integration tests, not
  by shared code.
- **No transaction construction.** TypeScript / Anchor-IDL flows own
  that; this package is for read-side PDA derivation only.

## Why not just duplicate in each consumer

Two reasons:

1. `InstallAdminEntry` seeds must match `grain-e2e-binding`'s DEK
   derivation AND `melusina-identity-gate`'s verifier. A byte diff
   between the two produces silent authorization bypass. Sharing the
   seed function eliminates the class.
2. base58 encoding differences (leading zero handling, empty string
   semantics) have historically been a source of Solana interop bugs.
   One implementation, one test suite, two consumers.
