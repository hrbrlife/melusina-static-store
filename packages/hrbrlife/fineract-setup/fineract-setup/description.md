Fineract Setup is the Melusina companion wizard for Apache Fineract integration. It provisions the attached Fineract backend, walks the operator through the bootstrap workflow, and exports a signed trust bundle shared by both security gates.

## Why Fineract Setup

- **Cryptographically pinned configuration bundles** — anchor any configuration bundle to your Solana wallet; bundles are tamper-evident, citable across Pearls via Grapple, verifiable independent of the operator, and audit-ready for compliance
- **Dual-gate architecture** — configuration flows through two security boundaries: the Go HTTPS sidecar and the Java SolanaSignatureAuthenticationFilter inside Fineract; each gate validates the trust bundle independently
- **Grain-local setup isolation** — setup happens once per pearl; every Fineract instance has its own isolated configuration; no shared state; no cross-instance leakage

## Bootstrap Workflow

The wizard packages the cold-start work that has to happen before cca.sh can talk to a hardened Fineract install:

- Tenant setup
- Offices and currencies
- Chart of accounts
- Savings products
- Signer registration
- Governance policy
- Trust-bundle export

## Status

*Pre-release.* The wizard currently ships with cca.sh Admin; the live Fineract integration lands in v0.2.
