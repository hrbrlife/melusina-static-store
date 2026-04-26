TeleScreen is the screening Pearl of the Melusina ecosystem — sanctions lists, adverse-media checks, on-chain wallet risk, and PEP / AML compliance probes, all wrapped in a single Pearl with signed configuration, Grapple-scoped grants, and per-Pearl isolation. A complete install is three Pearls across two SPKs: a REST/JSON sidecar, an HTMX admin + member core Pearl (both in this SPK), plus the setup Pearl shipped as `telescreen-companion.spk` separately. Setup signs the trust bundle; core consumes it; sidecar verifies and serves.

## Why TeleScreen

- **Pinned screening-result snapshots** — every screening result (sanctions hit, adverse-media match, on-chain risk score) is pinned to the requesting Pearl's Solana wallet at the moment of issuance. Compliance teams later cite "this counterparty was OFAC-clean as of date X per a wallet-rooted, tamper-evident attestation" — not "our SaaS vendor told us so once and we trust the dashboard"
- **Per-screening-config Pearl isolation** — each screening list (custom OFAC profile, internal blocklist, partner-specific PEP set) lives in its own sealed Pearl with signed configuration. A breach or misconfiguration in one list cannot leak into another; revoking access to one does not impact the others. Melusina-shipped permission isolation, not application-layer ACLs
- **Grant-validated capability surface** — consuming Pearls (cca.sh, NamedCoin, Bureau apps doing client-onboarding) request screening via Grapple with scoped grants — "ai-text" / "ai-vision" / "screening-sanctions" / "screening-adverse-media". The grant is verified against the signed trust bundle at the Cap'n Proto boundary; bypass requires forging the bundle's cryptographic root, not sidecar credentials

## Architecture

- **REST/JSON sidecar** — sanctions + adverse-media + blockchain-risk APIs over signed gRPC
- **HTMX admin + member core Pearl** — bundle authoring, list management, partner-trust editing
- **Setup Pearl** (separate SPK: `telescreen-companion.spk`) — signs the trust bundle distributed to consumer Pearls

Deployment is `spk dev` / `spk pack`. Docker / direct system service paths are out of scope for the polished MVP.

## Status

*Pre-release v0.1.1.* REST surface + sanctions screening live; adverse-media and on-chain wallet-risk integrations follow in v0.2.
