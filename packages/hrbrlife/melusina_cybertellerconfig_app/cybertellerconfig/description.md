Cyberteller Config is the admin pearl for the Cyberteller crypto-payment sidecar. One install gets one Cyberteller Config pearl; it owns the allowed-payment-rail registry, the per-rail fee-cap policy, and the operator-role allowlist that every Cyberteller pearl in the install reads at boot. Operators never edit Cyberteller code to change which chains, which providers, or which fee ceilings apply — they edit policy served from this pearl.

## Why Cyberteller Config

- **Pinned payment-rail policy** — the allowed-rails set (chains, address schemes, settlement providers) is hash-anchored to your Solana wallet at the moment a Cyberteller pearl claims it. The pearl's invoice-creation flow against rails-vN is tamper-evident, citable across grains via Grapple, and survives operator audits independent of who's running the install
- **Fee-cap enforcement as fail-closed boundary** — every fee schedule a Cyberteller pearl can quote is enumerated in a manifest the admin loads at boot; anything outside the cap range is rejected at the Cap'n Proto boundary, not at a sidecar's discretion. No silent over-fee, no out-of-band rail
- **One-install-one-license** — the admin pearl is the per-license boundary; every Cyberteller sibling pearl in the install (operator desk, customer invoice view) Grapple-claims this single offerable. Revocation, audit, and policy live in one place

## Status

*Pre-release v0.0.1.* Scaffold + welcome page. The Cap'n Proto AdminGate offerable lands at v0.1.0 alongside the live Cyberteller invoice-creation surface; until then the policy-runtime handshake from sibling Pearls is stubbed.
