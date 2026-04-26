cca.sh Config is the admin Pearl for the cca.sh / popaye operator console. One install gets one Config Pearl; it owns the procedure-template registry, the hook allowlist, the cross-Pearl case index, and the routing policy that every cca.sh sibling Pearl claims via Grapple at boot. Operators never edit ccash code to change product behavior — they edit YAML templates served from this Pearl.

## Why cca.sh Config

- **Pinned procedure-template versions** — every YAML template the admin serves is hash-anchored to your Solana wallet at the moment a case starts. The case's evaluation against template-vN is tamper-evident, citable across Pearls via Grapple, and survives operator audits independent of who's running the install
- **Hook allowlist as fail-closed boundary** — every typed event a procedure can fire is enumerated in a manifest the admin loads at boot; anything outside the allowlist is rejected at the Cap'n Proto boundary, not at a sidecar's discretion. No silent webhook spawn, no dynamic event routing
- **One-install-one-license** — the admin Pearl is the per-license boundary; every cca.sh sibling Pearl in the install (popaye operator, client seat, org member) Grapple-claims this single offerable. Revocation, audit, and policy live in one place

## Status

*Pre-release v0.0.1.* Scaffold + welcome page. The Cap'n Proto AdminGate offerable lands at v0.1.0 alongside ccash kill-list M1; until then the procedure-runtime handshake from sibling Pearls is stubbed.
