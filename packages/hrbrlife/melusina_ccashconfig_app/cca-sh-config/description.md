cca.sh Config is the admin pearl for the cca.sh / popaye operator console. One install gets one Config pearl; it owns the procedure-template registry, the hook allowlist, the cross-pearl case index, and the routing policy that every cca.sh sibling pearl claims via Grapple at boot. Operators never edit ccash code to change product behavior — they edit YAML templates served from this pearl.

## Why cca.sh Config

- **Pinned procedure-template versions** — every YAML template the admin serves is hash-anchored at the moment a case starts. The case's evaluation against template-vN is tamper-evident, citable across Pearls via Grapple, and survives operator audits independent of who's running the install.
- **Hook allowlist as fail-closed boundary** — every typed event a procedure can fire is enumerated in a manifest the admin loads at boot; anything outside the allowlist is rejected at the Cap'n Proto boundary, not at a sidecar's discretion. No silent webhook spawn, no dynamic event routing.
- **One-install-one-license** — the admin pearl is the per-license boundary; every cca.sh sibling pearl in the install (popaye operator, client seat, tradechain operator/vendor/buyer) Grapple-claims this single offerable. Revocation, audit, and policy live in one place.

## Status

**v0.0.10 — pearl-onboarded.** Live on Solana devnet, 3-of-4 Core App Team Squads quorum, canonical foundation master `B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe`. AdminGate Cap'n Proto offerable (`@0xa7c4d2e91b8f5634`) is served on FD 3 — sibling ccash Pearls (popaye + the cca-tc-* tradechain variants) Powerbox-claim it at first boot and import the bindings via `go.mod replace` for compile-time wire stability. See `RELEASE.json` and `changelog.md` for the on-chain attestation and per-release notes.
