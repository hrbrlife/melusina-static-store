**popaye** is a mobile-first operator console for an MSB / PSP / VASP
back office, packaged as a single Sandstorm grain. One pearl = one
client account = one customer.

## Three actors, one pearl

Every popaye install is shaped by three parties:

- **Wholesale platform operators** (the "ccash" side) run the
  underlying rails, custody, and compliance siblings.
- **The white-label brand** (e.g. popaye, paype, or any operator's
  own brand) configures the site profile — name, currencies, fees,
  legal entity, FAQ — by dropping a `/var/site-profile.json` into
  the grain. Same binary, different brand.
- **End clients** (the actual MSB customer whose name is on the
  account) hold the `client` role and are the only people who can
  approve money movement on their own client account. Operator staff
  draft; the client signs.

Seven built-in roles sit on top of that split: **admin**,
**collaborator**, and **auditor** on the operator side; **client**,
**client_assistant**, and **client_view_only** on the customer side;
and **whitelabel_oversight** for the white-label brand team —
pseudonymous, view-only across operational metrics, never end-client
PII.

## Load-bearing safety properties

- **No stored payment instruments.** Contacts are identity only —
  name, country, tax ID, contact details. No IBANs, no card masks,
  no crypto addresses on file. Every transaction mints its own
  one-time settlement instructions at approval time and they expire
  in 48h. This is enforced by an architectural test, not a guideline.
- **Solana signature on every write.** Every user must complete a
  wallet-signature onboarding handshake before any state change
  is accepted. Every audit row carries a base58 Ed25519
  `SignerPubkey`. There is no legacy / unsigned / grandfathered
  path.
- **Two independent signature gates** in front of the Apache
  Fineract core: a Go sidecar and a Spring Security filter inside
  the Fineract JVM, both verifying the same canonical payload
  against the same registered-pubkey registry.
- **Encrypted SQLite at rest.** Single `/var/grain.db.enc`,
  envelope-encrypted with a per-pearl wallet-anchored keybox.
- **Compliance is somebody else's job.** KYC, sanctions screening,
  AML rules, SAR drafting, and Travel Rule marshalling live in
  sibling DueProcess Station grains reached over Cap'n Proto
  Grapple capabilities — never via HTTP, never inside this pearl.

## What's in the box

| Surface | What it does |
|---|---|
| Dashboard | Total balance, quick actions, recent activity, role-tailored boot view |
| Wallets | Multi-currency wallets across fiat, stablecoin, crypto, and devnet tokens |
| Contacts | Identity-only directory of counterparties |
| Send / Receive | Four-step wizards with risk-tiered OTP approval |
| History | Filterable transaction log with full per-transaction timeline |
| Cards / Projects / Recurring / Requests | Light back-office surfaces |
| Audit log | Every state change signed and persisted |

## Stack

Go 1.25 + HTMX, raw Cap'n Proto WebSession (no http-bridge), no
JavaScript build step, no Tailwind, no Node. Single static binary,
single `.spk`. Mobile-first responsive HTML/CSS — Sandstorm owns
the PWA wrapper above the pearl.

## Licensing

Source-available under the Melusina Public License v1.0. White-label
deployments are negotiated separately with the wholesale platform
operator.
