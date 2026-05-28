cyberteller is a multi-chain crypto payment processor for Melusina. Create invoices, generate unique payment addresses per chain, track payments in real-time, and settle crypto across Ethereum, Tron, Solana, and TON.

## Why cyberteller

- **Pinned invoice + settlement chains** — cryptographically anchor any invoice and its settlement chain to your Solana wallet; records are tamper-evident, citable across Pearls via Grapple, and compliance-ready
- **Address non-reuse by HD-wallet derivation** — every invoice gets a fresh address derived via BIP-39/BIP-32 (secp256k1) and SLIP-0010 (ed25519); no address reuse; no payment correlation; privacy by design
- **YAML-driven, restart-free configuration** — edit chains, tokens, expiry, and tolerance thresholds via the admin UI; changes take effect immediately; no deployment cycles

## Features

- **Multi-chain support** — Ethereum, Tron, Solana, TON
- **Crypto & stablecoins** — ETH, TRX, SOL, TON native coins + USDT/USDC on every supported chain
- **Invoice API** — create invoices via REST with amount, currency, description, and customer details
- **Payment page** — customer-facing page with QR codes and copy-address buttons; auto-refreshes
- **Payment status tracking** — paid / underpaid / overpaid / expired
- **Webhook endpoint** — integrate blockchain monitoring services for real-time settlement notification
- **Admin panel** — dashboard, invoice detail view, live YAML config editor
- **SQLite storage** — zero external dependencies; fully offline-capable

## Status

*Pre-release.* The pearl currently installs as a Coming Soon stub; the live payment processor lands in v0.2.
