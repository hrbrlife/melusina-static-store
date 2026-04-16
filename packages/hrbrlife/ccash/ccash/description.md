**ccash** is a mobile-first operator console for an MSB / PSP / VASP back office.

A polished UI for managing wallets, contacts, and money movement. Contacts are identity only — no stored payment instruments — and every transaction passes through an approval gate that mints one-time settlement instructions. Every state change is signed with a Solana Ed25519 key and recorded in an encrypted SQLite audit log.

KYC, sanctions screening, and AML workflows are handled by sibling grains — ccash assumes every counterparty already has KYC done elsewhere.

Built in Go + HTMX as a Sandstorm grain. Beige on soft brown. Fraunces headings, Inter body, Inter Tight tabular numerals.
