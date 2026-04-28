Teleport is a Sandstorm-native chat grain with browser-side end-to-end field encryption. The server stays blind: encrypted messages are stored as `E2E1:<base64>` envelopes that the host never decrypts. Mixed-mode is supported, so plaintext and encrypted chat coexist as the operator chooses.

## Why Teleport

- **Server-blind E2E** — AES-256-GCM with a single DEK derived per browser session; the host stores opaque envelopes only
- **Per-grain isolation** — each Teleport grain is its own sealed Sandstorm container with its own SQLite database, members, and permissions
- **Role-aware permissions** — admin, collaborator, auditor, client, assistant, and public-viewer roles map to a six-bit permission set from the bridgeConfig
- **No third-party trust** — no external chat backend; messages stay on your Sandstorm instance
- **Wallet-rooted release attestation** — every release is anchored on Solana via a Squads-signed ReleaseEntry; the appHash on-chain has to match the SPK byte-for-byte

## Features

- **Session-scoped E2E encryption** — single DEK per browser session, AES-256-GCM, server-side blind
- **Per-user public keys** — directory of registered public keys for future per-recipient envelope wrapping (see `docs/CHAT_E2E.md` §7 future work)
- **GraphQL API** — `insertMessage`, `listMessages`, `upsertUserPublicKey`, `getUserPublicKey` over `/api/graphql`
- **Better-sqlite3 storage** — local file-backed database inside the grain
- **Six-role permission set** — admin / collaborator / auditor / client / assistant / public viewer

## Status

Teleport is the chat-only MVP carved out of the INSTASYS KYC platform. The full multi-grain platform (client / instance / manager / client-ui-manager grain types, panel execution, wallets, screening, AI enrichment, static publishing, identity, telemetry) was stripped from this build. The four grain-action entries in the SPK manifest reflect the original four-grain shape; only the chat path is wired in this MVP.

This release is for human testing and development. **Not production-ready**: chat E2E uses one DEK per browser session — no forward secrecy, no per-message DEK, no NaCl-box wrapping per recipient. See `docs/CHAT_E2E.md` for the threat model and the future-work notes.
