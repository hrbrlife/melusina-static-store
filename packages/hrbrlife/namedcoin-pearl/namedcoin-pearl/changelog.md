# NamedCoin — Identity Attestation Changelog

## v0.1.0 (2026-05-27)

- Initial release of namedcoin-pearl
- Biometric capture UI with tilt-to-capture liveness detection
- Document upload with OCR (name, DOB, document number extraction)
- Contact verification (email + phone OTP via mermail-sidecar)
- Sanctions screening integration (opensanctions-sidecar)
- On-chain NFT attestation on Solana devnet (Merkle-rooted claims)
- Selective-disclosure Merkle probe for individual claim verification
- Cross-server HMAC-signed probe subsystem
- Admin review workflow (approve, revoke, freeze attestations)
- AiLagoon integration for document-authenticity and face-match checks
- Sandstorm grain with bridgeConfig (Owner/Applicant/Viewer roles)
- AdminGate.ProcessExecutor export for DueProcess case routing
- Powerbox manifest for sidecar access (namedcoin, ailagoon, opensanctions, mermail)
- UiView tab configuration (Biometric, Document, Contact, Status, Result)
