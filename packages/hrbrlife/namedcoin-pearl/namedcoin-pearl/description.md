**NamedCoin — Identity Attestation** is the biometric KYC pearl for Melusina PSP.

Pass identity verification once — including tilt-to-capture liveness detection, document OCR, and sanctions screening — and receive a time-boxed on-chain NFT attestation on Solana devnet. Every Melusina app that needs "is this person KYC'd?" probes the attestation through the NamedCoin-sidecar.

Raw ID images, biometric captures, and questionnaire answers never leave the pearl's encrypted Sandstorm grain store. What lands on-chain is a Merkle root over salted (key, value) claim leaves; apps verify individual claims (e.g., "residence is FR", "age >= 18") with a selective-disclosure Merkle probe.

## Features
- **Biometric liveness**: Tilt-to-capture with camera, selfie, and document photo
- **Document OCR**: Extracts name, DOB, document number from uploaded ID
- **Sanctions screening**: Integrated OpenSanctions-sidecar check during receive
- **On-chain attestation**: Merkle-rooted NFT mint on Solana devnet with configurable expiry (90/180/365 days)
- **Selective disclosure**: Individual claim verification without exposing raw data
- **Admin review**: KYC packet approval, attestation issuance/revocation
- **Cross-server probe**: HMAC-signed Merkle verification across Melusina nodes

## Architecture
- **Grain**: NamedCoin-pearl (Go + HTMX, Sandstorm grain)
- **Sidecar**: NamedCoin-sidecar (Go, HTTP API on port 9100)
- **Admin grain**: melusina-NamedCoin-admin-app (separate grain)
- **Dependencies**: ailagoon-sidecar (LLM), OpenSanctions-sidecar (screening), mermail-sidecar (email OTP)

Built in Go with HTMX + vanilla templates. Sandstorm grain with HTTP-out to the NamedCoin, ailagoon, OpenSanctions, and mermail sidecars.
