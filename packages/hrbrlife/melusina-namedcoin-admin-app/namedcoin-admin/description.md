**NamedCoin Admin** is the operator console for the NamedCoin KYC system.

Review incoming KYC packets (ID photo, OCR, doc-authenticity, face-match, sanctions-screen results), configure the consumer-trust list that tells Melusina which other licenses' attestations this license accepts, build unsigned Solana instructions for issue / revoke / trust-edit so an install admin can sign them in their browser, and inspect any user wallet's live attestation state via the built-in KYC Inspector.

Companion grain for per-user onboarding: melusina-namedcoin-app (the Pearl).

Raw ID documents and questionnaire answers never leave the pearl's encrypted store. Nothing but Merkle roots, hashes, and enum values land on-chain or in the admin audit log.

Built in Go with HTMX + vanilla templates. Melusina grain.
