# Changelog

## 0.1.1 — 2026-06-04

NM-1…NM-5 four-eyes KYC attestation ceremony (publishable cut):

- NM-1: maker/checker write surface around `foureyes.Store`
- NM-2: KYC-attestation signer retargeted from sidecar hot-key to offline-sign/Squads (`pkg/offlinesign`, signer at offline-sign-server.mjs:3848)
- NM-3: `POST /admin/foureyes/signed-open` — VerifyEnvelope-authenticated cross-grain handoff (admin side)
- NM-5: Go anchor_client instruction builders for KYC-issuer provisioning (`authorize_kyc_issuer`, `designate_install_admin`, `update_install_admin_permissions` / PERM_KYC_ISSUE bit30) + PDA-marker fix for on-chain derivations
- On-chain ceremony executed on devnet (MINT=HWuU): LicenseEntry 9WJ9Qf, KycIssuerAuthority 5Z7SkXw, InstallAdminEntry GubeRbZ all Active; attestation AbU56Rj minted for subject end-client-eve

## 0.1.0 — 2026-04-21

Phase 1 + 2 scaffold:

- Ccash htmx+Go design layer forked wholesale (197 Go files, static/, templates/)
- Ccash-specific financial-services packages stripped (wallets, transactions, cards, projects, contacts, currency, fees, finreact, fxrates, iban, ledger, money, payintent, reconciliation, station)
- `pkg/users` → `pkg/operators`; `pkg/approval` → `pkg/kyc`
- KYC step subpackages stubbed: id_upload, liveness, ocr, doc_auth, face_match, questionnaire, sanctions_screen, attestation
- Signature/docusign flow removed from spec per kill list

Product implementation for the 4-eyes review + on-chain NFT-issuance dispatch to follow.
