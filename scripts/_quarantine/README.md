# Quarantined publish writers (kill-list K07/K12)

These scripts wrote per-app `RELEASE.json` directly into the catalog tree with a
**different Squads vault/multisig** than the canonical core-app-team authority, and
had **zero callers** — a single accidental run could clobber the whole fleet's
attestations with the wrong identity. They are kept here for reference only.

- `pearl-ceremony.sh` — bulk catalog-wide re-signer; hardcoded vault `5SmcSBsuaa…` /
  multisig `9X5ECjTM…` (NOT the canonical `4sPNmdcSz…`). Wrote `$ROOT/<repo>/<slug>/RELEASE.json`
  directly, no `/tmp` staging, no COPY gate.
- `welcome-pearl-ceremony.sh` — single-app variant of the same.

**Canonical signer:** `scripts/pearl-app-ceremony.sh` (core-app-team 3-of-4
`4sPNmdcSz…`), which stages to `/tmp` and copies one RELEASE.json per app. Do not
resurrect these without reconciling to the single Squads identity (K12).
