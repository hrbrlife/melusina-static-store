# DueProcess v32, welcome-pearl, ai-lagoon — CDN Cross-Verification

**Date:** 2026-05-30  
**CDN base:** `https://hrbrlife.github.io/melusina-static-store`  
**Local catalog:** `src/apps.json` (43 apps)  
**Live CDN catalog:** `apps/index.json` (43 apps)

---

## Results Table

| app_name | expected_pkgId | local_catalog_pkgId | CDN_pkgId | match? | releaseEntryPda | is_offline_stub? | SPK_CDN_200? | sha256_match? |
|---|---|---|---|---|---|---|---|---|
| **DueProcess** v32 | `f429990a...` | `f429990a4a19022f4d7659950611df54` | `f429990a4a19022f4d7659950611df54` | ✅ YES | `3LxUbMJZm6QXQgXdEFHtwh4FX9pco2aigTtARC6dJP6v` | ❌ No (real on-chain) | ✅ HTTP 200 | ✅ YES |
| **AiLagoon** v23 | `f8b9f972...` | `f8b9f972fa8312047e861381f8b57092` | `f8b9f972fa8312047e861381f8b57092` | ✅ YES | `34ZY5nAhjaJvV36ua4QEaa9H4oSH9JQV1KWjEvJDWr9X` | ❌ No (real on-chain) | ✅ HTTP 200 | ✅ YES |
| **Welcome pearl** v7 | `40f5a487...` | `40f5a4873fc10723cb8375ca25251dd8` | `40f5a4873fc10723cb8375ca25251dd8` | ✅ YES | `8UmaX2AoJhY1SQEWaaHWQdSh59TA9B6eMnuGWtGxf8dy` | ❌ No (real on-chain) | ✅ HTTP 200 | ✅ YES |

---

## Detailed Findings

### 1. DueProcess v32 — ✅ ALL GREEN

| Field | Local | CDN | Match |
|---|---|---|---|
| packageId | `f429990a4a19022f4d7659950611df54` | `f429990a4a19022f4d7659950611df54` | ✅ |
| sha256 | `f429990a4a19022f4d7659950611df5426d870b5ed4da022280cde142ac95e59` | `f429990a4a19022f4d7659950611df5426d870b5ed4da022280cde142ac95e59` | ✅ |
| versionNumber | 32 | 32 | ✅ |
| marketingVersion | 0.1.28 | 0.1.28 | ✅ |
| releaseEntryPda | `3LxUbMJZm6QXQgXdEFHtwh4FX9pco2aigTtARC6dJP6v` | `3LxUbMJZm6QXQgXdEFHtwh4FX9pco2aigTtARC6dJP6v` | ✅ |
| signedAtUnix | 1779579984 | 1779579984 | ✅ |
| SPK on CDN | — | HTTP 200, `application/octet-stream` | ✅ |

**RELEASE.json sources:**
- `/packages/hrbrlife/AITX-Procedures/dueprocess/RELEASE.json` — **real** on-chain PDA `3LxUbMJ...`, matches CDN ✅
- `/packages/hrbrlife/AITX-Procedures/RELEASE.json` — **offline stub** `offline-release-entry-wvgj30uhk0...` (root-level, not used by the catalog entry)
- `/packages/hrbrlife/AITX-Procedures-v2/dueprocess-v2/RELEASE.json` — **offline stub** `offline-release-entry-47der88w...` (for the "v2 option-b" duplicate entry)

**⚠️ Duplicate entry:** The CDN also carries `DueProcess v2 (option-b)` with the same pkgId but an offline-stub PDA. This is a known artifact — both entries share the same SPK at `/packages/f429990a4a19022f4d7659950611df54`.

**Local SPK:** 31 MiB at `packages/hrbrlife/AITX-Procedures-v2/dueprocess-v2/app.spk`

---

### 2. AiLagoon — ✅ ALL GREEN

| Field | Local | CDN | Match |
|---|---|---|---|
| packageId | `f8b9f972fa8312047e861381f8b57092` | `f8b9f972fa8312047e861381f8b57092` | ✅ |
| sha256 | `f8b9f972fa8312047e861381f8b57092c031b3e60c4dcf88512995e0eba37a8c` | `f8b9f972fa8312047e861381f8b57092c031b3e60c4dcf88512995e0eba37a8c` | ✅ |
| versionNumber | 23 | 23 | ✅ |
| marketingVersion | 0.7.15 | 0.7.15 | ✅ |
| releaseEntryPda | `34ZY5nAhjaJvV36ua4QEaa9H4oSH9JQV1KWjEvJDWr9X` | `34ZY5nAhjaJvV36ua4QEaa9H4oSH9JQV1KWjEvJDWr9X` | ✅ |
| signedAtUnix | 1779982895 | 1779982895 | ✅ |
| SPK on CDN | — | HTTP 200, `application/octet-stream` | ✅ |

**RELEASE.json:** `/packages/hrbrlife/AI_Lagoon/ai-lagoon/RELEASE.json` — **real** on-chain PDA `34ZY5nAh...`, includes full attest block (releaseHash, authorSig, quorumPolicy, releaseNonce) ✅

**Local SPK:** 11 MiB at `packages/hrbrlife/AI_Lagoon/ai-lagoon/app.spk`

---

### 3. Welcome pearl — ✅ ALL GREEN (but version note)

| Field | Local | CDN | Match |
|---|---|---|---|
| packageId | `40f5a4873fc10723cb8375ca25251dd8` | `40f5a4873fc10723cb8375ca25251dd8` | ✅ |
| sha256 | `40f5a4873fc10723cb8375ca25251dd89c08c754aa979712af97e81e6119af36` | `40f5a4873fc10723cb8375ca25251dd89c08c754aa979712af97e81e6119af36` | ✅ |
| versionNumber | **7** | **7** | ✅ |
| marketingVersion | 0.1.6 | 0.1.6 | ✅ |
| releaseEntryPda | `8UmaX2AoJhY1SQEWaaHWQdSh59TA9B6eMnuGWtGxf8dy` | `8UmaX2AoJhY1SQEWaaHWQdSh59TA9B6eMnuGWtGxf8dy` | ✅ |
| signedAtUnix | 1780148656 | 1780148656 | ✅ |
| SPK on CDN | — | HTTP 200, `application/octet-stream` | ✅ |

**⚠️ Version discrepancy with task spec:** The task requests "welcome-pearl v8" but the live catalog shows **vN=7** (v0.1.6). This is the current version on both local and CDN — a v8 does not exist in the catalog.

**RELEASE.json:** `/packages/hrbrlife/welcome-pearl/welcome-pearl/RELEASE.json` — **real** on-chain PDA `8UmaX2Ao...`, matches CDN ✅

**Secondary RELEASE.json:** `/packages/hrbrlife/AITX-Procedures/welcome-pearl/RELEASE.json` has a different PDA (`8fzTG3fEke...`) — this is inside the AITX-Procedures submodule and is a different deployment artifact.

**Local SPK:** 11 MiB at `packages/hrbrlife/welcome-pearl/welcome-pearl/app.spk`

---

## Summary

| Check | DueProcess v32 | AiLagoon | Welcome pearl |
|---|---|---|---|
| pkgId match (local→CDN) | ✅ | ✅ | ✅ |
| sha256 match | ✅ | ✅ | ✅ |
| versionNumber match | ✅ | ✅ | ✅ (vN=7, not v8) |
| RELEASE.json has real on-chain PDA | ✅ | ✅ | ✅ |
| RELEASE.json PDA matches CDN | ✅ | ✅ | ✅ |
| CDN catalog entry present | ✅ | ✅ | ✅ |
| SPK file reachable on CDN | ✅ (HTTP 200) | ✅ (HTTP 200) | ✅ (HTTP 200) |

**3/3 apps fully verified on the live CDN.** All SPKs are reachable, all pkgIds and sha256s match between local catalog and CDN, all 3 have real on-chain ReleaseEntry PDAs (no offline stubs on the primary entries).

**One flag:** welcome-pearl is at vN=7 (v0.1.6), not the requested "v8" — a v8 version does not exist in the catalog.
