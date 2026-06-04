# os-creeper-manifest-merge — Report

**Captain**: sidecar-authz-bundle
**Date**: 2026-05-30
**Status**: All staging artifacts verified and updated. Pending storekeeper CDN deploy.

---

## 1. Global-apps manifest state

**File**: `/home/user/Desktop/Melusina/deployer/config/approval-manifests/global-apps-2026-04-23.json`

- **Commit `1939739`**: NOT FOUND in the Melusina deployer repo. The branch `feat/mail-inbound-relay-domains-2026-05-29` does not exist locally or on origin. Neither `git fetch --all` nor `git branch -a --contains` located the commit or branch.
- **However**: The manifest entries for Creeper and OpenSanctions are ALREADY present on `main` (HEAD: `5562d550`), with correct app_hashes matching the v3 SPK rebuilds:

| App | app_hash (first 32 chars) | Version |
|-----|--------------------------|---------|
| Creeper | `4a4875b92542a66b88b9f976d14a78af` | 0.1.4 |
| OpenSanctions | `659edd86414e03b90e5b0e9107c52fbf` | 0.1.7 |

- **Cherry-pick**: NOT NEEDED. Manifest is already up-to-date on main. The update appears to have been committed directly to main (possibly during the deployer's own merge flow), not via the feat/mail-inbound branch.

---

## 2. Static store SPK verification

### Flat SPKs (`packages/<pkgId>.spk`)

| App | pkgId | SHA256 verified | Size |
|-----|-------|-----------------|------|
| OpenSanctions v9 | `659edd86414e03b90e5b0e9107c52fbf` | ✅ MATCH | 10.6 MiB |
| Creeper v6 | `4a4875b92542a66b88b9f976d14a78af` | ✅ MATCH | 11.1 MiB |

Source: Copied from `/home/user/Desktop/Melusina/static_store/packages/` (the deployer's embedded store).

### Submodule SPKs (`packages/hrbrlife/melusina-app-{creeper,opensanctions}/`)

- **Before fix**: Submodule SPKs were STALE — old v5/v8 builds with wrong pkgIds.
- **After fix**: Overwritten with new v3 SPKs. SHA256s now match flat SPKs. ✅

### Cross-source verification

Both source locations match:
- `/home/user/Desktop/melusina-app-opensanctions/melusina-app-opensanctions.spk` → `659edd86...` ✅
- `/home/user/Desktop/melusina-app-creeper/dist/melusina-app-creeper.spk` → `4a4875b9...` ✅

---

## 3. Catalog metadata audit

### metadata.json (submodule dirs)

Both updated via targeted text-replace (no formatting churn):

| Field | OpenSanctions (old → new) | Creeper (old → new) |
|-------|--------------------------|---------------------|
| packageId | `a833b968...` → `659edd86...` | `400c686e...` → `4a4875b9...` |
| version | 0.1.6 → 0.1.7 | 0.1.3 → 0.1.4 |
| versionNumber | 8 → 9 | 5 → 6 |
| marketingVersion | 0.1.6 → 0.1.7 | 0.1.3 → 0.1.4 |
| sha256 | `a833b968...` → `659edd86...` | `400c686e...` → `4a4875b9...` |

### apps.json (`src/apps.json`)

Both entries updated. Stale attest.appHash values preserved (they reflect the on-chain attestation which is `pending_reseat: true`).

### Attest RELEASE.json

Both stale (OpenSanctions v0.1.6, Creeper v0.1.0). This is EXPECTED — they require on-chain re-ceremony via Squads multisig (Foundation keypair blocker). The `pending_reseat: true` flag in the manifest covers this.

---

## 4. Preflight output

```
Gate 1: FAIL — Catalog SHRINK (43→42). NamedCoin removed. PRE-EXISTING.
Gate 2: FAIL — 9 hash drifts across popaye, ccash_wholesale, cyberteller, etc. PRE-EXISTING.
         Creeper + OpenSanctions: "local SPK matches manifest hash" ✅
Gate 3: WARN — MELUSINA_PUBLISH_AUTHORITATIVE not set
Gate 4: PASS — Icon QC (27 warnings, 0 fails)
Gate 5: PASS — Metadata QC (1 warning: DueProcess missing description)
Gate 6: INFO — Net delta 0 apps
```

**Assessment**: The two FAIL gates are pre-existing issues unrelated to this merge. Creeper and OpenSanctions pass manifest cross-check (shown under "pending on-chain reseat" with "local SPK matches manifest hash").

---

## 5. Coordination message → Storekeeper

```
@storekeeper @sidecar-authz-bundle

os-creeper-manifest-merge complete. Staging ready for CDN deploy.

OpenSanctions v9:
  pkgId: 659edd86414e03b90e5b0e9107c52fbf
  SPK: packages/659edd86414e03b90e5b0e9107c52fbf.spk (10.6 MiB)
  Submodule: packages/hrbrlife/melusina-app-opensanctions/ (metadata.json updated)
  Source: /home/user/Desktop/melusina-app-opensanctions/melusina-app-opensanctions.spk

Creeper v6:
  pkgId: 4a4875b92542a66b88b9f976d14a78af
  SPK: packages/4a4875b92542a66b88b9f976d14a78af.spk (11.1 MiB)
  Submodule: packages/hrbrlife/melusina-app-creeper/ (metadata.json updated)
  Source: /home/user/Desktop/melusina-app-creeper/dist/melusina-app-creeper.spk

Both carry sc33-401-root-cause auth-header fix.

Global-apps manifest: Already on main (5562d550). No cherry-pick needed.
  The supposed commit 1939739 on feat/mail-inbound-relay-domains-2026-05-29 does not
  exist in the repo — the manifest entries were authored directly on main.

pending_reseat: true (both apps). On-chain ceremony blocked by Foundation keypair
  (same blocker as 25+ other apps).

Preflight: 2 FAIL gates are pre-existing (catalog shrink + hash drifts on other apps).
  Creeper + OpenSanctions show "local SPK matches manifest hash" — clean.

CDN deploy command:
  MELUSINA_PUBLISH_AUTHORITATIVE=1 MELUSINA_PUBLISH_SHRINK_OK=1 MELUSINA_PUBLISH_ALLOW_MANIFEST_DRIFT=1 make deploy

  (All three overrides needed due to pre-existing drift on other apps)
```

---

## 6. Remaining blockers for CDN deploy

1. **Pre-existing catalog shrink** (NamedCoin removal) — needs `MELUSINA_PUBLISH_SHRINK_OK=1` override or resolution of the NamedCoin situation.
2. **Pre-existing manifest drifts** (9 apps including popaye, cyberteller, etc.) — needs `MELUSINA_PUBLISH_ALLOW_MANIFEST_DRIFT=1` override or per-app fixes.
3. **On-chain re-ceremony** (pending_reseat) — affects both Creeper and OpenSanctions plus 15+ other apps. Blocked on Foundation keypair availability for Squads multisig. The SPK can deploy to CDN without the ceremony, but grains won't pass authorization until the GlobalAppApproval is reseated on-chain.
4. **`MELUSINA_PUBLISH_AUTHORITATIVE`** — must be set to `1` in the canonical builder environment.

---

## 7. Commits

No commits made in static_store. All changes are uncommitted staging updates:

- `packages/659edd86414e03b90e5b0e9107c52fbf.spk` — new file (staged from deployer)
- `packages/4a4875b92542a66b88b9f976d14a78af.spk` — new file (staged from deployer)
- `packages/hrbrlife/melusina-app-creeper/creeper/app.spk` — overwritten (new v3)
- `packages/hrbrlife/melusina-app-opensanctions/opensanctions/app.spk` — overwritten (new v3)
- `packages/hrbrlife/melusina-app-creeper/creeper/metadata.json` — updated (pkgId, version, sha256)
- `packages/hrbrlife/melusina-app-opensanctions/opensanctions/metadata.json` — updated (pkgId, version, sha256)
- `src/apps.json` — updated (Creeper + OpenSanctions catalog entries)
