# cyberteller-v85-deploy — report

**Time:** 2026-05-31 23:10 +04  
**Operator:** cyberteller-v85-deploy (deepseek-v4-pro)

## Diagnosis (confirmed)
- v85 SPK staged at `packages/hrbrlife/cyberteller/cyberteller/app.spk` (mtime 22:13, marker=1)
- CDN was serving v84 (pkgId `4e50256ef53086a2e0bc0c6fdf83b388`)
- gh-pages HEAD was frozen at `dc44ceb8` (2026-05-31 21:06 local) — before the v85 attempt
- Root cause: `MELUSINA_PUBLISH_AUTHORITATIVE=1` not set — plan/apply abort without it (Makefile:108-116, 200-208)

## Deploy
- Command: `MELUSINA_PUBLISH_AUTHORITATIVE=1 MELUSINA_PUBLISH_ALLOW_MANIFEST_DRIFT=1 make deploy`
- Preflight: all 6 gates passed (11 manifest drifts allowed under DRIFT=1 opt-out, 13 pending reseats informational)
- Plan marker: main_head=e0a0ff1a, apps_count=43
- Apply: force-pushed main (e0a0ff1a→27c12aed), publish (dc44ceb8→e411bf1f), gh-pages (dc44ceb8→e411bf1f)

## Verification
- **gh-pages HEAD:** `e411bf1f969b793b2ef1e6e4a0447d29fbb9c20b` @ 2026-05-31 23:10:55 +0400
- **CDN:** cyberteller v85, pkgId `d2cf7beeb92e584b3aa908ef6405dd1a`
- **Package URL:** `packages/d2cf7beeb92e584b3aa908ef6405dd1a` → HTTP 200
- **Stability recheck (60s):** v85 still live — no orphan-race revert

## FINALE2E
- Fixed pkgId typo (`584bb3` → `584b3`) in `src/lib/app-targets.ts` line 94
- Committed + pushed to `hrbrlife/melusina_ccash_e2e_final` main (1555e0a→4a7d861)

## Conclusion
**v85 LIVE + STABLE on gh-pages CDN? yes — pkgId `d2cf7beeb92e584b3aa908ef6405dd1a`**
