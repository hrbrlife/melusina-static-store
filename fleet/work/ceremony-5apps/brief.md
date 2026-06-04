# Pearl Ceremony — 5 Apps (Offline-Stub Queue)

**Target directory:** `/home/user/Desktop/static_store`  
**Script:** `scripts/pearl-app-ceremony.sh`  
**Network:** Solana devnet  
**Squads multisig:** `4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V` (Core App Team, 3-of-4)

## Your job

Run `pearl-app-ceremony.sh` SERIALLY for 5 apps (one at a time — Squads transactionIndex
must not collide). All apps currently have offline RELEASE.json stubs and their SPKs are
already published on gh-pages. For each app:
1. Run the ceremony
2. Verify `verify-release PASS`
3. Confirm RELEASE.json written to catalog path (COPY_TO_CATALOG=1 is default)
4. Move to the next app only after the previous one completes + verify passes

**Do NOT commit** — leave all RELEASE.json changes uncommitted for the captain to audit
and commit together.

## Apps (in order)

| # | APP_SLUG | APP_CATALOG_PATH | expected version | packageId |
|---|----------|-----------------|-----------------|-----------|
| 1 | popaye | packages/hrbrlife/ccash_go_htmx/popaye | 0.3.64 | 3336f86e |
| 2 | namedcoin-pearl | packages/hrbrlife/namedcoin-pearl/namedcoin-pearl | 0.1.0 | 24f5913f |
| 3 | creeper | packages/hrbrlife/melusina-app-creeper/creeper | 0.1.3 | b8b30481 |
| 4 | opensanctions | packages/hrbrlife/melusina-app-opensanctions/opensanctions | 0.1.6 | 97e9d22d |
| 5 | cca-sh-wholesale | packages/hrbrlife/ccash_wholesale/cca-sh-wholesale | 0.2.4 | 130e0ee8 |

## How to run (from static_store root)

```bash
cd /home/user/Desktop/static_store

# App 1: popaye
APP_SLUG=popaye \
APP_CATALOG_PATH=packages/hrbrlife/ccash_go_htmx/popaye \
COPY_TO_CATALOG=1 \
bash scripts/pearl-app-ceremony.sh

# App 2: namedcoin-pearl
APP_SLUG=namedcoin-pearl \
APP_CATALOG_PATH=packages/hrbrlife/namedcoin-pearl/namedcoin-pearl \
COPY_TO_CATALOG=1 \
bash scripts/pearl-app-ceremony.sh

# App 3: creeper
APP_SLUG=creeper \
APP_CATALOG_PATH=packages/hrbrlife/melusina-app-creeper/creeper \
COPY_TO_CATALOG=1 \
bash scripts/pearl-app-ceremony.sh

# App 4: opensanctions
APP_SLUG=opensanctions \
APP_CATALOG_PATH=packages/hrbrlife/melusina-app-opensanctions/opensanctions \
COPY_TO_CATALOG=1 \
bash scripts/pearl-app-ceremony.sh

# App 5: cca-sh-wholesale
APP_SLUG=cca-sh-wholesale \
APP_CATALOG_PATH=packages/hrbrlife/ccash_wholesale/cca-sh-wholesale \
COPY_TO_CATALOG=1 \
bash scripts/pearl-app-ceremony.sh
```

## Keypairs (defaults — no override needed)
- Author: `/home/user/.config/Solana/id.json`
- Publisher: `/home/user/Desktop/Melusina/test-wallets/core-app-team/publisher.json`
- Reviewer1: `/home/user/Desktop/Melusina/test-wallets/core-app-team/reviewer-1.json`
- Reviewer2: `/home/user/Desktop/Melusina/test-wallets/core-app-team/reviewer-2.json`
- Squads config: `/home/user/Desktop/melusina-attestdeployer-tool/config/core-app-team-Squads.json`

## Definition of Done (per app)

- [ ] Script exits 0
- [ ] `verify-release` PASS line printed
- [ ] RELEASE.json in catalog path has real releaseEntryPda (not "offline-release-entry-...")
- [ ] RELEASE.json appHash matches SPK in the catalog (verify-release confirms this)
- [ ] result.json shows `approvedStatus: "Executed"` and `vaultTransactionExecute` sig

## Report format

Write `fleet/work/ceremony-5apps/report.md` with:
- Per-app table: version, appHash, releaseEntryPda, transactionIndex, execute sig, verify-release status
- DoD checklist per app
- Next expected transactionIndex after all 5 complete
- Any failures with exact error message

## Critical notes

- Run SERIALLY — never run two ceremonies at the same time (Squads transactionIndex conflict)
- On failure: stop, document the failure in report.md, do NOT attempt the remaining apps
- On success: do NOT commit; leave RELEASE.json changes for captain
- The current last-used transactionIndex is unknown; the ceremony script reads it automatically
- If the Squads vault is out of SOL for rent, report it and stop
