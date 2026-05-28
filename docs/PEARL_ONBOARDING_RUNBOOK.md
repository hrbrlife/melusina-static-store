# pearl-Mode Onboarding Runbook

## When to use this
Your app currently uses `spkmodule` in offline-stub mode and you want to migrate to greenfield pearl-mode (Squads-quorum signed releases).

## Prerequisites
- App is on canonical spkmodule submodule URL (see Stream B sweep — most apps already are)
- You have `melusina-pearl-tool` v0.3.0+ on PATH (`melusina-pearl-tool --version`)
- Solana CLI installed; `~/.config/Solana/id.json` keypair has >=0.5 SOL on devnet (`Solana balance --url devnet`)
- Access to Core App Team Squads cosigners (publisher + reviewer-1 + reviewer-2 must approve)
- Awareness of license-registry v104 master-NFT gate (see "Workaround until v105" below)

## Step-by-step (15-30 min on devnet)

### 1. Bump spkmodule to greenfield
```
cd $APP_DIR
cd spkmodule && git fetch origin && git checkout greenfield && cd ..
git add spkmodule
git commit -m "spkmodule: bump to greenfield"
```

### 2. Declare pearl vars in your Makefile
After the existing `APP_SLUG := ...` line, add:
```makefile
PEARL_LIVE_MASTER_NFT_MINT := <base58>
PEARL_LICENSE_MINT         := <base58>
PEARL_RELEASE_VERSION      := 0.1.0
PEARL_APP_ID               := $(APP_SLUG)
TEAM_LIVE_SQUADS           := 4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V
```
(For DEV lineage, also add `PEARL_DEV_MASTER_NFT_MINT` + `TEAM_DEV_SQUADS`.)

### 3. Run ceremony
```
melusina-pearl-tool onboard --lineage=live --app-dir=$APP_DIR
```
This will:
1. Sanity-check your environment
2. Mint a License NFT (sub-1 minute on devnet)
3. Mint or accept a canonical Master NFT
4. Propose a ReleaseEntry on-chain
5. Print Squads UI URLs for 3 cosigners to approve

### 4. Cosigners approve (3-of-4)
Each cosigner visits their printed Squads URL and clicks Approve. Approval is per-cosigner, async, ~30 sec each.

### 5. Finalize
Once quorum is reached, re-run (or pass `--wait-active` to step 3 to poll):
```
melusina-pearl-tool onboard --lineage=live --app-dir=$APP_DIR
```
This finalizes the ReleaseEntry, writes signed RELEASE.json, patches your Makefile with real mints, and commits to `feat/pearl-onboard-live-<date>` branch.

### 6. Publish
```
cd $APP_DIR
make publish
```
greenfield gates (version-bump, SPK-size, Squads quorum) run automatically.

## Workaround until v105 (current 2026-05-18 state)

license-registry v104 has a hardcoded global master NFT mint. Per-app master mint will fail at execute-proposal. For devnet validation TODAY, pass:
```
--canonical-master=B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe
```
And use the spkmodule `greenfield-spike-canonical-master` branch (tag `v0.0.0-spike-canonical-master.2`).

Once Stream A ships v105 (~2026-05-26 to 2026-05-28), drop the flag and use plain `greenfield`.

## Troubleshooting

### "FATAL: refusing to publish — files changed but version not bumped"
Gate A working as intended. Bump `PEARL_RELEASE_VERSION` in your Makefile.

### "WrongMasterNFT" at execute-proposal
You hit the v104 contract gate. Use the `--canonical-master` workaround above.

### "Squads has not signed this release"
Gate B working — not enough cosigners. Visit the Squads UI URLs and get more approvals.

### SPK > 100MB push rejected
Auto-routes to GitHub Releases via `gh release upload`. Make sure `gh` CLI is installed.

## See also

- `spkmodule/docs/pearl-ceremony-gotchas.md` — 4 known ceremony gotchas
- `spkmodule/docs/stream-c-dev-store-envelope-proposal.md` — DEV-lineage upload contract
- `static_store/SHIP-IT.md` — overall ship-loop runbook
- Memory: `project_greenfield_publish_design.md`, `project_devpublish_spec_integration_2026_05_18.md`
