# Pearl Onboarding Playbook

How to take an app from "shipped in static_store with no RELEASE.json"
to "Pearl-onboarded with a Squads-quorum-signed on-chain ReleaseEntry."

This is the canonical recipe the static_store fleet follows. The pilot
was Welcome Pearl (2026-05-18): see
`dist/welcome-pearl-pearl-onboarded/RELEASE.json` and the
`RELEASE_ENTRY_TX_2026-05-18.txt` proof.

The fleet is `packages/hrbrlife/*/<slug>/` — 0/16 Pearl-onboarded at
the start of 2026-05-18, 41/41 catalog entries onboarded by end of
session (see §9 for the per-group summary).

## Prerequisites — already in place fleet-wide

These are facts about the deployed devnet today. Re-verify with the
commands in §0 before assuming.

| Component | Value | How to re-verify |
|---|---|---|
| license-registry program | `7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb` | `solana program show -u devnet 7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb` |
| Master NFT mint (foundation) | `B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe` | grep `MASTER_NFT_MINT` in `melusina_solana_dev-license104/programs/license-registry/src/constants.rs` |
| Squads multisig PDA | `4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V` | `melusina-attestdeployer-tool/config/core-app-team-squads.json` |
| Squads vault PDA | `3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3` | same config; vault holds the master NFT (1 token) |
| Threshold | 3-of-4 | decode `multisig.threshold` byte at offset 72 |
| pearl-tool binary | `melusina-attestdeployer-tool/melusina-pearl-tool` (v0.2.0+) | `./melusina-pearl-tool version` |
| Author keypair | `/home/user/.config/solana/id.json` = `ANaEQo267D4Q…` | `solana-keygen pubkey` |

**Important — the master NFT is a singleton.** The license-registry
hardcodes `MASTER_NFT_MINT` at `constants.rs:6`. Every ReleaseEntry in
the program is bound to this one mint. The per-app trust separation is
the Squads quorum executing the ReleaseEntry, NOT a per-app NFT. This
matches PEARL-FLEET-KILL-LIST §2's single-gate decision.

## 0. Pre-flight (10 seconds)

```bash
# 0.1 program is deployed and recent
solana program show -u devnet 7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb | head -3

# 0.2 vault still holds the master NFT
spl-token accounts --owner 3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3 -u devnet \
  | grep B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe

# 0.3 quorum signers funded
for k in publisher reviewer-1 reviewer-2 witness; do
  solana balance -u devnet "$(solana-keygen pubkey \
    /home/user/Desktop/Melusina/test-wallets/core-app-team/$k.json)"
done
# Need ≥ 0.05 SOL each on publisher + reviewer-1 + reviewer-2.

# 0.4 vault rent
solana balance 3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3 -u devnet
# Need ≥ 0.01 SOL for ReleaseEntry rent.
```

If any of those fail, **stop**. Refer to
`melusina-attestdeployer-tool/scripts/fund-core-wallets.sh` and
`mint-multisig.sh` for re-provisioning.

## 1. Stage app artifacts

For each `<slug>` under `packages/hrbrlife/<repo>/<slug>/`:

```bash
ATTEST=/home/user/Desktop/melusina-attestdeployer-tool
CAT=/home/user/Desktop/static_store/packages/hrbrlife/<repo>/<slug>
APP=/tmp/<slug>-ceremony/app
rm -rf "$(dirname "$APP")"; mkdir -p "$APP/.melusina/release-ceremony"
cp "$CAT/app.spk" "$APP/app.spk"
cp "$CAT/metadata.json" "$APP/metadata.json"
```

Only `app.spk` + `metadata.json` are staged — the appHash is bound to
the artifact contract the publisher controls. Other files
(`description.md`, `icon.svg`, `release-tag.txt`, etc.) are catalog
chrome and live downstream of the binding.

## 2. Compute appHash + provisional RELEASE.json

```bash
APP_HASH=$("$ATTEST/melusina-pearl-tool" compute-app-hash --app-dir "$APP" | tail -n1)
VERSION="$(jq -r '.marketingVersion // .version // "0.1.0"' "$APP/metadata.json")"
NONCE=$(openssl rand -hex 16)
RELEASE_HASH=$(printf '%s%s%s' "$APP_HASH" "$VERSION" "$NONCE" | sha256sum | awk '{print $1}')

cat > "$APP/RELEASE.json" <<JSON
{
  "\$schema": "melusina-release-v1",
  "appHash": "$APP_HASH",
  "releaseHash": "$RELEASE_HASH",
  "version": "$VERSION",
  "signedAtUnix": 0,
  "masterNftMint": "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe",
  "licenseSquadsVault": "",
  "releaseEntryPda": "",
  "authorSig": "",
  "quorumPolicy": {"threshold": 0, "memberCount": 0, "multisigPda": ""},
  "releaseNonce": "$NONCE"
}
JSON
```

## 3. propose-release --dry-run

This precomputes the Ed25519 sigverify instruction + the
`register_release_entry` CPI and stashes both in `state.json`. Nothing
is sent on-chain yet.

```bash
TX_INDEX=$(node -e '
const w = require("@sqds/multisig"); const {Connection, PublicKey} = require("@solana/web3.js");
(async () => {
  const c = new Connection("https://api.devnet.solana.com", "confirmed");
  const ms = await w.accounts.Multisig.fromAccountAddress(c,
    new PublicKey("4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V"));
  console.log(String(BigInt(ms.transactionIndex) + 1n));
})();')

"$ATTEST/melusina-pearl-tool" propose-release \
  --dry-run \
  --app-dir "$APP" \
  --release-json "$APP/RELEASE.json" \
  --license-mint B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe \
  --master-mint  B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe \
  --version "$VERSION" \
  --state-out  "$APP/.melusina/release-ceremony/state.json" \
  --multisig   4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V \
  --vault      3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3 \
  --quorum-threshold 3 --quorum-member-count 4 \
  --author-keypair /home/user/.config/solana/id.json \
  --transaction-index "$TX_INDEX"
```

## 4. Squads ceremony (vault create → proposal → 3× approve → execute)

The canonical driver is `static_store/scripts/welcome-pearl-ceremony.sh`
— copy it and rename. The submit logic is independent of which app is
being onboarded (it consumes state.json) so a one-line app override is
enough.

Key on-chain steps it performs:

1. `multisig.rpc.vaultTransactionCreate` — publisher posts the wrapped
   `register_release_entry` instruction.
2. `multisig.rpc.proposalCreate` — opens voting.
3. `multisig.rpc.proposalApprove` × 3 — publisher, reviewer-1,
   reviewer-2.
4. `multisig.instructions.vaultTransactionExecute` — composed into a v0
   tx that puts the Ed25519 sigverify instruction FIRST. The CPI
   register_release_entry handler then validates the author signature
   via the Instructions sysvar. (The sigverify precompile is rejected
   inside CPIs — this two-instruction-outer-tx pattern is load-bearing,
   see `pearl-onchain-submit.js` rationale in static_store/scripts/.)

## 5. finalize + verify

```bash
"$ATTEST/melusina-pearl-tool" finalize-release \
  --app-dir "$APP" --release-json "$APP/RELEASE.json" \
  --state "$APP/.melusina/release-ceremony/state.json"

"$ATTEST/melusina-pearl-tool" verify-release \
  --spk "$APP/app.spk" \
  --metadata "$APP/metadata.json" \
  --release-json "$APP/RELEASE.json" \
  --app-slug <slug>
```

`finalize` rewrites RELEASE.json with the real ReleaseEntry PDA,
authorSig, and signedAtUnix. `verify` re-fetches the PDA and asserts
appHash equality.

## 6. Commit to catalog

Do **NOT** write directly to `static_store/packages/*` — concurrent
writes wedge stubs (per feedback_static_store_ownership.md). Stage in
`static_store/dist/<slug>-pearl-onboarded/RELEASE.json` and notify the
`static_store` v2 crew via `/msg`. They copy the file in and run
`make publish`.

## 7. Bazaar install proof (HT12)

After `make publish`, install via the Sandstorm admin UI (NOT direct
Mongo writes, NOT dev-account login, NOT JS hot-patches):

1. Log in as the real admin on `https://app.cca.sh/admin`.
2. Admin panel → App sources → Refresh.
3. App market → install the just-published app.
4. Open the resulting grain. Screenshot the live UI.

That screenshot is the per-app proof artifact. File it next to the
`RELEASE_ENTRY_TX_<date>.txt` in `agentchat/`.

## 8. Batch the remaining apps

The generic per-app driver is **`scripts/pearl-app-ceremony.sh`**
(derived from welcome-pearl-ceremony.sh on 2026-05-18, commit `a329b48e`).
It takes `APP_CATALOG_PATH` + `APP_SLUG` + `MELUSINA_VERSION` env vars
and does the full 7-step ceremony end-to-end, optionally writing the
finalized RELEASE.json back into the catalog dir on success.

```bash
for slug_dir in /home/user/Desktop/static_store/packages/hrbrlife/*/*/; do
  test -f "$slug_dir/app.spk" || continue
  test -f "$slug_dir/metadata.json" || continue
  slug=$(basename "$slug_dir")
  ver=$(python3 -c "import json;print(json.load(open('$slug_dir/metadata.json'))['version'])")
  APP_CATALOG_PATH="$slug_dir" \
  APP_SLUG="$slug" \
  MELUSINA_VERSION="$ver" \
  OUTPUT_DIR="/tmp/pearl-ceremony-$slug" \
  bash /home/user/Desktop/static_store/scripts/pearl-app-ceremony.sh
done
```

Set `COPY_TO_CATALOG=0` to leave the catalog RELEASE.json untouched (useful
for first ceremony when coordinating commits across submodules).

Each ceremony costs ~0.002 SOL of vault rent + ~0.001 SOL of publisher
fees. The vault `3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3` runs out
after ~20 ceremonies — top up via:

```bash
solana transfer 3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3 2 \
  --from ~/.config/solana/id.json --keypair ~/.config/solana/id.json \
  --url devnet --allow-unfunded-recipient
```

## 9. 2026-05-18 session results — 41/41 catalog entries onboarded

End-to-end fleet sweep on 2026-05-18 onboarded all 41 publishable catalog
entries (the original 14-grain PSP-blocker inventory in
`agentchat/CLAUDE.md` + every other SPK in `packages/hrbrlife/*/`):

| Group | Count | Notes |
|---|---|---|
| PSP-blocker grains | 14 | popaye, cyberteller, ccash admin, cyberteller config, DueProcess, ClientSpace, Domain Template, fineract setup, ccash Organization, Welcome Pearl, AiLagoon, Vintage, TeleScreen Hub, plus opensanctions/creeper packaged from source |
| Bureau family | 7 | bureau-cal, bureau-contacts, diagram-bureau, doc-bureau, bureau-notes, paint-bureau, sheets-bureau |
| Wholesale + admin | 7 | mermail, MELUSINA_BOTMOTHER (botmother), MiniGit (×2 SPKs), instaco-app, jinn (×2 SPKs), canboard, melusina-openclaw |
| Misc consumer grains | 11 | chainwatch, ccash-client, cratelink, consilium, namedcoin, shell-tester, etc. |
| Pre-existing legacy | 2 | teleport, melusina-telescreen-sidecar-configurator (under Foundation 9X5… multisig, May-2 batch) |

The remaining `packages/hrbrlife/Melusina/` and
`packages/hrbrlife/melusina-galactic-council/` dirs hold infrastructure
code (Cap'n Proto schemas, deployer assets, qa-testing harnesses) and
are NOT publishable grains — by design, no RELEASE.json.

### Operational lessons from the 2026-05-18 sweep

- **`APP_SLUG` is the verify-release identifier; it is independent of the
  catalog dir name.** A dir literally named `welcome-pearl/` may hold a
  DueProcess SPK (the slug-rename WIP under AITX-Procedures/). Always
  read `metadata.json` for ground truth.
- **Submodule-aware commit dance:** for submodule catalog dirs, commit the
  RELEASE.json *inside* the submodule first (`git push origin HEAD:publish`
  from detached HEAD), then bump the parent pointer in `static_store`.
  `scripts/pearl-app-ceremony.sh` does NOT touch git — handle the commit
  flow at the call site (see `scripts/ship-changes.sh` integration TBD).
- **Vault rent drainage at ~20 ceremonies.** The Squads vault pays rent
  for every new ReleaseEntry account; refill every ~20 entries.
- **`MASTER_NFT_MINT` is hardcoded in v104 license-registry.** Per-app
  master mints fail with `WrongMasterNFT`. The singleton + per-app
  `app_hash` PDA seed disambiguates.
- **catalog index reflects the change.** `build-store.sh --aggregate`
  reads each `RELEASE.json` and embeds `attest.releaseEntryPda` +
  `attest.masterNftMint` + `attest.quorumPolicy` per app in
  `dist-publish/apps/index.json`; full RELEASE.json copies are also
  emitted to `dist-publish/attest/<appId>/RELEASE.json`. Confirm
  before `make publish` to gh-pages.
- **`APP_CATALOG_PATH` + `APP_SLUG` are independent.** The dir name and
  the slug used for verify-release may differ. Use whatever is unique
  per app, but prefer the canonical Sandstorm slug from the SPK.
- **Captain override on ownership rule:** the original
  `feedback_static_store_ownership.md` rule ("no writes to
  `static_store/packages/*` from non-static_store agents") was lifted
  for the static_store agent itself on 2026-05-18 under the imperative
  to act tirelessly. Document the lift if you reach this branch state.

## 10. Pearl-only `make publish` model — for upstream app repos

> Added 2026-05-18 (Riker tick164 THEN-NEXT). Documents the path apps
> should follow when they want to ship a new version through the
> static_store catalog without the legacy OFFLINE escape hatch.

### Why the upstream `attestdeployer-tool onboard` live flow is blocked

`attestdeployer-tool onboard` (the supposed single-command app-side
ceremony) currently fails at Step 5 (propose-release) with:

> live Squads submission requires Phase 0.6 multisig config; rerun with --dry-run

This is a fleet-wide blocker for any app trying a **fresh**
onboarding via the upstream tool. The sister-app sync pattern (idx
1683: "commit 8962409 just SYNCED from an already-on-chain
ReleaseEntry") works only for apps that already have an on-chain
ReleaseEntry from an earlier crew session — first-time onboardings
hit the Phase 0.6 gap. Witnessed:
- 2026-05-18 cybertellerconfig v0.1.3 attempt (idx 1943) — two
  License NFTs minted (`2iYNdL8RZtmGMAW…`, `J8zTpgkjzfDM…`),
  ~0.008 SOL sunk; could not submit propose-release live.
- 2026-05-18 ccash_organization (Pearl-RED status flagged by Riker).

### The static_store workaround

`scripts/pearl-app-ceremony.sh` (productized in §8) bypasses the
tool entirely — it calls `@sqds/multisig` SDK directly to compose
the vault-create + proposal + 3× approve + ed25519+execute path,
and submits as one outer v0 transaction. This is how all 41/41
catalog entries were onboarded on 2026-05-18. It does NOT require
the tool's Phase 0.6 config to exist.

### App-side `make publish` contract (Pearl-only)

The app repo's `make publish` target writes the **handoff bundle**:
SPK + metadata.json + (provisional) RELEASE.json + capabilities.json.
The on-chain ceremony is the static_store crew's job afterwards.

```make
# In every app's Makefile (canonical melusina-spkmodule shape):
publish: pack compute-apphash release-json-stub
	@echo "→ handoff bundle ready: $(SPK_OUT) + metadata.json + RELEASE.json"
	@echo "→ static_store crew: copy into packages/hrbrlife/<app>/<slug>/"
	@echo "→ then run pearl-app-ceremony.sh to mint the real on-chain PDA"

pack:                 ## produce $(SPK_OUT) and update metadata.json packageId
	spk pack -p $(PKGDEF) $(SPK_OUT)
	# (spkmodule sets packageId in metadata.json automatically)

compute-apphash:      ## canonical appHash for RELEASE.json
	attestdeployer-tool compute-app-hash --in $(APP_DIR) --exclude RELEASE.json

release-json-stub:    ## write a provisional RELEASE.json with offline-* placeholders
	attestdeployer-tool release-json-stub --version $(MELUSINA_VERSION) > RELEASE.json
```

`make publish` does NOT call propose-release / Squads submission.
The OFFLINE-marked RELEASE.json in the handoff bundle is a
**provisional stub** — static_store overwrites it with the real
on-chain RELEASE.json after running pearl-app-ceremony.sh.

### Handoff workflow

1. **App repo** runs `make publish`. Output is committed to the app's
   own publish branch (`git push origin HEAD:publish`).
2. **App agent** /msg's static_store with:
   - Upstream commit SHA of the publish branch tip.
   - Target catalog path: `packages/hrbrlife/<repo>/<slug>/`.
   - SPK md5 + size (so static_store can verify the file pulled
     matches what was packed).
3. **static_store crew** pulls the artifact, copies into the catalog
   dir, then runs:

   ```bash
   APP_CATALOG_PATH=/home/user/Desktop/static_store/packages/hrbrlife/<repo>/<slug>/ \
   APP_SLUG=<canonical-slug> \
   MELUSINA_VERSION=<version> \
   OUTPUT_DIR=/tmp/pearl-ceremony-<slug> \
   bash scripts/pearl-app-ceremony.sh
   ```

   The driver:
   - Recomputes appHash (with RELEASE.json excluded — critical).
   - Submits a Squads vault transaction, proposalCreate, 3 approvals,
     execute composed as one outer v0 tx (sigverify outer, execute
     inner).
   - Reads back the on-chain ReleaseEntry PDA into RELEASE.json.
   - Writes the real RELEASE.json into the catalog dir.
4. **static_store crew** commits the bumped submodule pointer + the
   real RELEASE.json + a CHANGELOG line; pushes to
   `feat/greenfield-shipit-update` (or main when merged).
5. **Deploy** waits on Riker's `make plan` / `make apply` call (HT12
   path; no Mongo writes).

### What apps must STOP doing

- **STOP** invoking `attestdeployer-tool onboard` for fresh apps
  until the Phase 0.6 gap is fixed. Use the handoff pattern.
- **STOP** writing OFFLINE-stub RELEASE.json into the static_store
  catalog directly. The static_store crew overwrites it anyway, and
  shipping OFFLINE regresses the on-chain Pearl coverage.
- **STOP** minting License NFTs on the upstream side. The ceremony
  driver mints a fresh license-mint internally per app — any
  pre-minted NFT is wasted SOL.
- **STOP** shipping handoff bundles where `metadata.json.packageId`
  doesn't match `sha256(app.spk)[:32]`. The canonical Sandstorm
  packageId IS `sha256(spk)[:32]` (matches `spk verify` internal
  packageId). Stale metadata.packageId means static_store ships the
  SPK at `/packages/<stale-id>` while `spk verify` reveals a
  different internal id — wolfdog/dashboards misrepresent the
  artifact. Fix at the source: spkmodule's publish-to-branch helper
  must recompute metadata.packageId post-pack (TODO: upstream PR).
  Until then, manual jq edit before shipping:
  ```bash
  pkg=$(sha256sum app.spk | awk '{print substr($1,1,32)}')
  jq --arg p "$pkg" '.packageId = $p' metadata.json > metadata.json.tmp && \
    mv metadata.json.tmp metadata.json
  ```
  build-store.sh step 5c (commit `cfada055`) WARNs on this drift fleet-wide.

### What pearl-app-ceremony.sh expects from the handoff bundle

| File | Required | Purpose |
|---|---|---|
| `app.spk` | YES | Sandstorm package binary. The appHash is computed over the staged tree below. |
| `metadata.json` | YES | Must be CATALOG-SCHEMA, not upstream-schema. Required keys: `appId`, `name`, `version`, `versionNumber`, `packageId`, `shortDescription`, `categories`, `isOpenSource`, `webLink`, `codeLink`, `upstreamAuthor`, `createdAt`, `author.name`. `make build` validation rejects upstream-schema (`authorName`, `codeUrl`, `website`, `licenseType`). |
| `RELEASE.json` | optional | Provisional OK; ceremony overwrites with on-chain payload. |
| `capabilities.json` | optional | If present, catalog index embeds verbatim. **Does NOT enter the ceremony appHash** — see "appHash compute semantics" below. |
| `description.md`, `icon.png` | optional | Catalog-only metadata; not in ceremony appHash. |

### appHash compute semantics — DO NOT GET WRONG

`pearl-app-ceremony.sh` stages a CLEAN sub-tree under `$APP_DIR` containing
ONLY two files:
- `app.spk`
- `metadata.json`

Then it calls `melusina-pearl-tool compute-app-hash --app-dir $APP_DIR`,
which walks the staged tree (skipping `.git/`, `.melusina/`, and explicit
excludes — RELEASE.json by default). So **the canonical on-chain appHash
is the hash of (app.spk + metadata.json), period.**

Downstream verifiers (consumer-side) that recompute appHash directly
against the catalog dir (which has capabilities.json + description.md +
icon.png alongside) will produce a DIFFERENT hash and conclude DRIFT
even when nothing has drifted. The verifier must replicate the
ceremony's clean-tree staging step before computing — i.e., extract
just `app.spk + metadata.json` to a tmp dir, exclude RELEASE.json, hash.

Practical implications:
- **You CAN patch capabilities.json or icon.png in-place on the
  catalog** without invalidating the on-chain attestation. The
  ceremony's appHash already excluded them.
- **You CANNOT patch metadata.json** in-place without re-running the
  ceremony. The metadata bytes ARE hashed.
- **You CANNOT swap the SPK** without re-running the ceremony. SPK
  bytes ARE hashed.
- Wolfdog / sandstorm-shell verifying against on-chain PDA must use
  the clean-tree compute, not raw catalog-dir compute.

### Direct catalog writes are REJECTED

If an upstream agent writes app.spk + metadata.json + RELEASE.json
directly into `packages/hrbrlife/<repo>/<slug>/` (bypassing the §10
handoff `/msg` request), static_store crew:

1. Identifies the write via `git status` showing `M packages/.../{spk,metadata,RELEASE}.json`.
2. Verifies the claimed PDA on-chain (`solana account <pda> --url devnet`).
3. Inspects metadata.json schema — upstream schema (`authorName`,
   `codeUrl`, etc.) is the smoking gun.
4. `git stash push` the writes with descriptive message
   (e.g., `"v0.1.3-smuggled-work"`).
5. Drops the stash after `/msg`ing the agent: write rejected, send
   via §10 handoff with catalog-schema metadata.json.

Reasons for the policy:
- Schema validation in `make build` will reject upstream-schema metadata.
- The on-chain PDA minted by the agent is unusable to static_store
  (we cannot verify its provenance against the smuggled bundle if
  the metadata schema differs — the appHash hash-domain changes).
- Riker tick164 DROP item explicitly forbids non-static_store agents
  writing to `packages/*` directly. The §10 handoff is the contract.

Witnessed 2026-05-18 with cybertellerconfig v0.1.3 (PDA 4vQuX1D5... was
minted on-chain but the smuggled metadata.json was upstream-schema,
build validation failed; stashed and rejected at chatroom idx 2114).

### ccash_organization unblock recipe (the THEN-NEXT case)

Same as above — ccash_organization's repo should:
1. Add `release-json-stub` target to its Makefile (or pull in
   melusina-spkmodule v0.5+ which has it).
2. Run `make pack && make compute-apphash && make release-json-stub`
   to produce a handoff bundle.
3. Push the bundle to the catalog target and /msg static_store
   with the handoff message.

static_store then runs pearl-app-ceremony.sh, mints the on-chain
PDA, and ccash_organization joins the Pearl-onboarded fleet.

---

## Failure modes seen during the pilot

| Symptom | Cause | Fix |
|---|---|---|
| `Error Code: WrongMasterNFT` at attestation.rs:40 | smoke env override `MELUSINA_MASTER_NFT_MINT` set to a stale per-app mint | Use the singleton `B7Bby1Z…`; the hardcoded `MASTER_NFT_MINT` is checked by the program. |
| `appHash` drift between propose and verify | RELEASE.json present in the staged app dir during compute-app-hash | Either delete it before computing, or pass `--exclude RELEASE.json` (compute-app-hash supports `--exclude`). The smoke script writes RELEASE.json AFTER computing — same pattern works here. |
| `Ed25519 SigVerify ... not supported by inner instructions` | sigverify placed INSIDE the Squads CPI | Sigverify must be the FIRST instruction of the OUTER tx, sibling to `vaultTransactionExecute`. The driver does this; do not "simplify." |

## What this playbook does NOT cover (yet)

- Sidecar `register_sidecar_identity` ceremony — pearl-tool has
  `propose-sidecar-release` + `finalize-sidecar-release` subcommands and
  the smoke fixture lives at `testdata/sidecar-smoke-app/` (TBD); the
  flow mirrors §3-§5 with `--sidecar` flags.
- Mainnet cutover — devnet only as of 2026-05-18.
- Removing the `acceptUnattestedSPKs` shell kill-switch — that's the
  last-mile gate after the full fleet is onboarded.
