# Pearl Onboarding Playbook

How to take an app from "shipped in static_store with no RELEASE.json"
to "Pearl-onboarded with a Squads-quorum-signed on-chain ReleaseEntry."

This is the canonical recipe the static_store fleet follows. The pilot
was Welcome Pearl (2026-05-18): see
`dist/welcome-pearl-pearl-onboarded/RELEASE.json` and the
`RELEASE_ENTRY_TX_2026-05-18.txt` proof.

The 16-app fleet is `packages/hrbrlife/*/<slug>/` — 0/16 Pearl-onboarded
at the start of 2026-05-18, 1/16 after Welcome Pearl.

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

## 8. Batch the remaining 15

The smoke driver `melusina-attestdeployer-tool/scripts/smoke-release-entry.sh`
is parametrically clean. To run the fleet:

```bash
for slug_dir in /home/user/Desktop/static_store/packages/hrbrlife/*/*/; do
  test -f "$slug_dir/app.spk" || continue
  test -f "$slug_dir/metadata.json" || continue
  slug=$(basename "$slug_dir")
  OUTPUT_DIR="/tmp/$slug-pearl" \
  WELCOME_PEARL_CATALOG="$slug_dir" \
  bash /home/user/Desktop/static_store/scripts/welcome-pearl-ceremony.sh
done
```

(The driver name carries "welcome-pearl" because it was first — the
logic is fleet-generic. A future rename to
`pearl-onboard-ceremony.sh` is cosmetic.)

Each ceremony costs ~0.002 SOL of vault rent + ~0.001 SOL of publisher
fees, so the 15 remaining apps need ~0.05 SOL of vault headroom and ~0.02
SOL on publisher. Top up via `fund-core-wallets.sh` if needed.

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
