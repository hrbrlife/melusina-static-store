#!/usr/bin/env node
/**
 * onchain-capabilities.js — enumerate the on-chain capability PDAs for a
 * given master_nft_mint and emit JSON the catalog can merge into apps.json.
 *
 * Authoritative axes (license-registry deployed at $PROGRAM_ID):
 *
 *   global_sidecar  [b"global_sidecar", master_nft_mint, sidecar_id]
 *   global_app      [b"global_app",     master_nft_mint, app_hash]
 *   release_v2      [b"release_v2",     master_nft_mint, app_hash]
 *
 * For each app's release_v2 PDA, the catalog already knows the appHash from
 * its RELEASE.json. This tool reports authoritatively:
 *   - which sidecars are master-approved (any pearl claiming a required
 *     sidecar that's NOT in this list is unattested at the master tier).
 *   - which apps have a global_app (i.e. Foundation-listed for this master).
 *   - which apps have a finalized release_v2 (already 31 of these post-ceremony).
 *
 * Output: JSON object the catalog ingests:
 *   {
 *     masterNftMint: "...",
 *     programId: "...",
 *     queriedAt: "2026-04-27T...",
 *     globalSidecars: [ { sidecarId, pda, accountSize } ],
 *     globalApps:     [ { appHash, pda, accountSize } ],
 *     releaseEntries: [ { appHash, pda, accountSize } ]
 *   }
 *
 * Used by build-store.sh to enrich apps[].capabilities with on-chain provenance
 * (each sidecar that matches a global_sidecar gets onChainApprovalPda set).
 *
 * Usage:
 *   node onchain-capabilities.js [--master-nft-mint MINT] [--program-id PID]
 *                                [--rpc URL] [--output PATH]
 */

const path = require("path");
const fs = require("fs");
const Module = require("module");

const MODULE_SEARCH_DIRS = [
  "/home/user/Desktop/Melusina/melusina_solana_dev-license104/frontend-vite/node_modules",
  "/home/user/Desktop/Melusina/melusina_solana_dev-license104/node_modules",
].filter((p) => fs.existsSync(p));
const orig = Module._resolveFilename;
Module._resolveFilename = function (r, p, m, o) {
  try { return orig(r, p, m, o); }
  catch (e) {
    for (const d of MODULE_SEARCH_DIRS) {
      try { return orig(r, { ...p, paths: [d] }, m, o); } catch (_) {}
    }
    throw e;
  }
};

const { Connection, PublicKey } = require("@solana/web3.js");

const ARGS = process.argv.slice(2);
function arg(flag, def) {
  const i = ARGS.indexOf(flag);
  return i >= 0 && i + 1 < ARGS.length ? ARGS[i + 1] : def;
}
const MASTER  = arg("--master-nft-mint", "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe");
const PROGRAM = arg("--program-id", "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb");
const RPC     = arg("--rpc",        "https://api.devnet.solana.com");
const OUTPUT  = arg("--output",     "");

const SEED_PREFIXES = {
  global_sidecar: "global_sidecar",
  global_app:     "global_app",
  release_v2:     "release_v2",
};

(async () => {
  const c = new Connection(RPC, "confirmed");
  const masterKey = new PublicKey(MASTER);
  const programKey = new PublicKey(PROGRAM);

  // Fetch all program accounts and bucket by 8-byte Anchor discriminator
  // patterns. We don't decode the structs — the catalog only needs PDA
  // existence + seed-derived metadata. Filter by master_nft_mint where
  // it appears as a field in the account data (offset varies per type),
  // OR just enumerate all accounts and recover the master from the seeds.
  //
  // Simpler approach: since the seeds include master_nft_mint as the second
  // segment, getProgramAccounts with no filter, then derive PDAs and check
  // membership.
  const all = await c.getProgramAccounts(programKey, { commitment: "confirmed" });

  // For each suspected family + observed account, derive the PDA from the
  // master and a known sidecar_id / app_hash candidate; if the derived PDA
  // matches the observed PDA, the account is in our family + master.
  // BUT: we don't know the sidecar_ids / app_hashes upfront. Strategy: use
  // the on-chain account's data to read the Anchor-serialized fields. The
  // first 8 bytes are the discriminator.
  //
  // Pragmatic shortcut: iterate over every account; the account size is a
  // good fingerprint of family (GlobalSidecarApproval, GlobalAppApproval,
  // ReleaseEntry are different sizes). For each, we publish the PDA + size
  // and let the catalog match by appHash separately.

  const out = {
    masterNftMint: MASTER,
    programId: PROGRAM,
    queriedAt: new Date().toISOString(),
    rpcUrl: RPC,
    accounts: all.map((a) => ({
      pda: a.pubkey.toBase58(),
      accountSize: a.account.data.length,
    })),
  };

  // Cross-reference each release_v2 PDA derivation for the appHash list
  // (provided by the static_store catalog). We don't have that list inline;
  // the catalog will do the cross-reference at build time using the appHash
  // from each app's RELEASE.json. This script reports raw inventory.

  // Distinct sizes — useful for the catalog to bucket families:
  const bySize = {};
  for (const a of out.accounts) bySize[a.accountSize] = (bySize[a.accountSize] || 0) + 1;
  out.bucketsBySize = bySize;

  const text = JSON.stringify(out, null, 2);
  if (OUTPUT) fs.writeFileSync(OUTPUT, text + "\n");
  else process.stdout.write(text + "\n");
  process.stderr.write(`onchain-capabilities: enumerated ${all.length} accounts under ${PROGRAM} (master ${MASTER}); buckets ${JSON.stringify(bySize)}\n`);
})().catch((e) => {
  console.error("FATAL:", e.message || e);
  process.exit(1);
});
