// Send the Store provider's release revoke instruction to a disposable local
// validator running the real registry. The release is registered by the
// contracts producer with a fresh Ed25519 publisher signature first.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const contractsRoot = process.env.ESTATE_CONTRACTS_ROOT;
const programBinary = process.env.ESTATE_REVOKE_PROGRAM;
const ledgerRoot = process.env.ESTATE_REVOKE_LEDGER_ROOT;
const solanaBin = process.env.ESTATE_SOLANA_BIN;
assert.ok(contractsRoot && programBinary && ledgerRoot && solanaBin,
  'RELEASE_REVOKE_VALIDATOR_INPUTS_REQUIRED');
const require = createRequire(join(contractsRoot, 'package.json'));
const web3 = require('@solana/web3.js');
const ix = await import(pathToFileURL(join(contractsRoot, 'scripts/estate/lib/chain-ix.mjs')));
const seed = await import(pathToFileURL(join(contractsRoot, 'scripts/estate/lib/seed-catalogue-ix.mjs')));
const {
  Connection, Ed25519Program, Keypair, PublicKey, SystemProgram,
  Transaction, TransactionInstruction, sendAndConfirmTransaction,
} = web3;

const registry = new PublicKey(process.env.ESTATE_REVOKE_PROGRAM_ID ||
  '7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb');
const mint = new PublicKey(process.env.ESTATE_REVOKE_MASTER_MINT ||
  'B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe');
const tokenProgram = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
const holder = Keypair.generate();
const appHash = crypto.randomBytes(32);
const approval = crypto.randomBytes(32);
function sandstormAppId(bytes) {
  const alphabet = '0123456789acdefghjkmnpqrstuvwxyz';
  let bits = 0, carry = 0, out = '';
  for (const byte of bytes) {
    carry = (carry << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += alphabet[(carry >> bits) & 31];
      carry &= (1 << bits) - 1;
    }
  }
  if (bits) out += alphabet[(carry << (5 - bits)) & 31];
  return out;
}
const appId = crypto.createHash('sha256').update(sandstormAppId(approval)).digest();
const releaseHash = crypto.randomBytes(32);
const publisher = crypto.generateKeyPairSync('ed25519');
const pubRaw = publisher.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const [releasePda] = PublicKey.findProgramAddressSync(
  [Buffer.from('release_v2'), mint.toBuffer(), appHash], registry);
const ata = PublicKey.findProgramAddressSync(
  [holder.publicKey.toBuffer(), tokenProgram.toBuffer(), mint.toBuffer()],
  new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'))[0];
const sha = (value) => crypto.createHash('sha256').update(value).digest('hex');

// Mint and custody account are the preceding foundation's local-validator
// state. All release state below is created and changed by signed program
// transactions; no ReleaseEntry bytes are inserted into the validator.
const mintData = Buffer.alloc(82);
mintData.writeBigUInt64LE(1n, 36);
mintData[45] = 1;
const ataData = Buffer.alloc(165);
mint.toBuffer().copy(ataData, 0);
holder.publicKey.toBuffer().copy(ataData, 32);
ataData.writeBigUInt64LE(1n, 64);
ataData[108] = 1;
const dir = mkdtempSync(join(ledgerRoot, 'revoke-validator-'));
function accountFile(name, owner, data) {
  const file = join(dir, `${name}.json`);
  writeFileSync(file, JSON.stringify({ pubkey: name, account: {
    lamports: 1_000_000_000, data: [data.toString('base64'), 'base64'],
    owner: owner.toBase58(), executable: false, rentEpoch: 0, space: data.length,
  } }));
  return ['--account', name, file];
}
const port = Number(process.env.ESTATE_REVOKE_RPC_PORT || 28759);
const validator = spawn(join(solanaBin, 'solana-test-validator'), [
  '--ledger', join(dir, 'ledger'), '--reset', '--quiet', '--bind-address', '127.0.0.1',
  '--rpc-port', String(port), '--faucet-port', String(port + 1000),
  '--gossip-port', String(port + 2000), '--dynamic-port-range', `${port + 3000}-${port + 3050}`,
  '--bpf-program', registry.toBase58(), programBinary,
  ...accountFile(mint.toBase58(), tokenProgram, mintData),
  ...accountFile(ata.toBase58(), tokenProgram, ataData),
], { stdio: ['ignore', 'ignore', 'pipe'] });
let validatorError = '';
validator.stderr.on('data', (chunk) => { validatorError += chunk.toString(); });
const rpc = new Connection(`http://127.0.0.1:${port}`, 'confirmed');
async function send(instructions, label) {
  try {
    return await sendAndConfirmTransaction(rpc, new Transaction().add(...instructions), [holder],
      { commitment: 'confirmed', skipPreflight: false });
  } catch (error) {
    throw new Error(`${label}: ${error.message}\n${(error.logs || []).join('\n')}`);
  }
}
function producerInstruction() {
  const source = join(import.meta.dirname, 'mel-release-provider.py');
  const script = [
    'import importlib.util, json, sys',
    'spec = importlib.util.spec_from_file_location("mel_release_provider", sys.argv[1])',
    'mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)',
    'print(json.dumps(mod.revoke_instruction(sys.argv[2], {"vault": sys.argv[3]}, sys.argv[4])))',
  ].join('\n');
  const child = spawnSync('python3', ['-B', '-c', script, source,
    releasePda.toBase58(), holder.publicKey.toBase58(), ata.toBase58()], {
    encoding: 'utf8', env: { ...process.env,
      MEL_PROGRAM_ID: registry.toBase58(), MEL_RELEASE_MASTER_NFT_MINT: mint.toBase58() },
  });
  assert.equal(child.status, 0, `RELEASE_REVOKE_STORE_PRODUCER_MUST_BUILD_INSTRUCTION: ${child.stderr}`);
  return JSON.parse(child.stdout);
}
let result;
try {
  const deadline = Date.now() + 90_000;
  for (;;) {
    try { await rpc.getLatestBlockhash('confirmed'); break; } catch (error) {
      if (validator.exitCode !== null || Date.now() > deadline) {
        throw new Error(`RELEASE_REVOKE_VALIDATOR_MUST_START: ${validatorError || error}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
  const genesis = await rpc.getGenesisHash();
  assert.ok(!new Set([
    'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG',
    '4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY',
    '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d',
  ]).has(genesis), 'RELEASE_REVOKE_LOCAL_GENESIS_REQUIRED');
  const airdrop = await rpc.requestAirdrop(holder.publicKey, 5_000_000_000);
  await rpc.confirmTransaction({ signature: airdrop, ...(await rpc.getLatestBlockhash()) }, 'confirmed');
  const payload = seed.releaseEntrySignedPayloadHash({
    masterNftMint: mint, appHash, appId, releaseHash, version: '1.0.0',
    coreMultisig: holder.publicKey, publisherEd25519PublicKey: pubRaw,
  });
  const signature = crypto.sign(null, payload, publisher.privateKey);
  const register = seed.registerReleaseEntry({ programId: registry, appHash, appId, releaseHash,
    version: '1.0.0', publisherSquadsVault: holder.publicKey,
    publisherEd25519PublicKey: pubRaw, signature, signedPayloadHash: payload });
  const registerIx = new TransactionInstruction({ programId: registry, data: register['data'], keys: [
    { pubkey: releasePda, isWritable: true, isSigner: false },
    { pubkey: holder.publicKey, isWritable: true, isSigner: true },
    { pubkey: mint, isWritable: false, isSigner: false },
    { pubkey: ata, isWritable: false, isSigner: false },
    { pubkey: new PublicKey('Sysvar1nstructions1111111111111111111111111'), isWritable: false, isSigner: false },
    { pubkey: SystemProgram.programId, isWritable: false, isSigner: false },
    { pubkey: tokenProgram, isWritable: false, isSigner: false },
  ] });
  const verifyIx = Ed25519Program.createInstructionWithPublicKey({
    publicKey: pubRaw, signature, message: payload,
  });
  const registerTx = await send([verifyIx, registerIx], 'RELEASE_REVOKE_SIGNED_REGISTER_MUST_EXECUTE');
  const activeRaw = await rpc.getAccountInfo(releasePda, 'confirmed');
  assert.ok(activeRaw && activeRaw.owner.equals(registry), 'RELEASE_REVOKE_SIGNED_REGISTER_MUST_CREATE_ENTRY');
  const active = ix.decodeStoreChainAccount('ReleaseEntry', activeRaw['data']);
  assert.equal(active.status, 'Active', 'RELEASE_REVOKE_ACTIVE_TWIN_MUST_READ_BACK');
  assert.equal(active.signedPayloadHash, payload.toString('hex'),
    'RELEASE_REVOKE_SIGNED_RELEASE_HASH_MUST_READ_BACK');
  const produced = producerInstruction();
  assert.equal(produced.programId, registry.toBase58());
  assert.deepEqual(produced['accounts'].map((a) => a.pubkey),
    [releasePda, holder.publicKey, mint, ata, tokenProgram].map((p) => p.toBase58()));
  const revokeIx = new TransactionInstruction({
    programId: new PublicKey(produced.programId), data: Buffer.from(produced['data'], 'base64'),
    keys: produced['accounts'].map((a) => ({ ...a, pubkey: new PublicKey(a.pubkey) })),
  });
  const revokeTx = await send([revokeIx], 'RELEASE_REVOKE_STORE_PRODUCER_MUST_EXECUTE');
  const revokedRaw = await rpc.getAccountInfo(releasePda, 'confirmed');
  const revoked = ix.decodeStoreChainAccount('ReleaseEntry', revokedRaw['data']);
  assert.equal(revoked.status, 'Revoked', 'RELEASE_REVOKE_STORE_PRODUCER_MUST_MARK_REVOKED');
  assert.ok(Number(revoked.revokedAt) > 0, 'RELEASE_REVOKE_TIMESTAMP_MUST_READ_BACK');
  assert.equal(revoked.signedPayloadHash, payload.toString('hex'),
    'RELEASE_REVOKE_SIGNED_RELEASE_MUST_REMAIN_BOUND');
  result = { genesis, program: registry.toBase58(), binarySha256: sha(readFileSync(programBinary)),
    releaseEntryPda: releasePda.toBase58(), publisherPubkey: pubRaw.toString('hex'),
    packageId: sandstormAppId(approval), approvalHash: approval.toString('hex'),
    releaseAppHash: appHash.toString('hex'),
    releaseHash: releaseHash.toString('hex'), masterNftMint: mint.toBase58(),
    signedPayloadHash: payload.toString('hex'), activeStatus: active.status,
    revokedStatus: revoked.status, revokedAt: Number(revoked.revokedAt), registerTx, revokeTx };
  if (process.env.ESTATE_REVOKE_READBACK_DIR) {
    const readbackDir = process.env.ESTATE_REVOKE_READBACK_DIR;
    mkdirSync(readbackDir, { recursive: true });
    writeFileSync(join(readbackDir, 'active-release-entry.bin'), activeRaw['data']);
    writeFileSync(join(readbackDir, 'revoked-release-entry.bin'), revokedRaw['data']);
    writeFileSync(join(readbackDir, 'release-readback.json'), `${JSON.stringify(result, null, 2)}\n`);
  }
  console.log(`RELEASE_REVOKE_VALIDATOR_PASS ${JSON.stringify(result)}`);
} finally {
  const socket = rpc._rpcWebSocket;
  if (socket) { socket.reconnect = false; clearTimeout(socket.reconnect_timer_id); socket.close(); }
  validator.kill('SIGKILL');
  rmSync(dir, { recursive: true, force: true });
}
