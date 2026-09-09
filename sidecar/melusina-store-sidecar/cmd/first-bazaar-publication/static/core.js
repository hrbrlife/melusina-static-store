"use strict";
// Closed original Core3of4 Store-policy/grant ceremony. The original account
// readers and Squads builders below are retained from the governed Store route.
(() => {
  const root=globalThis, encoder=new TextEncoder(), decoder=new TextDecoder("utf-8",{fatal:true});
  const C=Object.freeze({
  "schema": "melusina.original-store-control-governance.v1",
  "origin": "http://127.0.0.1:9200",
  "path": "/store-control/setup/",
  "rpc": "https://api.devnet.solana.com",
  "genesis": "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
  "licenseProgram": "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
  "squadsProgram": "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf",
  "systemProgram": "11111111111111111111111111111111",
  "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  "masterMint": "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe",
  "coreMultisig": "4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V",
  "coreVault": "3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3",
  "coreMasterNftATA": "EA2FEHzhg4ZunhchFhcBMjaVtTh3pGkEy2SG6FEmYepn",
  "rootLicenseMint": "9yfmmcTG8BBiSPHf6kZC77tUzm46VMnfyrLzd3E2ii9J",
  "rootLicensePDA": "733z4wgFiE6xrcMwSxk3xq8if9EdbyYSKFswaDVa5jYT",
  "storeOperator": "CvQ1KRa9LiKDW4ZjY414UbpChYt4HV4SAX3hwhNMnnK5",
  "storePolicy": "GEdMJo6Bk5zjDNwS48aEBpyjfHpasoALriRax1DQ6smZ",
  "storeAuthority": "4J2hbufiTKmvgfxjGVNqhoQXiKVDsYwaor6hcaDKjzZV",
  "domainHash": "1bdcbe62b188e6ffe095d43b5a6a2c7bed70e738d8a5cf3e6d389563fab46592",
  "coreMembers": [
    "ARX39MQQR1c7cT8L9ARbeg7AWw975gPGr9EE9oygKv1P",
    "8stvUEVXhaPiXecztiXc4cAmE2pVrMjBVZSQMNmHU4rC",
    "7hG6N24krBwu2hgNkfin7XVSAUmtcAv7CCUqtzUfMKvV",
    "133bmq4L4iPfcCeGzjYHLtUXFYMQniHb6ZNVBoEnXpWC"
  ],
  "apps": {
    "021x360jnqz798taefscu7r69a0xvvqyhfwfjadq8g2f9wuqm5h0": "Welcome",
    "8kea8reanvm5cw7awrxj8udguh5hf3yfcns01fmq7vq42ps2hvuh": "Personal NamedCoin",
    "uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510": "Account"
  },
  "multisigDiscriminator": "e07479ba44a14fec",
  "vaultTransactionDiscriminator": "a8faa264510ea2cf",
  "proposalDiscriminator": "1a5ebdbb74883521"
});
  function fail(message) { throw new Error(message); }
  function web3() { if (!root.solanaWeb3) fail("the pinned Solana Web3 asset did not load"); return root.solanaWeb3; }
  function bytesEqual(a, b) { if (!a || !b || a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i += 1) d |= a[i] ^ b[i]; return d === 0; }
  function hex(bytes) { return Array.from(bytes, (v) => v.toString(16).padStart(2, "0")).join(""); }
  function concat(...parts) { const n = parts.reduce((s, p) => s + p.length, 0); const o = new Uint8Array(n); let i = 0; for (const p of parts) { o.set(p, i); i += p.length; } return o; }
  function le(value, width) { let n = BigInt(value); if (n < 0n) fail("negative integer is forbidden"); const o = new Uint8Array(width); for (let i = 0; i < width; i += 1) { o[i] = Number(n & 255n); n >>= 8n; } if (n !== 0n) fail("integer exceeds fixed width"); return o; }
  function hexBytes(value, label) { if (!/^[0-9a-f]{64}$/.test(value)) fail(`${label} is not canonical sha256`); return Uint8Array.from(value.match(/../g), (pair) => Number.parseInt(pair, 16)); }
  function pubkey(value, label) { if (typeof value !== "string" || value.length < 32 || value.length > 48) fail(`${label} is not a public key`); try { return new (web3().PublicKey)(value); } catch (_) { fail(`${label} is not a canonical public key`); } }
  function pkBytes(value, label) { return pubkey(value, label).toBytes(); }
  function prefix(bytes, expected, label) { const want = Uint8Array.from(expected.match(/../g), (pair) => Number.parseInt(pair, 16)); if (!bytesEqual(bytes, want)) fail(`${label}: discriminator mismatch`); }
  function stringBytes(value) { const raw = encoder.encode(value); return concat(le(raw.length, 4), raw); }

  class Reader {
    constructor(bytes, label) { this.bytes = Uint8Array.from(bytes); this.label = label; this.i = 0; }
    take(n, label) { if (!Number.isSafeInteger(n) || n < 0 || this.i + n > this.bytes.length) fail(`${this.label}.${label}: truncated`); const out = this.bytes.subarray(this.i, this.i + n); this.i += n; return out; }
    u8(label) { return this.take(1, label)[0]; }
    u16(label) { const b = this.take(2, label); return b[0] | (b[1] << 8); }
    u32(label) { const b = this.take(4, label); return b[0] + b[1] * 0x100 + b[2] * 0x10000 + b[3] * 0x1000000; }
    u64(label) { const b = this.take(8, label); let out = 0n; for (let i = 7; i >= 0; i -= 1) out = (out << 8n) | BigInt(b[i]); return out; }
    pk(label) { try { return new (web3().PublicKey)(this.take(32, label)).toBase58(); } catch (_) { fail(`${this.label}.${label}: invalid public key`); } }
    string(label) { const n = this.u32(`${label}.length`); if (n > 4096) fail(`${this.label}.${label}: oversized string`); return decoder.decode(this.take(n, label)); }
    optionPk(label) { const tag = this.u8(`${label}.tag`); if (tag === 0) return null; if (tag !== 1) fail(`${this.label}.${label}: invalid option`); return this.pk(label); }
    optionI64(label) { const tag = this.u8(`${label}.tag`); if (tag === 0) return null; if (tag !== 1) fail(`${this.label}.${label}: invalid option`); return this.u64(label); }
    optionString(label) { const tag = this.u8(`${label}.tag`); if (tag === 0) return null; if (tag !== 1) fail(`${this.label}.${label}: invalid option`); return this.string(label); }
    vecBytes(label, max) { const n = this.u32(`${label}.length`); if (n > max) fail(`${this.label}.${label}: oversized vector`); return this.take(n, label); }
    pfx(value, label) { prefix(this.take(value.length / 2, label), value, `${this.label}.${label}`); }
    done() { if (this.i !== this.bytes.length) fail(`${this.label}: unexpected trailing bytes`); }
    donePadded() { for (; this.i < this.bytes.length; this.i += 1) if (this.bytes[this.i] !== 0) fail(`${this.label}: nonzero trailing bytes`); }
  }

  function transactionPda(index) { return web3().PublicKey.findProgramAddressSync([encoder.encode("multisig"), pkBytes(C.coreMultisig, "Core multisig"), encoder.encode("transaction"), le(index, 8)], pubkey(C.squadsProgram, "Squads program"))[0].toBase58(); }
  function proposalPda(index) { return web3().PublicKey.findProgramAddressSync([encoder.encode("multisig"), pkBytes(C.coreMultisig, "Core multisig"), encoder.encode("transaction"), le(index, 8), encoder.encode("proposal")], pubkey(C.squadsProgram, "Squads program"))[0].toBase58(); }
  function vaultPda() { return web3().PublicKey.findProgramAddressSync([encoder.encode("multisig"), pkBytes(C.coreMultisig, "Core multisig"), encoder.encode("vault"), Uint8Array.of(0)], pubkey(C.squadsProgram, "Squads program"))[0].toBase58(); }
  function decodeMultisig(data) {
    const r = new Reader(data, "Squads Multisig"); r.pfx(C.multisigDiscriminator, "discriminator"); r.pk("create_key"); const configAuthority = r.pk("config_authority"); const threshold = r.u16("threshold"); const timeLock = r.u32("time_lock"); const transactionIndex = r.u64("transaction_index"); r.u64("stale_transaction_index"); r.optionPk("rent_collector"); r.u8("bump"); const n = r.u32("members.length"); if (n === 0 || n > 32) fail("Squads member count is invalid"); const members = []; for (let i = 0; i < n; i += 1) members.push({ key: r.pk(`members[${i}].key`), permissions: r.u8(`members[${i}].permissions`) }); r.donePadded(); return { configAuthority, threshold, timeLock, transactionIndex, members };
  }
  function decodeVaultTransaction(data) {
    const r = new Reader(data, "Squads VaultTransaction"); r.pfx(C.vaultTransactionDiscriminator, "discriminator"); const multisig = r.pk("multisig"); const creator = r.pk("creator"); const index = r.u64("index"); r.u8("bump"); const vaultIndex = r.u8("vault_index"); r.u8("vault_bump"); const ephemeralSignerBumps = r.vecBytes("ephemeral_signer_bumps", 32); const numSigners = r.u8("message.num_signers"); const numWritableSigners = r.u8("message.num_writable_signers"); const numWritableNonSigners = r.u8("message.num_writable_non_signers"); if (numSigners === 0 || numWritableSigners > numSigners) fail("stored transaction signer header is invalid"); const n = r.u32("message.account_keys.length"); if (n === 0 || n > 64) fail("stored transaction key count is invalid"); const accountKeys = []; for (let i = 0; i < n; i += 1) accountKeys.push(r.pk(`message.account_keys[${i}]`)); const count = r.u32("message.instructions.length"); if (count !== 1) fail("stored transaction must contain exactly one instruction"); const instructions = []; for (let i = 0; i < count; i += 1) { const programIdIndex = r.u8(`message.instructions[${i}].program`); const accountCount = r.u32(`message.instructions[${i}].accounts.length`); if (accountCount > 64) fail("stored transaction account vector is invalid"); const accountIndexes = Array.from(r.take(accountCount, `message.instructions[${i}].accounts`)); const dataLength = r.u32(`message.instructions[${i}].data.length`); if (dataLength > 2048) fail("stored transaction data is too large"); instructions.push({ programIdIndex, accountIndexes, data: r.take(dataLength, `message.instructions[${i}].data`) }); } if (r.u32("message.lookup_tables.length") !== 0) fail("address lookup tables are forbidden"); r.donePadded(); return { multisig, creator, index, vaultIndex, ephemeralSignerBumps, message: { numSigners, numWritableSigners, numWritableNonSigners, accountKeys, instructions } };
  }
  function decodeProposal(data) {
    const r = new Reader(data, "Squads Proposal"); r.pfx(C.proposalDiscriminator, "discriminator"); const multisig = r.pk("multisig"); const transactionIndex = r.u64("transaction_index"); const tag = r.u8("status.tag"); const statuses = ["Draft", "Active", "Rejected", "Approved", "Executing", "Executed", "Cancelled"]; if (tag >= statuses.length) fail("proposal status is invalid"); if (tag !== 4) r.u64("status.timestamp"); r.u8("bump"); const readKeys = (label) => { const n = r.u32(`${label}.length`); if (n > 32) fail(`${label} is too large`); const values = []; for (let i = 0; i < n; i += 1) values.push(r.pk(`${label}[${i}]`)); return values; }; const approved = readKeys("approved"); const rejected = readKeys("rejected"); const cancelled = readKeys("cancelled"); r.donePadded(); return { multisig, transactionIndex, status: statuses[tag], approved, rejected, cancelled };
  }

  function serializeWrappedMessage(message) { if (message.addressTableLookups.length !== 0 || message.compiledInstructions.length !== 1) fail("fixed Store setup message shape is invalid"); const writableSigners = message.header.numRequiredSignatures - message.header.numReadonlySignedAccounts; const writableNonSigners = message.staticAccountKeys.length - message.header.numRequiredSignatures - message.header.numReadonlyUnsignedAccounts; const keys = concat(Uint8Array.of(message.staticAccountKeys.length), ...message.staticAccountKeys.map((key) => key.toBytes())); const instructions = message.compiledInstructions.map((ix) => concat(Uint8Array.of(ix.programIdIndex), Uint8Array.of(ix.accountKeyIndexes.length), Uint8Array.from(ix.accountKeyIndexes), le(ix.data.length, 2), Uint8Array.from(ix.data))); return concat(Uint8Array.of(message.header.numRequiredSignatures, writableSigners, writableNonSigners), keys, Uint8Array.of(instructions.length), ...instructions, Uint8Array.of(0)); }
  function buildVaultCreate(member, index, target) { const wrapped = serializeWrappedMessage(compileInnerMessage(target)); return new (web3().TransactionInstruction)({ programId: pubkey(C.squadsProgram, "Squads program"), keys: [{ pubkey: pubkey(C.coreMultisig, "Core multisig"), isSigner: false, isWritable: true }, { pubkey: pubkey(transactionPda(index), "transaction PDA"), isSigner: false, isWritable: true }, { pubkey: pubkey(member, "creator"), isSigner: true, isWritable: false }, { pubkey: pubkey(member, "rent payer"), isSigner: true, isWritable: true }, { pubkey: pubkey(C.systemProgram, "system program"), isSigner: false, isWritable: false }], data: concat(Uint8Array.of(48,250,78,168,208,226,218,211), Uint8Array.of(0, 0), le(wrapped.length, 4), wrapped, Uint8Array.of(0)) }); }
  function buildProposalCreate(member, index) { return new (web3().TransactionInstruction)({ programId: pubkey(C.squadsProgram, "Squads program"), keys: [{ pubkey: pubkey(C.coreMultisig, "Core multisig"), isSigner: false, isWritable: false }, { pubkey: pubkey(proposalPda(index), "proposal PDA"), isSigner: false, isWritable: true }, { pubkey: pubkey(member, "creator"), isSigner: true, isWritable: false }, { pubkey: pubkey(member, "rent payer"), isSigner: true, isWritable: true }, { pubkey: pubkey(C.systemProgram, "system program"), isSigner: false, isWritable: false }], data: concat(Uint8Array.of(220,60,73,224,30,108,79,159), le(index, 8), Uint8Array.of(0)) }); }
  function buildProposalApprove(member, index) { return new (web3().TransactionInstruction)({ programId: pubkey(C.squadsProgram, "Squads program"), keys: [{ pubkey: pubkey(C.coreMultisig, "Core multisig"), isSigner: false, isWritable: false }, { pubkey: pubkey(member, "member"), isSigner: true, isWritable: true }, { pubkey: pubkey(proposalPda(index), "proposal PDA"), isSigner: false, isWritable: true }], data: concat(Uint8Array.of(144,37,164,136,188,216,42,248), Uint8Array.of(0)) }); }
  function writable(message, index) { if (index < message.numWritableSigners) return true; return index >= message.numSigners && index < message.numSigners + message.numWritableNonSigners; }
  function buildVaultExecute(member, index, stored) { const remaining = stored.message.accountKeys.map((key, position) => ({ pubkey: pubkey(key, `stored account ${position}`), isWritable: writable(stored.message, position), isSigner: position < stored.message.numSigners && key !== C.coreVault })); return new (web3().TransactionInstruction)({ programId: pubkey(C.squadsProgram, "Squads program"), keys: [{ pubkey: pubkey(C.coreMultisig, "Core multisig"), isSigner: false, isWritable: false }, { pubkey: pubkey(proposalPda(index), "proposal PDA"), isSigner: false, isWritable: true }, { pubkey: pubkey(transactionPda(index), "transaction PDA"), isSigner: false, isWritable: false }, { pubkey: pubkey(member, "executor"), isSigner: true, isWritable: false }, ...remaining], data: Uint8Array.of(194,8,161,87,153,164,25,171) }); }
  function assertStoredFixedTransaction(stored, index, target) { const expected = compileInnerMessage(target); const message = stored.message; const expectedWritableSigners = expected.header.numRequiredSignatures - expected.header.numReadonlySignedAccounts; const expectedWritableNonSigners = expected.staticAccountKeys.length - expected.header.numRequiredSignatures - expected.header.numReadonlyUnsignedAccounts; const matching = message.numSigners === expected.header.numRequiredSignatures && message.numWritableSigners === expectedWritableSigners && message.numWritableNonSigners === expectedWritableNonSigners && message.accountKeys.length === expected.staticAccountKeys.length && message.accountKeys.every((key, i) => key === expected.staticAccountKeys[i].toBase58()) && message.instructions.length === 1 && message.instructions[0].programIdIndex === expected.compiledInstructions[0].programIdIndex && message.instructions[0].accountIndexes.length === expected.compiledInstructions[0].accountKeyIndexes.length && message.instructions[0].accountIndexes.every((key, i) => key === expected.compiledInstructions[0].accountKeyIndexes[i]) && bytesEqual(message.instructions[0].data, expected.compiledInstructions[0].data); if (stored.multisig !== C.coreMultisig || stored.index !== index || stored.vaultIndex !== 0 || stored.ephemeralSignerBumps.length !== 0 || !matching) fail("stored VaultTransaction is not the exact fixed Store policy or grant setup"); }

  function canonicalKey(text,label) {
    if(typeof text!=="string"||!/^[A-Za-z0-9_-]{43}$/.test(text))fail(label+" must be canonical base64url Ed25519 public key");
    const bytes=Uint8Array.from(atob(text.replace(/-/g,"+").replace(/_/g,"/")+"="),c=>c.charCodeAt(0));
    const encoded=btoa(String.fromCharCode(...bytes)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
    if(bytes.length!==32||encoded!==text||bytes.every(x=>x===0))fail(label+" is invalid");return bytes;
  }
  function plan(raw) {
    if(typeof raw!=="string"||raw.length>4096)fail("one bounded public setup plan is required");
    const p=JSON.parse(raw),init=p?.action==="initialize_policy",grant=p?.action==="enroll_publisher";
    const fields=["schema","action","pearlCommandPublicKey","humanApprovalPublicKey",...(grant?["appId","policyEpoch","notBefore","expiresAt"]:[])];
    if(!p||(!init&&!grant)||Object.keys(p).sort().join()!==fields.slice().sort().join()||p.schema!==C.schema)fail("unknown Store setup scope or plan field");
    const command=canonicalKey(p.pearlCommandPublicKey,"Pearl command key"),human=canonicalKey(p.humanApprovalPublicKey,"human approval key");
    if(bytesEqual(command,human)||[...C.coreMembers,C.storeAuthority].some(k=>bytesEqual(pkBytes(k,"existing authority"),command)||bytesEqual(pkBytes(k,"existing authority"),human)))fail("command and human approval keys must be distinct from each other and existing authorities");
    if(grant&&(!Object.hasOwn(C.apps,p.appId)||!Number.isSafeInteger(p.policyEpoch)||p.policyEpoch<1||!Number.isSafeInteger(p.notBefore)||p.notBefore<1||!Number.isSafeInteger(p.expiresAt)||p.expiresAt<=p.notBefore||p.expiresAt-p.notBefore>366*86400))fail("publisher grant must name one original app, observed epoch and bounded lifetime");
    const normalized=Object.fromEntries(fields.map(k=>[k,p[k]]));
    if(JSON.stringify(normalized)!==raw.trim())fail("setup plan must be exact canonical JSON without duplicate, reordered, aliased or additional fields");
    return Object.freeze(normalized);
  }
  async function digest(p){return hex(new Uint8Array(await crypto.subtle.digest("SHA-256",encoder.encode(C.schema+"\0"+JSON.stringify(p)))));}
  function disc(text){return Uint8Array.from(text.match(/../g),x=>parseInt(x,16));}
  async function appHash(p){return new Uint8Array(await crypto.subtle.digest("SHA-256",encoder.encode(p.appId)));}
  async function grantPda(p){return web3().PublicKey.findProgramAddressSync([encoder.encode("store_publisher_grant"),pkBytes(C.storePolicy,"policy"),await appHash(p),pkBytes(C.coreMembers[0],"original publisher")],pubkey(C.licenseProgram,"registry"))[0].toBase58();}
  function setupInstruction(p,appID,grant) {
    const common=[C.storeOperator,C.rootLicensePDA,C.coreVault,C.masterMint,C.coreMasterNftATA,C.systemProgram,C.tokenProgram];
    const addresses=p.action==="initialize_policy"?[C.storePolicy,...common]:[grant,C.storePolicy,...common];
    const accounts=addresses.map((key,i)=>({pubkey:pubkey(key,"fixed setup account"),isSigner:key===C.coreVault,isWritable:i===0||key===C.coreVault}));
    const data=p.action==="initialize_policy"?concat(disc("a6a7fd0a6d4fe47f"),pkBytes(C.rootLicenseMint,"license"),hexBytes(C.domainHash,"domain"),canonicalKey(p.pearlCommandPublicKey,"Pearl key"),canonicalKey(p.humanApprovalPublicKey,"human key")):concat(disc("b3c66d00d0a9b91a"),appID,pkBytes(C.coreVault,"publisher vault"),pkBytes(C.coreMembers[0],"publisher key"),le(3,2),le(p.notBefore,8),le(p.expiresAt,8),le(p.policyEpoch,8));
    return new (web3().TransactionInstruction)({programId:pubkey(C.licenseProgram,"registry"),keys:accounts,data});
  }
  function compileInnerMessage(target){return new (web3().TransactionMessage)({payerKey:pubkey(C.coreVault,"Core vault"),recentBlockhash:web3().PublicKey.default.toBase58(),instructions:[target]}).compileToV0Message();}
  function connection(){return root.MelusinaMSBRegistry.connection();}
  function owned(info,owner,label){if(!info||info.executable||info.owner.toBase58()!==owner)fail(label+" absent, executable or owned by another program");return new Uint8Array(info.data);}
  function assertFixedAddresses(){
    const registry=pubkey(C.licenseProgram,"registry"),license=pkBytes(C.rootLicenseMint,"license"),domain=hexBytes(C.domainHash,"domain");
    const derive=seeds=>web3().PublicKey.findProgramAddressSync(seeds,registry)[0].toBase58();
    const ata=web3().PublicKey.findProgramAddressSync([pkBytes(C.coreVault,"vault"),pkBytes(C.tokenProgram,"token"),pkBytes(C.masterMint,"Master")],pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL","ATA program"))[0].toBase58();
    if(derive([encoder.encode("license"),license])!==C.rootLicensePDA||derive([encoder.encode("store_operator"),license,domain])!==C.storeOperator||derive([encoder.encode("store_control_policy"),license,domain])!==C.storePolicy||ata!==C.coreMasterNftATA)fail("fixed Store or Master account derivation changed");
  }
  function requireOriginalCore(m){
    if(m.threshold!==3||m.timeLock!==0||m.members.length!==4||new Set(m.members.map(x=>x.key)).size!==4||m.members.some(x=>!C.coreMembers.includes(x.key)||x.permissions!==7)||vaultPda()!==C.coreVault)fail("original Core3of4 authority changed");
  }
  function decodePolicy(data,p){
    if(data.length!==299)fail("Store policy has another allocation");const r=new Reader(data,"StoreControlPolicy");r.pfx("e0b792e2ff97be93","discriminator");
    const license=r.pk("license"),domain=hex(r.take(32,"domain")),authority=r.pk("authority"),operator=r.pk("operator"),command=r.take(32,"Pearl key"),human=r.take(32,"human key"),epoch=r.u64("epoch"),status=r.u8("status");
    r.take(80,"audit");r.optionI64("retiredAt");r.u8("bump");r.donePadded();
    if(license!==C.rootLicenseMint||domain!==C.domainHash||authority!==C.storeAuthority||operator!==C.storeOperator||status!==0||epoch<1n||!bytesEqual(command,canonicalKey(p.pearlCommandPublicKey,"Pearl key"))||!bytesEqual(human,canonicalKey(p.humanApprovalPublicKey,"human key")))fail("Store policy authority, scope or keys differ from reviewed plan");return epoch;
  }
  function decodeGrant(data,p,expectedApp) {
    if(data.length!==319)fail("Store publisher grant has another allocation");const r=new Reader(data,"StorePublisherGrant");r.pfx("998c0ce972d5c1fb","discriminator");
    const policy=r.pk("policy"),app=r.take(32,"app"),vault=r.pk("publisher vault"),publisher=r.take(32,"publisher key"),actions=r.u16("actions"),notBefore=r.u64("notBefore"),expiresAt=r.u64("expiresAt"),epoch=r.u64("epoch"),status=r.u8("status");
    const previous=r.optionPk("previous");r.take(80,"audit");const revokedAt=r.optionI64("revokedAt"),revokedBy=r.optionPk("revokedBy");r.u8("bump");r.donePadded();
    if(policy!==C.storePolicy||!bytesEqual(app,expectedApp)||vault!==C.coreVault||!bytesEqual(publisher,pkBytes(C.coreMembers[0],"publisher"))||actions!==3||notBefore!==BigInt(p.notBefore)||expiresAt!==BigInt(p.expiresAt)||epoch!==1n||status!==0||previous!==null||revokedAt!==null||revokedBy!==null)fail("existing publisher grant differs from the exact reviewed enrollment");return {epoch,expiresAt,notBefore};
  }
  async function context(p,index=null,conn=connection()){
    assertFixedAddresses();if(await conn.getGenesisHash()!==C.genesis)fail("not original devnet");
    const grant=p.action==="enroll_publisher"?await grantPda(p):null;
    const addresses=[C.coreMultisig,C.coreMasterNftATA,C.masterMint,C.storeOperator,C.rootLicensePDA,C.storePolicy,C.coreVault,C.coreMembers[0],...(grant?[grant]:[]),...(index!==null?[transactionPda(index),proposalPda(index)]:[])];
    const result=await conn.getMultipleAccountsInfoAndContext(addresses.map(x=>pubkey(x,"fixed account")),{commitment:"finalized"});
    if(!result.context?.slot||result.value.length!==addresses.length)fail("incomplete finalized account cohort");const infos=Object.fromEntries(addresses.map((x,i)=>[x,result.value[i]]));
    const m=decodeMultisig(owned(infos[C.coreMultisig],C.squadsProgram,"Core"));requireOriginalCore(m);
    const ata=owned(infos[C.coreMasterNftATA],C.tokenProgram,"Master ATA"),mint=owned(infos[C.masterMint],C.tokenProgram,"Master mint");
    if(ata.length!==165||!bytesEqual(ata.slice(0,32),pkBytes(C.masterMint,"Master"))||!bytesEqual(ata.slice(32,64),pkBytes(C.coreVault,"Core vault"))||!bytesEqual(ata.slice(64,72),le(1,8))||ata[108]!==1||mint.length!==82||!bytesEqual(mint.slice(36,44),le(1,8))||mint[44]!==0||mint[45]!==1)fail("original Core-owned Master NFT custody changed");
    const op=owned(infos[C.storeOperator],C.licenseProgram,"Store operator");
    if(op.length!==193||!bytesEqual(op.slice(0,8),disc("7cd5bb30bf26839a"))||!bytesEqual(op.slice(8,40),pkBytes(C.rootLicenseMint,"license"))||hex(op.slice(40,72))!==C.domainHash||!bytesEqual(op.slice(72,104),pkBytes(C.storeAuthority,"Store authority"))||op[136]!==1||op[142]!==0)fail("original active root Store operator changed");
    const license=owned(infos[C.rootLicensePDA],C.licenseProgram,"Store license");if(license.length<104||!bytesEqual(license.slice(0,8),disc("7ad03d7ba408976f"))||!bytesEqual(license.slice(8,40),pkBytes(C.rootLicenseMint,"license"))||!bytesEqual(license.slice(72,104),pkBytes(C.masterMint,"Master")))fail("Store license differs");
    const registry=await root.MelusinaMSBRegistry.context(conn);if(registry.program.state!=="complete")fail("reviewed StoreControl registry artifact is not finalized");
    let policyEpoch=null;if(infos[C.storePolicy])policyEpoch=decodePolicy(owned(infos[C.storePolicy],C.licenseProgram,"Store policy"),p);
    if(p.action==="enroll_publisher"&&(policyEpoch===null||policyEpoch!==BigInt(p.policyEpoch)))fail("enrollment policy epoch differs from fresh chain");
    const app=grant?await appHash(p):null;let grantValue=null;if(grant&&infos[grant])grantValue=decodeGrant(owned(infos[grant],C.licenseProgram,"publisher grant"),p,app);
    const target=setupInstruction(p,app,grant);
    owned(infos[C.coreVault],C.systemProgram,"original Core rent vault");owned(infos[C.coreMembers[0]],C.systemProgram,"original publisher funding account");
    const [policyRent,grantRent,vaultFloor]=await Promise.all([299,319,0].map(n=>conn.getMinimumBalanceForRentExemption(n,"finalized")));
    const vaultLamports=infos[C.coreVault].lamports,publisherLamports=infos[C.coreMembers[0]].lamports;
    if([policyRent,grantRent,vaultFloor,vaultLamports,publisherLamports].some(n=>!Number.isSafeInteger(n)||n<0)||policyRent===0||grantRent===0||vaultFloor===0||infos[C.coreVault].data.length||infos[C.coreMembers[0]].data.length)fail("original setup funding account or rent quote is invalid");
    const funding={vaultLamports,publisherLamports,policyRent,grantRent,vaultFloor,allOriginalSetupRent:policyRent+3*grantRent+vaultFloor,operationRent:(p.action==="initialize_policy"?policyRent:grantRent)+vaultFloor};
    const stored=index!==null&&infos[transactionPda(index)]?decodeVaultTransaction(owned(infos[transactionPda(index)],C.squadsProgram,"stored transaction")):null;
    if(stored){assertStoredFixedTransaction(stored,index,target);if(stored.creator!==C.coreMembers[0])fail("setup creator is not original publisher");}
    const proposal=index!==null&&infos[proposalPda(index)]?decodeProposal(owned(infos[proposalPda(index)],C.squadsProgram,"proposal")):null;
    if(proposal&&(proposal.multisig!==C.coreMultisig||proposal.transactionIndex!==index||[...proposal.approved,...proposal.rejected,...proposal.cancelled].some(x=>!C.coreMembers.includes(x))||new Set(proposal.approved).size!==proposal.approved.length))fail("proposal identity or voter set changed");
    return {slot:result.context.slot,funding,multisig:m,policyEpoch,grant,grantPresent:!!grantValue,grantValue,stored,proposal,target,connection:conn};
  }
  async function authorize(action,p,index,member,conn=connection()){
    if(!["fund","create","propose","approve","execute"].includes(action)||!C.coreMembers.includes(member)||typeof index!=="bigint"||index<1n)fail("unknown bounded Core operation");
    const c=await context(p,index,conn);
    if(action==="fund"){
      if(p.action!=="initialize_policy"||member!==C.coreMembers[0]||c.policyEpoch!==null||c.funding.vaultLamports>=c.funding.allOriginalSetupRent||c.funding.publisherLamports<10010000||c.funding.allOriginalSetupRent-c.funding.vaultLamports>10000000)fail("one bounded original publisher funding action is unavailable");
      return {context:c,instructions:[web3().SystemProgram.transfer({fromPubkey:pubkey(C.coreMembers[0],"original publisher"),toPubkey:pubkey(C.coreVault,"original Core vault"),lamports:10000000})]};
    }
    if(c.funding.vaultLamports<c.funding.operationRent)fail("original Core vault lacks the quoted setup rent and its own rent floor");
    if(p.action==="initialize_policy"&&c.policyEpoch!==null)fail("Store policy is already initialized");
    if(p.action==="enroll_publisher"&&(c.grantPresent||p.expiresAt<=Math.floor(Date.now()/1000)))fail("scoped grant is already present or review has expired");
    let instruction;
    if(action==="create") {if(member!==C.coreMembers[0]||c.stored||c.proposal||index!==c.multisig.transactionIndex+1n)fail("only original publisher may reserve the next exact Core index");instruction=buildVaultCreate(member,index,c.target);}
    else {if(!c.stored)fail("exact stored setup transaction is absent");if(action==="propose"){if(member!==C.coreMembers[0]||c.proposal)fail("original setup proposal already exists or proposer differs");instruction=buildProposalCreate(member,index);}
      else {if(!c.proposal||c.proposal.rejected.length||c.proposal.cancelled.length)fail("proposal absent or has a refused disposition");if(action==="approve"){if(c.proposal.status!=="Active"||c.proposal.approved.includes(member))fail("proposal needs a distinct active approval");instruction=buildProposalApprove(member,index);}else{if(c.proposal.status!=="Approved"||c.proposal.approved.length<3)fail("three original Core approvals are required");instruction=buildVaultExecute(member,index,c.stored);}}}
    return {context:c,instructions:[instruction]};
  }
  function outer(member,instructions,blockhash){return new (web3().VersionedTransaction)(new (web3().TransactionMessage)({payerKey:pubkey(member,"Core member"),recentBlockhash:blockhash,instructions}).compileToV0Message());}
  root.MelusinaStorePolicySetup=Object.freeze({constants:C,plan,digest,canonicalKey,appHash,grantPda,setupInstruction,compileInnerMessage,serializeWrappedMessage,transactionPda,proposalPda,decodeMultisig,decodeVaultTransaction,decodeProposal,decodePolicy,decodeGrant,requireOriginalCore,assertFixedAddresses,buildVaultCreate,buildProposalCreate,buildProposalApprove,buildVaultExecute,assertStoredFixedTransaction,context,authorize,outer,connection,simulate:root.MelusinaMSBRegistry.simulate});
})();
