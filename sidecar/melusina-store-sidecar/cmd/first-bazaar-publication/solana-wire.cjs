'use strict';
// Pure canonical wire parser copied from chrome-cdp-wallet-login.js, lines252–427.
// No signer, RPC, browser control or action namespace is imported.
const crypto = require('node:crypto');
const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58(bytes) {
  let n = 0n;
  for (const byte of bytes) n = (n << 8n) + BigInt(byte);
  let result = '';
  while (n > 0n) {
    result = alphabet[Number(n % 58n)] + result;
    n /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    result = '1' + result;
  }
  return result || '1';
}

function base58Decode(value) {
  if (typeof value !== 'string' || !value) throw new Error('base58 public key is missing');
  let number = 0n;
  for (const character of value) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) throw new Error('base58 public key contains an invalid character');
    number = number * 58n + BigInt(digit);
  }
  const bytes = [];
  while (number > 0n) {
    bytes.unshift(Number(number & 0xffn));
    number >>= 8n;
  }
  for (const character of value) {
    if (character !== '1') break;
    bytes.unshift(0);
  }
  return Buffer.from(bytes);
}

function assertBase58PublicKey(label, value) {
  const bytes = base58Decode(value);
  if (bytes.length !== 32) throw new Error(`${label} is not a 32-byte base58 public key`);
  return value;
}

function decodeShortU16(bytes, offset) {
  if (!Buffer.isBuffer(bytes)) bytes = Buffer.from(bytes);
  let value = 0;
  let shift = 0;
  for (let index = 0; index < 3; index++) {
    if (offset >= bytes.length) throw new Error('truncated Solana shortvec');
    const byte = bytes[offset++];
    value |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      if (value > 0xffff || (index > 0 && (byte & 0x7f) === 0)) throw new Error('non-canonical Solana shortvec');
      return { value, next: offset };
    }
    shift += 7;
  }
  throw new Error('Solana shortvec exceeds u16');
}

function encodeShortU16(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw new Error('shortvec value is outside u16');
  const output = [];
  do {
    let byte = value & 0x7f;
    value >>>= 7;
    if (value) byte |= 0x80;
    output.push(byte);
  } while (value);
  return Buffer.from(output);
}

// Parse only enough of a canonical Solana wire transaction to produce a
// review receipt. It has no signing or RPC capability, and rejects trailing
// bytes so it cannot silently describe a prefix of another transaction.
function parseSolanaWireTransaction(value) {
  const bytes = Buffer.from(value);
  if (bytes.length < 1 || bytes.length > 4096) throw new Error('Solana wire transaction length is outside the capture limit');
  let offset = 0;
  const signatures = decodeShortU16(bytes, offset);
  offset = signatures.next;
  const signatureBytes = signatures.value * 64;
  if (signatures.value < 1 || signatures.value > 64 || offset + signatureBytes >= bytes.length) {
    throw new Error('invalid Solana transaction signature vector');
  }
  const signatureOffset = offset;
  offset += signatureBytes;
  const messageOffset = offset;
  let version = 'legacy';
  if (bytes[offset] & 0x80) {
    const requested = bytes[offset] & 0x7f;
    if (requested !== 0) throw new Error(`unsupported Solana transaction version ${requested}`);
    version = 0;
    offset++;
  }
  if (offset + 3 > bytes.length) throw new Error('truncated Solana message header');
  const numRequiredSignatures = bytes[offset++];
  const numReadonlySignedAccounts = bytes[offset++];
  const numReadonlyUnsignedAccounts = bytes[offset++];
  if (numRequiredSignatures !== signatures.value) throw new Error('Solana signature vector does not match message header');
  const accountCount = decodeShortU16(bytes, offset);
  offset = accountCount.next;
  if (accountCount.value < numRequiredSignatures || accountCount.value > 256 || offset + accountCount.value * 32 + 32 > bytes.length) {
    throw new Error('invalid Solana static account vector');
  }
  const accountKeys = [];
  for (let index = 0; index < accountCount.value; index++) {
    accountKeys.push(base58(bytes.subarray(offset, offset + 32)));
    offset += 32;
  }
  const recentBlockhash = base58(bytes.subarray(offset, offset + 32));
  offset += 32;
  const instructionCount = decodeShortU16(bytes, offset);
  offset = instructionCount.next;
  if (instructionCount.value > 64) throw new Error('Solana transaction has too many instructions for capture');
  const instructions = [];
  for (let index = 0; index < instructionCount.value; index++) {
    if (offset >= bytes.length) throw new Error('truncated Solana instruction program index');
    const programIdIndex = bytes[offset++];
    const accounts = decodeShortU16(bytes, offset);
    offset = accounts.next;
    if (accounts.value > 256 || offset + accounts.value > bytes.length) throw new Error('invalid Solana instruction account indexes');
    const accountIndexes = [...bytes.subarray(offset, offset + accounts.value)];
    offset += accounts.value;
    const data = decodeShortU16(bytes, offset);
    offset = data.next;
    if (data.value > 2048 || offset + data.value > bytes.length) throw new Error('invalid Solana instruction data');
    const payload = bytes.subarray(offset, offset + data.value);
    offset += data.value;
    instructions.push({
      programIdIndex,
      programId: programIdIndex < accountKeys.length ? accountKeys[programIdIndex] : null,
      accountIndexes,
      dataLength: payload.length,
      dataHex: payload.toString('hex'),
      dataSha256: crypto.createHash('sha256').update(payload).digest('hex'),
      discriminatorHex: payload.subarray(0, 8).toString('hex'),
    });
  }
  let addressTableLookups = 0;
  if (version === 0) {
    const lookupCount = decodeShortU16(bytes, offset);
    offset = lookupCount.next;
    if (lookupCount.value > 32) throw new Error('too many Solana address-table lookups for capture');
    addressTableLookups = lookupCount.value;
    for (let index = 0; index < lookupCount.value; index++) {
      if (offset + 32 > bytes.length) throw new Error('truncated Solana address-table lookup key');
      offset += 32;
      const writable = decodeShortU16(bytes, offset);
      offset = writable.next;
      if (writable.value > 256 || offset + writable.value > bytes.length) throw new Error('invalid Solana writable lookup indexes');
      offset += writable.value;
      const readonly = decodeShortU16(bytes, offset);
      offset = readonly.next;
      if (readonly.value > 256 || offset + readonly.value > bytes.length) throw new Error('invalid Solana readonly lookup indexes');
      offset += readonly.value;
    }
  }
  if (offset !== bytes.length) throw new Error('trailing bytes after canonical Solana transaction');
  return {
    wireBytes: bytes.length,
    transactionSha256: crypto.createHash('sha256').update(bytes).digest('hex'),
    messageSha256: crypto.createHash('sha256').update(bytes.subarray(messageOffset)).digest('hex'),
    version,
    signatures: signatures.value,
    signatureOffset,
    messageOffset,
    numRequiredSignatures,
    numReadonlySignedAccounts,
    numReadonlyUnsignedAccounts,
    feePayer: accountKeys[0],
    staticAccountKeys: accountKeys,
    recentBlockhash,
    addressTableLookups,
    instructions,
  };
}

module.exports = {base58, base58Decode, decodeShortU16, encodeShortU16, parseSolanaWireTransaction};
