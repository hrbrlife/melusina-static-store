"""Product wire verification for governed Store recall evidence.

The authority argument is projected from the Shell-verified estate profile,
never from a recall receipt or a request body.
"""

import base64
import hashlib
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
REVOKE = hashlib.sha256(b"global:revoke_release_entry").digest()[:8]


def b58decode(value):
    if not isinstance(value, str) or not value:
        raise ValueError("base58-empty")
    n = 0
    for char in value:
        n = n * 58 + ALPHABET.index(char)
    width = len(value) - len(value.lstrip("1"))
    return bytes(width) + (n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b"")


def verify_pointer(pointer, authority, catalog_sha):
    """Mirror app_catalog.go's signed message, including the estate domain."""
    try:
        if (pointer["schema"] != "melusina-app-catalog-pointer-v1" or
                pointer["catalogSha256"] != catalog_sha or
                pointer["servingDomainHash"] != authority["storeDomainHash"]):
            raise ValueError("pointer scope")
        key = b58decode(authority["storeOperatorKey"])
        if len(key) != 32:
            raise ValueError("key")
        message = pointer_message(pointer)
        sig = b58decode(pointer["operatorSignature"])
        if len(sig) != 64:
            raise ValueError("signature")
        Ed25519PublicKey.from_public_bytes(key).verify(sig, bytes(message))
    except (KeyError, TypeError, ValueError, InvalidSignature, OverflowError) as exc:
        raise ValueError("estate-drill-pointer-signature-invalid") from exc
    return True


def pointer_message(pointer):
    message = bytearray(b"melusina-app-catalog-pointer-v1\x00")
    for field in ("appId", "packageId", "version"):
        message.extend(hashlib.sha256(pointer[field].encode()).digest())
    for field in ("appHash", "releaseHash", "stageId", "catalogSha256"):
        message.extend(bytes.fromhex(pointer[field]))
    message.extend(hashlib.sha256(pointer.get("previousVersion", "").encode()).digest())
    message.extend(bytes.fromhex(pointer.get("previousAppHash", "") or "00" * 32))
    message.extend(bytes.fromhex(pointer["servingDomainHash"]))
    message.extend(struct.pack(">QQ", pointer["publishedAt"], pointer.get("previousValidUntil", 0)))
    return bytes(message)


def shortvec(raw, offset):
    result = 0
    for shift in (0, 7, 14):
        byte = raw[offset]
        offset += 1
        result |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return result, offset
    raise ValueError("shortvec")


def verify_signed_transaction(raw, expected_signature):
    """Verify every required Ed25519 signature over the exact Solana message."""
    try:
        count, offset = shortvec(raw, 0)
        if count < 1 or count > 32:
            raise ValueError("signature count")
        signatures = [raw[offset + i * 64:offset + (i + 1) * 64] for i in range(count)]
        offset += count * 64
        message = raw[offset:]
        if not message or len(signatures[0]) != 64 or signatures[0] != b58decode(expected_signature):
            raise ValueError("signature mismatch")
        index = 1 if message[0] & 0x80 else 0
        if index and message[0] != 0x80:
            raise ValueError("transaction version")
        required = message[index]
        index += 3
        key_count, index = shortvec(message, index)
        keys = [message[index + i * 32:index + (i + 1) * 32] for i in range(key_count)]
        if count != required or count > key_count or any(len(k) != 32 for k in keys):
            raise ValueError("account keys")
        for pubkey, signature in zip(keys, signatures):
            Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, message)
        index += key_count * 32 + 32  # static keys and recent blockhash
        instructions, index = shortvec(message, index)
        programs = []
        for _ in range(instructions):
            program_index = message[index]
            index += 1
            accounts, index = shortvec(message, index)
            index += accounts
            length, index = shortvec(message, index)
            index += length
            if program_index >= key_count:
                raise ValueError("lookup-table program")
            programs.append(b58encode(keys[program_index]))
        if not programs or index > len(message):
            raise ValueError("outer instructions")
        if not (message[0] & 0x80) and index != len(message):
            raise ValueError("transaction trailing bytes")
        return [b58encode(key) for key in keys], programs
    except (IndexError, ValueError, InvalidSignature) as exc:
        raise ValueError("estate-drill-transaction-signature-invalid") from exc


def b58encode(raw):
    n = int.from_bytes(raw, "big")
    chars = ""
    while n:
        n, mod = divmod(n, 58)
        chars = ALPHABET[mod] + chars
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + chars


def release_pda(authority, app_hash):
    try:
        from solders.pubkey import Pubkey
        program = Pubkey.from_string(authority["releaseProgramId"])
        mint = bytes(Pubkey.from_string(authority["masterMint"]))
        return str(Pubkey.find_program_address(
            [b"release_v2", mint, bytes.fromhex(app_hash)], program)[0])
    except (ImportError, KeyError, ValueError) as exc:
        raise ValueError("estate-drill-release-pda-invalid") from exc


def verify_revoked_account(raw, authority, app_hash, app_id, revoked_at_unix):
    """Decode the exact fixed ReleaseEntry layout, including terminal state."""
    try:
        if (len(raw) != 383 or raw[:8] != hashlib.sha256(b"account:ReleaseEntry").digest()[:8] or
                raw[8:40] != b58decode(authority["masterMint"]) or
                raw[40:72] != bytes.fromhex(app_hash) or
                raw[72:104] != hashlib.sha256(app_id.encode()).digest()):
            raise ValueError("identity")
        version_len = struct.unpack_from("<I", raw, 136)[0]
        if version_len > 32:
            raise ValueError("version")
        if raw[140 + version_len:172 + version_len] != b58decode(authority["releaseVault"]):
            raise ValueError("vault")
        offset = 140 + version_len + 32 + 32 + 64 + 32 + 32
        registered_at = struct.unpack_from("<q", raw, offset)[0]
        status, option = raw[offset + 8], raw[offset + 9]
        revoked_at = struct.unpack_from("<q", raw, offset + 10)[0]
        if (status != 1 or option != 1 or revoked_at <= registered_at or
                revoked_at <= 0 or revoked_at != revoked_at_unix or
                raw[offset + 19:] != bytes(len(raw) - offset - 19)):
            raise ValueError("terminal")
    except (KeyError, IndexError, TypeError, ValueError, struct.error) as exc:
        raise ValueError("estate-drill-release-account-invalid") from exc
    return True


def verify_revoke_instruction(meta, static_keys, outer_programs, authority, pda):
    loaded = meta.get("loadedAddresses") or {}
    keys = static_keys + loaded.get("writable", []) + loaded.get("readonly", [])
    if meta.get("err") is not None or authority["squadsProgramId"] not in outer_programs:
        raise ValueError("estate-drill-transaction-failed")
    try:
        from solders.pubkey import Pubkey
        vault = bytes(Pubkey.from_string(authority["releaseVault"]))
        token = bytes(Pubkey.from_string(authority["tokenProgramId"]))
        mint = bytes(Pubkey.from_string(authority["masterMint"]))
        ata_program = Pubkey.from_string(authority["ataProgramId"])
        ata = str(Pubkey.find_program_address([vault, token, mint], ata_program)[0])
    except (ImportError, KeyError, ValueError) as exc:
        raise ValueError("estate-drill-revoke-authority-invalid") from exc
    for row in meta.get("innerInstructions", []):
        index = row.get("index")
        if type(index) is not int or index < 0 or index >= len(outer_programs) or \
                outer_programs[index] != authority["squadsProgramId"]:
            continue
        for ix in row.get("instructions", []):
            try:
                accounts = [keys[i] for i in ix["accounts"]]
                program = keys[ix["programIdIndex"]]
                data = b58decode(ix["data"])
                if (program == authority["releaseProgramId"] and data == REVOKE and
                        len(accounts) == 5 and accounts[:3] ==
                        [pda, authority["releaseVault"], authority["masterMint"]] and
                        accounts[3] == ata and
                        accounts[4] == authority["tokenProgramId"]):
                    return True
            except (KeyError, IndexError, TypeError, ValueError):
                continue
    raise ValueError("estate-drill-revoke-instruction-absent")
