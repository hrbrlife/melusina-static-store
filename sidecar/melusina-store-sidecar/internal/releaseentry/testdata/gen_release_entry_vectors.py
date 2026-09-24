#!/usr/bin/env python3
"""Generate release-entry-vectors.json from the Rust source excerpt.

Independent of the Go decoder: the field list, types, LEN and the payload
preimage are parsed from license-registry-excerpt.rs (verbatim program
source), each value is Borsh-encoded by its Rust type, and the account is
padded with zeros to LEN exactly as Anchor's `init` + serialize leaves it.

app_id is sha256 of the Sandstorm appId text and release_hash is sha256 of
appHash hex + version + releaseNonce, the two derivations the release tools
use; each vector records its appId text and nonce so a test can recompute
both.

The publisher key and every address are derived from fixed public labels.
They are test fixtures only and hold no authority anywhere.

    python3 gen_release_entry_vectors.py > release-entry-vectors.json
"""
import hashlib
import json
import os
import re
import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = open(os.path.join(HERE, "license-registry-excerpt.rs"), encoding="utf-8").read()


def struct_fields(name):
    body = re.search(r"#\[account\]\npub struct " + name + r" \{\n(.*?)\n\}", SOURCE, re.S).group(1)
    return re.findall(r"^\s*pub (\w+): ([^,]+),$", body, re.M)


def enum_variants(name):
    body = re.search(r"pub enum " + name + r" \{\n(.*?)\n\}", SOURCE, re.S).group(1)
    return re.findall(r"^\s*(\w+),$", body, re.M)


def rust_len(name):
    expr = re.search(r"impl " + name + r" \{\s*pub const LEN: usize =\s*(.*?);", SOURCE, re.S).group(1)
    for const, value in re.findall(r"pub const (\w+): usize = (\d+);", SOURCE):
        expr = expr.replace(const, value)
    if not re.fullmatch(r"[\d\s+()]+", expr):
        raise SystemExit("unexpected LEN expression: " + expr)
    # The program spreads this LEN over several lines; join them first.
    return eval(" ".join(expr.split()))  # digits, spaces, + and parentheses only (checked above)


def payload_preimage_names():
    body = re.search(r"fn release_payload_hash\(.*?hashv\(&\[\n(.*?)\n\s*\]\)", SOURCE, re.S).group(1)
    return [line.strip().rstrip(",") for line in body.splitlines()]


FIELDS = struct_fields("ReleaseEntry")
STATUS = enum_variants("AttestationStatus")
LEN = rust_len("ReleaseEntry")
DISCRIMINATOR = hashlib.sha256(b"account:ReleaseEntry").digest()[:8]
PREIMAGE = payload_preimage_names()
DOMAIN = re.fullmatch(r'b"([^"]+)"', PREIMAGE[0]).group(1)


def b58(raw):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def encode(rust_type, value):
    if rust_type == "Pubkey" or rust_type == "[u8; 32]":
        assert len(value) == 32
        return value
    if rust_type == "[u8; 64]":
        assert len(value) == 64
        return value
    if rust_type == "String":
        raw = value.encode("utf-8")
        return struct.pack("<I", len(raw)) + raw
    if rust_type == "i64":
        return struct.pack("<q", value)
    if rust_type == "u8":
        return struct.pack("<B", value)
    if rust_type == "AttestationStatus":
        return struct.pack("<B", STATUS.index(value))
    if rust_type == "Option<i64>":
        return b"\0" if value is None else b"\1" + struct.pack("<q", value)
    raise SystemExit("no Borsh rule for " + rust_type)


def payload_hash(fields):
    # release_payload_hash: the hashv argument list, in source order. Each
    # argument after the domain is `<field>.as_ref()` or `version.as_bytes()`.
    parts = [DOMAIN.encode("utf-8")]
    for item in PREIMAGE[1:]:
        name, accessor = item.split(".", 1)
        value = fields[name]
        if accessor == "as_bytes()":
            parts.append(value.encode("utf-8"))
        elif accessor == "as_ref()":
            parts.append(value)
        else:
            raise SystemExit("unexpected preimage accessor " + item)
    return hashlib.sha256(b"".join(parts)).digest()


def label(text):
    return hashlib.sha256(("melusina-release-entry-vector:" + text).encode()).digest()


PUBLISHER_SEED_LABEL = "melusina-release-entry-vector-publisher"
publisher = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(PUBLISHER_SEED_LABEL.encode()).digest())
publisher_pub = publisher.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def vector(name, app_id_text, version, nonce, status, revoked_at, registered_at, bump):
    app_hash = label("app-hash:" + name)
    fields = {
        "master_nft_mint": label("master"),
        "app_hash": app_hash,
        "app_id": hashlib.sha256(app_id_text.encode("utf-8")).digest(),
        "release_hash": hashlib.sha256((app_hash.hex() + version + nonce).encode("utf-8")).digest(),
        "version": version,
        "publisher_squads_vault": label("release-custodian-vault"),
        "publisher_ed25519_pubkey": publisher_pub,
        "registered_by": label("release-custodian-vault"),
        "registered_at": registered_at,
        "status": status,
        "revoked_at": revoked_at,
        "bump": bump,
    }
    fields["signed_payload_hash"] = payload_hash(fields)
    fields["signature"] = publisher.sign(fields["signed_payload_hash"])
    body = DISCRIMINATOR + b"".join(encode(t, fields[n]) for n, t in FIELDS)
    assert len(body) <= LEN
    account = body + b"\0" * (LEN - len(body))

    def show(n, t):
        v = fields[n]
        if t == "Pubkey":
            return b58(v)
        if isinstance(v, bytes):
            return v.hex()
        return v

    return {
        "name": name,
        "appIdText": app_id_text,
        "releaseNonce": nonce,
        "fields": {n: show(n, t) for n, t in FIELDS},
        "serializedLength": len(body),
        "accountHex": account.hex(),
    }


print(json.dumps({
    "schema": "melusina.store.release-entry-vectors.v1",
    "source": "license-registry-excerpt.rs",
    "len": LEN,
    "discriminatorHex": DISCRIMINATOR.hex(),
    "payloadDomain": DOMAIN,
    "fieldOrder": [[n, t] for n, t in FIELDS],
    "statusVariants": STATUS,
    "publisherSeedLabel": PUBLISHER_SEED_LABEL,
    "vectors": [
        vector("active-none", "vectorapp0000000000000000000000000000000000000000001",
               "2.4.1", "00112233445566778899aabbccddeeff", "Active", None, 1767225600, 254),
        vector("revoked-some-max-version", "vectorapp0000000000000000000000000000000000000000002",
               "0123456789abcdefghijklmnopqrstuv", "ffeeddccbbaa99887766554433221100", "Revoked", 1790000000, 1767225601, 253),
    ],
}, indent=2))
