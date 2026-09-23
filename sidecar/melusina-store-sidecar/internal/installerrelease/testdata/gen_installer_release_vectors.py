#!/usr/bin/env python3
"""Generate installer-release-entry-vectors.json from the Rust source excerpt.

Independent of the Go decoder: the field list, types, LEN and the payload
preimage are parsed from license-registry-excerpt.rs (verbatim program
source), each value is Borsh-encoded by its Rust type, and the account is
padded with zeros to LEN exactly as Anchor's `init` + serialize leaves it.

The publisher key is derived from a fixed public label. It is a test fixture
only and holds no authority anywhere.

    python3 gen_installer_release_vectors.py > installer-release-entry-vectors.json
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
    body = re.search(r"pub struct " + name + r" \{\n(.*?)\n\}", SOURCE, re.S).group(1)
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
    return eval(expr)  # digits, spaces, + and parentheses only (checked above)


FIELDS = struct_fields("InstallerReleaseEntry")
STATUS = enum_variants("AttestationStatus")
LEN = rust_len("InstallerReleaseEntry")
DISCRIMINATOR = hashlib.sha256(b"account:InstallerReleaseEntry").digest()[:8]


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
    # installer_release_payload_hash: the hashv argument list, in source order.
    return hashlib.sha256(
        b"melusina-installer-release-v1" + fields["master_nft_mint"] + fields["installer_hash"]
        + fields["version"].encode("utf-8") + fields["publisher_squads_vault"] + fields["publisher_ed25519_pubkey"]
    ).digest()


def label(text):
    return hashlib.sha256(("melusina-installer-release-vector:" + text).encode()).digest()


PUBLISHER_SEED_LABEL = "melusina-installer-release-vector-publisher"
publisher = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(PUBLISHER_SEED_LABEL.encode()).digest())
publisher_pub = publisher.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def vector(name, version, status, revoked_at, registered_at, bump):
    fields = {
        "master_nft_mint": label("master"),
        "installer_hash": label("installer:" + name),
        "version": version,
        "publisher_squads_vault": label("core-vault"),
        "registered_by": label("core-vault"),
        "registered_at": registered_at,
        "status": status,
        "publisher_ed25519_pubkey": publisher_pub,
        "revoked_at": revoked_at,
        "bump": bump,
    }
    fields["signed_payload_hash"] = payload_hash(fields)
    fields["publisher_signature"] = publisher.sign(fields["signed_payload_hash"])
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
        "fields": {n: show(n, t) for n, t in FIELDS},
        "serializedLength": len(body),
        "accountHex": account.hex(),
    }


print(json.dumps({
    "schema": "melusina.store.installer-release-entry-vectors.v1",
    "source": "license-registry-excerpt.rs",
    "len": LEN,
    "discriminatorHex": DISCRIMINATOR.hex(),
    "fieldOrder": [[n, t] for n, t in FIELDS],
    "statusVariants": STATUS,
    "publisherSeedLabel": PUBLISHER_SEED_LABEL,
    "vectors": [
        vector("active-none", "1.0.64", "Active", None, 1767225600, 254),
        vector("superseded-some-max-version", "0123456789abcdefghijklmnopqrstuv", "Superseded", 1790000000, 1767225601, 253),
    ],
}, indent=2))
