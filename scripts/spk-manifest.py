#!/usr/bin/env python3
"""Read the manifest embedded in a signed Sandstorm .spk — the ONLY authority
on what version an app package actually is.

Why this exists
---------------
Every other version field in the catalog is an ASSERTION someone typed:
`metadata.json` (version / marketingVersion / versionNumber), `RELEASE.json`,
`apps/index.json`, the operator-signed `update/generation.json`. None of them is
derived from the package bytes, and until this file existed nothing in the
publish path ever opened an SPK to check. That is how the catalog came to
advertise versions its own bytes do not contain (clientspace index 0.1.3/vN8 vs
SPK 0.1.0/v1; BotMother 1.1.3/vN19 vs 1.1.2/v13; Paint Bureau index vN19 vs SPK
appVersion 20).

Format (sandstorm/src/sandstorm/spk.c++ L1415-1470, package.capnp L700-757):

    spk::MAGIC_NUMBER (8 bytes)
    xz stream, whose plaintext is:
        unpacked capnp message: spk::Signature   (publicKey, signature)
        unpacked capnp message: spk::Archive     (a file tree)
    The archive-root file `sandstorm-manifest` IS a serialized spk::Manifest.

Why not shell out to `spk verify -d`
------------------------------------
`spk verify` copies the decompressed archive to a temp FILE. On a full disk it
dies with `kj/io.c++:365: No space left on device` and a caller that treats a
non-zero exit as "unknown" then has to choose between blocking and skipping —
which is exactly how a version gate silently stops biting. This reader never
touches the disk: it decompresses into memory and parses capnp directly.
Peak RSS is the decompressed archive (~340 MB for the largest catalog app);
worst-case runtime ~6 s.

Byte-exactness is not assumed. `scripts/test-spk-manifest.sh` asserts this
parser reproduces `spk verify -d` field-for-field (appId, appVersion,
appMarketingVersion, appTitle, packageId) on real catalog SPKs whenever the
`spk` CLI is available and has scratch space.

Usage:
    spk-manifest.py <app.spk>          # JSON to stdout
    spk-manifest.py -                  # read the SPK from stdin

Exit 0 with JSON on success; exit 2 with a message on stderr otherwise.
"""

from __future__ import annotations

import hashlib
import json
import lzma
import struct
import sys

# spk::MAGIC_NUMBER — package.capnp.
MAGIC = bytes.fromhex("8fc6cdef451aea96")


class CapnpError(Exception):
    pass


class Message:
    """A flat (unpacked) capnp message: segment table + contiguous segments."""

    def __init__(self, buf: bytes, offset: int = 0):
        try:
            seg_count = struct.unpack_from("<I", buf, offset)[0] + 1
            sizes = struct.unpack_from("<%dI" % seg_count, buf, offset + 4)
        except struct.error as exc:
            raise CapnpError(f"truncated segment table: {exc}") from exc
        header = 4 + 4 * seg_count
        header += (-header) % 8
        self.buf = buf
        self.segments: list[tuple[int, int]] = []
        pos = offset + header
        for size in sizes:
            self.segments.append((pos, size * 8))
            pos += size * 8
        if pos > len(buf):
            raise CapnpError("segment table overruns the buffer")
        self.end = pos

    def word(self, segment: int, index: int) -> int:
        base, size = self.segments[segment]
        if (index + 1) * 8 > size:
            raise CapnpError("word index outside segment")
        return struct.unpack_from("<Q", self.buf, base + index * 8)[0]

    def raw(self, segment: int, word_index: int, length: int) -> bytes:
        base, size = self.segments[segment]
        start = base + word_index * 8
        if word_index * 8 + length > size:
            raise CapnpError("byte range outside segment")
        return self.buf[start:start + length]


def _sign_extend_30(value: int) -> int:
    return value - (1 << 30) if value & (1 << 29) else value


def deref(msg: Message, segment: int, word_index: int):
    """Resolve one pointer word.

    Returns ("struct", seg, data_start, data_words, ptr_start, ptr_words)
         or ("list",   seg, start, element_size, count)
         or None for a null pointer.
    """
    word = msg.word(segment, word_index)
    if word == 0:
        return None
    kind = word & 3
    if kind == 2:  # far pointer
        double_landing = (word >> 2) & 1
        offset = (word >> 3) & 0x1FFFFFFF
        target_segment = word >> 32
        if not double_landing:
            return deref(msg, target_segment, offset)
        far = msg.word(target_segment, offset)
        tag = msg.word(target_segment, offset + 1)
        if (far & 3) != 2:
            raise CapnpError("double-far landing pad is not a far pointer")
        content_offset = (far >> 3) & 0x1FFFFFFF
        content_segment = far >> 32
        if (tag & 3) == 0:
            data_words = (tag >> 32) & 0xFFFF
            ptr_words = (tag >> 48) & 0xFFFF
            return ("struct", content_segment, content_offset, data_words,
                    content_offset + data_words, ptr_words)
        element_size = (tag >> 32) & 7
        count = (tag >> 35) & 0x1FFFFFFF
        return ("list", content_segment, content_offset, element_size, count)

    offset = _sign_extend_30((word >> 2) & 0x3FFFFFFF)
    start = word_index + 1 + offset
    if kind == 0:
        data_words = (word >> 32) & 0xFFFF
        ptr_words = (word >> 48) & 0xFFFF
        return ("struct", segment, start, data_words, start + data_words, ptr_words)
    if kind == 1:
        element_size = (word >> 32) & 7
        count = (word >> 35) & 0x1FFFFFFF
        return ("list", segment, start, element_size, count)
    raise CapnpError("capability pointer in a package archive")


def struct_u32(msg: Message, st, index: int) -> int:
    _, segment, data_start, data_words, _, _ = st
    if index // 2 >= data_words:
        return 0
    return struct.unpack_from("<I", msg.raw(segment, data_start, data_words * 8), index * 4)[0]


def struct_ptr(msg: Message, st, index: int):
    _, segment, _, _, ptr_start, ptr_words = st
    if index >= ptr_words:
        return None
    return deref(msg, segment, ptr_start + index)


def list_bytes(msg: Message, lst) -> bytes:
    _, segment, start, element_size, count = lst
    if element_size != 2:
        raise CapnpError(f"expected a byte list, got elementSize={element_size}")
    return msg.raw(segment, start, count)


def list_text(msg: Message, lst):
    if lst is None:
        return None
    raw = list_bytes(msg, lst)
    if raw.endswith(b"\0"):
        raw = raw[:-1]
    return raw.decode("utf-8", "replace")


def localized_text(msg: Message, st):
    """Util.LocalizedText — `defaultText @0 :Text` is pointer 0."""
    if st is None:
        return None
    return list_text(msg, struct_ptr(msg, st, 0))


def composite_elements(msg: Message, lst):
    _, segment, start, element_size, _ = lst
    if element_size != 7:
        raise CapnpError(f"expected a composite list, got elementSize={element_size}")
    tag = msg.word(segment, start)
    count = _sign_extend_30((tag >> 2) & 0x3FFFFFFF)
    data_words = (tag >> 32) & 0xFFFF
    ptr_words = (tag >> 48) & 0xFFFF
    pos = start + 1
    for _ in range(count):
        yield ("struct", segment, pos, data_words, pos + data_words, ptr_words)
        pos += data_words + ptr_words


def archive_manifest_bytes(archive: Message) -> bytes:
    """Return the bytes of the archive-root file `sandstorm-manifest`.

    Archive.File: name @0 (pointer 0); the union members regular @1 /
    executable @2 / symlink @3 / directory @4 all live in pointer 1.
    """
    root = deref(archive, 0, 0)
    if root is None:
        raise CapnpError("archive has a null root")
    files = struct_ptr(archive, root, 0)
    if files is None:
        raise CapnpError("archive has no file list")
    for entry in composite_elements(archive, files):
        if list_text(archive, struct_ptr(archive, entry, 0)) != "sandstorm-manifest":
            continue
        content = struct_ptr(archive, entry, 1)
        if content is None:
            raise CapnpError("sandstorm-manifest has no content")
        return list_bytes(archive, content)
    raise CapnpError("sandstorm-manifest not found at the archive root")


BASE32_ALPHABET = "0123456789acdefghjkmnpqrstuvwxyz"


def app_id(public_key: bytes) -> str:
    """Port of sandstorm::base32Encode (src/sandstorm/id-to-text.c++ L28-57).

    MSB-first, Crockford-ish alphabet. The app ID is simply the encoded
    libsodium signing public key.
    """
    if not public_key:
        return ""
    out: list[str] = []
    buffer = public_key[0]
    nxt = 1
    bits = 8
    while bits > 0 or nxt < len(public_key):
        if bits < 5:
            if nxt < len(public_key):
                buffer = (buffer << 8) | public_key[nxt]
                nxt += 1
                bits += 8
            else:
                pad = 5 - bits
                buffer <<= pad
                bits += pad
        out.append(BASE32_ALPHABET[0x1F & (buffer >> (bits - 5))])
        bits -= 5
    return "".join(out)


def parse_plaintext(plain: bytes) -> dict:
    signature = Message(plain, 0)
    signature_root = deref(signature, 0, 0)
    if signature_root is None:
        raise CapnpError("spk::Signature has a null root")
    public_key = list_bytes(signature, struct_ptr(signature, signature_root, 0))
    if len(public_key) != 32:
        raise CapnpError(f"public key is {len(public_key)} bytes, expected 32")

    archive = Message(plain, signature.end)
    manifest = Message(archive_manifest_bytes(archive), 0)
    root = deref(manifest, 0, 0)
    if root is None:
        raise CapnpError("spk::Manifest has a null root")

    # spk::Manifest data section, allocated in ordinal order:
    #   @0 minApiVersion :UInt32   -> u32 slot 0
    #   @1 maxApiVersion :UInt32   -> u32 slot 1
    #   @4 appVersion    :UInt32   -> u32 slot 2
    #   @5 minUpgradable :UInt32   -> u32 slot 3
    # Pointer section, also ordinal order:
    #   @2 actions, @3 continueCommand, @6 appMarketingVersion,
    #   @7 appTitle, @8 metadata
    return {
        "appId": app_id(public_key),
        "appTitle": localized_text(manifest, struct_ptr(manifest, root, 3)),
        "appVersion": struct_u32(manifest, root, 2),
        "minUpgradableAppVersion": struct_u32(manifest, root, 3),
        "appMarketingVersion": localized_text(manifest, struct_ptr(manifest, root, 2)),
    }


def read_spk(handle) -> dict:
    magic = handle.read(len(MAGIC))
    if magic != MAGIC:
        raise CapnpError(f"not an spk: magic {magic.hex()} != {MAGIC.hex()}")
    digest = hashlib.sha256()
    digest.update(magic)
    decompressor = lzma.LZMADecompressor()
    plain = bytearray()
    while True:
        chunk = handle.read(1 << 20)
        if not chunk:
            break
        digest.update(chunk)
        if not decompressor.eof:
            plain += decompressor.decompress(chunk)
    result = parse_plaintext(bytes(plain))
    full = digest.hexdigest()
    result["spkSha256"] = full
    # Sandstorm's package ID is sha256(spk)[:32] — see spk.c++ PACKAGE_ID_BYTE_SIZE.
    result["packageId"] = full[:32]
    return result


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-4], file=sys.stderr)
        print("usage: spk-manifest.py <app.spk>|-", file=sys.stderr)
        return 2
    try:
        if argv[1] == "-":
            result = read_spk(sys.stdin.buffer)
        else:
            with open(argv[1], "rb") as handle:
                result = read_spk(handle)
    except (CapnpError, lzma.LZMAError, OSError, struct.error) as exc:
        print(f"spk-manifest: {argv[1]}: {exc}", file=sys.stderr)
        return 2
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
