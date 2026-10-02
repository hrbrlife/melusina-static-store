// Package canonical is THE canonical byte encoding for every melusina-attest
// contract (PROVENANCE_CONTRACTS.md §4.1, Rule 5: "One encoding, one contract.
// A second canonical byte representation is a second contract and is
// forbidden.").
//
// It is the encoding envelope.CanonicalPayload has always used, factored out
// verbatim so that graincert and sidecarresult BIND TO THE SAME PRIMITIVE
// rather than copy-pasting `appendLen`. Copy-paste is literally how three
// identical 505-line proof_builder.go files happened (§6.3); a fourth copy of
// a four-line encoder is the same disease at a smaller scale.
//
// The encoding:
//   - a fixed ASCII domain-separation prefix (the domain tag);
//   - every field emitted POSITIONALLY, each as uint32 little-endian length
//     ‖ bytes;
//   - empty fields emitted as a zero length — NEVER omitted (§4.6(4): a
//     conditionally-emitted field makes the canonical bytes depend on
//     content).
//
// Properties this buys, per §4.1: length-prefixed (immune to
// field-concatenation ambiguity), domain-tagged (a v1 blob cannot be replayed
// at a v2 verifier — the prefix mismatch surfaces as a hash mismatch),
// positional (no map iteration order).
package canonical

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
)

// Encode returns domainTag ‖ (len‖field)* for fields, in the given order.
//
// The field ORDER is the contract. Callers MUST emit their contract's frozen
// field list positionally and unconditionally; see §4.6's extension rule
// (append only, never insert; bump the domain tag; delete the prior emitter in
// the same change).
func Encode(domainTag string, fields []string) []byte {
	out := make([]byte, 0, 512)
	out = append(out, []byte(domainTag)...)
	for _, f := range fields {
		out = AppendLen(out, []byte(f))
	}
	return out
}

// AppendLen appends uint32-LE(len(b)) ‖ b to dst.
func AppendLen(dst, b []byte) []byte {
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(b)))
	dst = append(dst, lenBuf[:]...)
	return append(dst, b...)
}

// SHA256Hex is the lowercase-hex sha256 used for every *HashHex field in
// every contract.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Int renders an integer as decimal ASCII for inclusion as a canonical field.
// Frozen: decimal ASCII, no padding, no separators — matching the existing
// envelope emitter's fmt.Sprintf("%d", …).
func Int(v int64) string { return strconv.FormatInt(v, 10) }

// Uint renders an unsigned integer as decimal ASCII for inclusion as a
// canonical field.
func Uint(v uint64) string { return strconv.FormatUint(v, 10) }

// HashList binds an ordered list of hex hashes as a single field:
// sha256(concat of each entry, in array order), lowercase hex.
//
// Used by §7.1 for `sha256(concat of each SidecarResult.ResultHashHex in array
// order)` and `sha256(concat of each RequiredScreens entry in array order)`.
// Order is part of the binding: reordering the array changes the field.
func HashList(entries []string) string {
	h := sha256.New()
	for _, e := range entries {
		h.Write([]byte(e))
	}
	return hex.EncodeToString(h.Sum(nil))
}
