package primitives

import (
	"errors"
	"fmt"
	"strings"
)

// sandstormBase32Digits is Sandstorm's base32 alphabet (sandstorm
// src/sandstorm/util.c++; contracts scripts/estate/lib/blacklist-clearance.mjs
// SANDSTORM_BASE32_DIGITS; authz pkg/grainauth/sandstorm_appid.go).
const sandstormBase32Digits = "0123456789acdefghjkmnpqrstuvwxyz"

// DecodeSandstormAppID returns the decoded, stable 32-byte key of a Sandstorm
// appId: the license registry's BlacklistType::App target and the approval
// records' app_id. It is NOT SHA-256 of the appId text — that is
// ReleaseEntry.app_id, the release ceremony's AppIDHash — and it is never a
// master NFT mint or a release hash.
//
// Only the canonical text is accepted: exactly 52 characters of the lower-case
// Sandstorm alphabet whose four trailing padding bits are zero, so one key has
// exactly one text and SHA-256 of the text is well defined.
func DecodeSandstormAppID(text string) ([32]byte, error) {
	var out [32]byte
	if len(text) != 52 {
		return out, fmt.Errorf("sandstorm appId: %d characters, a canonical appId is exactly 52", len(text))
	}
	var acc uint32
	bits, n := 0, 0
	for i := 0; i < len(text); i++ {
		digit := strings.IndexByte(sandstormBase32Digits, text[i])
		if digit < 0 {
			return [32]byte{}, fmt.Errorf("sandstorm appId: character %d (%q) is not in the lower-case Sandstorm base32 alphabet", i, text[i])
		}
		acc = acc<<5 | uint32(digit)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out[n] = byte(acc >> bits)
			n++
			acc &= (1 << bits) - 1
		}
	}
	// 52 x 5 = 260 bits: the 256-bit key, then four padding bits.
	if bits != 4 || n != 32 || acc != 0 {
		return [32]byte{}, errors.New("sandstorm appId: the padding bits are not zero (non-canonical text)")
	}
	return out, nil
}

// EncodeSandstormAppID returns the canonical 52-character text of a decoded
// Sandstorm appId key. DecodeSandstormAppID(EncodeSandstormAppID(k)) == k.
func EncodeSandstormAppID(key [32]byte) string {
	out := make([]byte, 0, 52)
	var acc uint32
	bits := 0
	for _, b := range key {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, sandstormBase32Digits[(acc>>bits)&0x1f])
		}
		acc &= (1 << bits) - 1
	}
	// 256 bits leave one final digit carrying the last bit and four zero
	// padding bits.
	out = append(out, sandstormBase32Digits[(acc<<(5-bits))&0x1f])
	return string(out)
}
