package estateprofile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"strings"
	"time"
)

// binaryWriter is the one digest encoding. It is the idiom of
// targetBoundInstallationAdmissionBinaryWriter in internal/installmodel and of
// the JS Writer classes: a byte string is its 4-byte big-endian length and
// then its bytes, an integer is fixed-width big-endian, a list is its 4-byte
// count and then its items, and a time is its 8-byte Unix seconds. It is copied
// rather than imported because this package must stand alone in three modules.
type binaryWriter struct{ bytes.Buffer }

func (writer *binaryWriter) string(value string) { writer.bytes([]byte(value)) }

func (writer *binaryWriter) bytes(value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	writer.Write(length[:])
	writer.Write(value)
}

// raw appends fixed-width bytes with no length prefix. It is used only for
// the 32-byte estate nonce at the end of the estate-ID preimage.
func (writer *binaryWriter) raw(value []byte) { writer.Write(value) }

func (writer *binaryWriter) uint8(value uint8) { writer.WriteByte(value) }

func (writer *binaryWriter) bool(value bool) {
	if value {
		writer.uint8(1)
		return
	}
	writer.uint8(0)
}

func (writer *binaryWriter) uint32(value uint32) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	writer.Write(raw[:])
}

func (writer *binaryWriter) uint64(value uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	writer.Write(raw[:])
}

func (writer *binaryWriter) time(value time.Time) { writer.uint64(uint64(value.Unix())) }

const issuedAtLayout = "2006-01-02T15:04:05Z"

// parseIssuedAt accepts exactly one spelling of a UTC whole second after the
// Unix epoch, so the JSON string and the preimage integer are one value.
func parseIssuedAt(value string) (time.Time, bool) {
	parsed, err := time.Parse(issuedAtLayout, value)
	if err != nil || parsed.Format(issuedAtLayout) != value || parsed.Unix() <= 0 {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

// validDigest accepts a lowercase, nonzero, 64-character hex SHA-256.
func validDigest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value && strings.Trim(value, "0") != ""
}

func validSourceCommit(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 20 && hex.EncodeToString(raw) == value && strings.Trim(value, "0") != ""
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// decodeBase58Key decodes one canonical base58 32-byte Solana address or hash.
func decodeBase58Key(value string) ([32]byte, bool) {
	var out [32]byte
	if len(value) < 32 || len(value) > 44 {
		return out, false
	}
	number := new(big.Int)
	base := big.NewInt(58)
	for _, char := range value {
		index := strings.IndexRune(base58Alphabet, char)
		if index < 0 {
			return out, false
		}
		number.Mul(number, base)
		number.Add(number, big.NewInt(int64(index)))
	}
	decoded := number.Bytes()
	leading := 0
	for leading < len(value) && value[leading] == '1' {
		leading++
	}
	if leading+len(decoded) != len(out) {
		return out, false
	}
	copy(out[leading:], decoded)
	if encodeBase58(out[:]) != value {
		return [32]byte{}, false
	}
	return out, true
}

func encodeBase58(raw []byte) string {
	number := new(big.Int).SetBytes(raw)
	base := big.NewInt(58)
	remainder := new(big.Int)
	var reversed []byte
	for number.Sign() > 0 {
		number.DivMod(number, base, remainder)
		reversed = append(reversed, base58Alphabet[remainder.Int64()])
	}
	for _, item := range raw {
		if item != 0 {
			break
		}
		reversed = append(reversed, base58Alphabet[0])
	}
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	return string(reversed)
}

// validAddress accepts a canonical base58 32-byte value that is not all zero.
func validAddress(value string) bool {
	raw, ok := decodeBase58Key(value)
	return ok && raw != [32]byte{}
}

// validAddressOrDefault additionally accepts the all-zero address, which is
// how Squads spells "this multisig has no config authority".
func validAddressOrDefault(value string) bool {
	_, ok := decodeBase58Key(value)
	return ok
}

// decodeSignature accepts one canonical unpadded base64url 64-byte signature.
func decodeSignature(value string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, false
	}
	return raw, true
}

// Ed25519 field and curve constants, used only to refuse a public key that is
// not a canonical point of the prime-order subgroup. Keys are public inputs,
// so variable-time big-integer arithmetic handles no secret.
var (
	edwardsP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edwardsD = func() *big.Int {
		inverse := new(big.Int).ModInverse(big.NewInt(121666), edwardsP)
		return new(big.Int).Mod(new(big.Int).Mul(big.NewInt(-121665), inverse), edwardsP)
	}()
	edwardsSqrtM1 = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(edwardsP, big.NewInt(1)), 2), edwardsP)
	// edwardsL is the prime order of the base-point subgroup.
	edwardsL, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
)

// edwardsPoint is a point in extended coordinates (X:Y:Z:T), x=X/Z, y=Y/Z,
// xy=T/Z.
type edwardsPoint struct{ x, y, z, t *big.Int }

func edwardsIdentity() edwardsPoint {
	return edwardsPoint{big.NewInt(0), big.NewInt(1), big.NewInt(1), big.NewInt(0)}
}

// add is the unified a=-1 addition law, complete on this curve, so it also
// doubles.
func (left edwardsPoint) add(right edwardsPoint) edwardsPoint {
	mod := func(value *big.Int) *big.Int { return value.Mod(value, edwardsP) }
	a := mod(new(big.Int).Mul(left.x, right.x))
	b := mod(new(big.Int).Mul(left.y, right.y))
	c := mod(new(big.Int).Mul(mod(new(big.Int).Mul(left.t, right.t)), edwardsD))
	d := mod(new(big.Int).Mul(left.z, right.z))
	e := new(big.Int).Mul(new(big.Int).Add(left.x, left.y), new(big.Int).Add(right.x, right.y))
	e = mod(e.Sub(e, a).Sub(e, b))
	f := mod(new(big.Int).Sub(d, c))
	g := mod(new(big.Int).Add(d, c))
	h := mod(new(big.Int).Add(b, a))
	return edwardsPoint{mod(new(big.Int).Mul(e, f)), mod(new(big.Int).Mul(g, h)), mod(new(big.Int).Mul(f, g)), mod(new(big.Int).Mul(e, h))}
}

func (point edwardsPoint) isIdentity() bool {
	return point.x.Sign() == 0 && point.y.Cmp(point.z) == 0
}

// decompressEdwardsPoint decodes one canonical 32-byte point encoding.
func decompressEdwardsPoint(raw [32]byte) (edwardsPoint, bool) {
	sign := raw[31] >> 7
	raw[31] &= 0x7f
	littleEndian := make([]byte, 32)
	for index := range raw {
		littleEndian[31-index] = raw[index]
	}
	y := new(big.Int).SetBytes(littleEndian)
	if y.Cmp(edwardsP) >= 0 {
		return edwardsPoint{}, false
	}
	ySquared := new(big.Int).Mod(new(big.Int).Mul(y, y), edwardsP)
	numerator := new(big.Int).Mod(new(big.Int).Sub(ySquared, big.NewInt(1)), edwardsP)
	denominator := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(edwardsD, ySquared), big.NewInt(1)), edwardsP)
	xSquared := new(big.Int).Mod(new(big.Int).Mul(numerator, new(big.Int).ModInverse(denominator, edwardsP)), edwardsP)
	exponent := new(big.Int).Rsh(new(big.Int).Add(edwardsP, big.NewInt(3)), 3)
	x := new(big.Int).Exp(xSquared, exponent, edwardsP)
	if new(big.Int).Mod(new(big.Int).Mul(x, x), edwardsP).Cmp(xSquared) != 0 {
		x.Mod(x.Mul(x, edwardsSqrtM1), edwardsP)
	}
	if new(big.Int).Mod(new(big.Int).Mul(x, x), edwardsP).Cmp(xSquared) != 0 {
		return edwardsPoint{}, false
	}
	if x.Sign() == 0 && sign == 1 {
		return edwardsPoint{}, false
	}
	if uint8(x.Bit(0)) != sign {
		x.Sub(edwardsP, x)
	}
	return edwardsPoint{x, y, big.NewInt(1), new(big.Int).Mod(new(big.Int).Mul(x, y), edwardsP)}, true
}

// decodeEd25519PublicKey accepts a lowercase hex key that is a canonical,
// non-identity point of the prime-order subgroup. The standard verifier
// accepts small- and mixed-order keys, under which a threshold is weaker than
// it reads; a policy naming one is refused.
func decodeEd25519PublicKey(value string) (ed25519.PublicKey, bool) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != ed25519.PublicKeySize || hex.EncodeToString(raw) != value {
		return nil, false
	}
	point, ok := decompressEdwardsPoint([32]byte(raw))
	if !ok || point.isIdentity() {
		return nil, false
	}
	product := edwardsIdentity()
	for bit := edwardsL.BitLen() - 1; bit >= 0; bit-- {
		product = product.add(product)
		if edwardsL.Bit(bit) == 1 {
			product = product.add(point)
		}
	}
	if !product.isIdentity() {
		return nil, false
	}
	return ed25519.PublicKey(raw), true
}
