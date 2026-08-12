// Package primitives holds the Solana primitives every Melusina
// service shares: base58 codec, PDA derivation, thin Ed25519 helpers.
package primitives

import (
	"errors"
	"math/big"
	"strings"
)

// Bitcoin-alphabet base58, the encoding Solana uses everywhere.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var (
	base58Radix = big.NewInt(58)
	base58Index = func() map[rune]int64 {
		index := make(map[rune]int64, len(base58Alphabet))
		for i, r := range base58Alphabet {
			index[r] = int64(i)
		}
		return index
	}()
)

// EncodeBase58 returns the base58 representation of b. Empty input
// yields empty output.
func EncodeBase58(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	value := new(big.Int).SetBytes(b)
	mod := new(big.Int)
	encoded := make([]byte, 0, len(b)*2)
	for value.Sign() > 0 {
		value.DivMod(value, base58Radix, mod)
		encoded = append(encoded, base58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		encoded = append(encoded, base58Alphabet[0])
	}
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}
	return string(encoded)
}

// DecodeBase58 parses a base58-encoded string. Empty or
// whitespace-only input returns an error.
func DecodeBase58(s string) ([]byte, error) {
	if strings.TrimSpace(s) == "" {
		return nil, errors.New("base58 input is empty")
	}
	value := big.NewInt(0)
	for _, r := range s {
		digit, ok := base58Index[r]
		if !ok {
			return nil, errors.New("base58 input contains invalid character")
		}
		value.Mul(value, base58Radix)
		value.Add(value, big.NewInt(digit))
	}
	decoded := value.Bytes()
	zeros := 0
	for zeros < len(s) && s[zeros] == base58Alphabet[0] {
		zeros++
	}
	out := make([]byte, zeros+len(decoded))
	copy(out[zeros:], decoded)
	return out, nil
}
