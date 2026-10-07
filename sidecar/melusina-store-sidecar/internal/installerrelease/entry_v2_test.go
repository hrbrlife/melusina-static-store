package installerrelease

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"testing"
)

// The three deterministic keys are rehearsal-only. They exercise real
// Ed25519 verification over the exact V2 digest and account serialization.
func v2Fixture(t *testing.T, threshold uint32) (Entry, *Trust, []ed25519.PrivateKey) {
	t.Helper()
	_, e := activeVector(t)
	e.Legacy = false
	e.ReleaseTrustProfileHash = sha256.Sum256([]byte("owner-signed rehearsal estate profile"))
	keys := make([]ed25519.PrivateKey, 3)
	for i, label := range []string{"rehearsal/publisher-1", "rehearsal/publisher-2", "rehearsal/publisher-3"} {
		seed := sha256.Sum256([]byte("melusina-estate-profile-vector-key:" + label))
		keys[i] = ed25519.NewKeyFromSeed(seed[:])
	}
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i].Public().(ed25519.PublicKey), keys[j].Public().(ed25519.PublicKey)) < 0
	})
	copy(e.PublisherEd25519Pubkey[:], keys[0].Public().(ed25519.PublicKey))
	e.SignedPayloadHash = PayloadHashV2(e.MasterNFTMint, e.InstallerHash, e.Version, e.PublisherSquadsVault,
		e.PublisherEd25519Pubkey, e.ReleaseTrustProfileHash)
	copy(e.PublisherSignature[:], ed25519.Sign(keys[0], e.SignedPayloadHash[:]))
	e.AdditionalPublisherSignatures = nil
	for _, key := range keys[1:2] {
		var signer PublisherSignature
		copy(signer.PublisherEd25519Pubkey[:], key.Public().(ed25519.PublicKey))
		copy(signer.Signature[:], ed25519.Sign(key, e.SignedPayloadHash[:]))
		e.AdditionalPublisherSignatures = append(e.AdditionalPublisherSignatures, signer)
	}
	pubs := make([][32]byte, len(keys))
	for i, key := range keys {
		copy(pubs[i][:], key.Public().(ed25519.PublicKey))
	}
	trust, err := NewTrust(e.MasterNFTMint, e.PublisherSquadsVault, pubs, threshold)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.BindProfile(hex.EncodeToString(e.ReleaseTrustProfileHash[:])); err != nil {
		t.Fatal(err)
	}
	return e, trust, keys
}

func TestH09_1_6StoreThresholdUsesOwnerNOfM(t *testing.T) {
	entry, two, _ := v2Fixture(t, 2)
	if err := two.Admit(entry, entry.InstallerHash); err != nil {
		t.Fatalf("1.6::store-threshold positive 2-of-3: %v", err)
	}
	_, three, _ := v2Fixture(t, 3)
	if err := three.Admit(entry, entry.InstallerHash); err == nil || !errors.Is(err, ErrThresholdUnmet) || !strings.Contains(err.Error(), "1.6::store-threshold") {
		t.Fatalf("1.6::store-threshold: 2 signatures satisfied 3-of-3: %v", err)
	}
}

func encodeV2(e Entry) []byte {
	disc := Discriminator()
	b := append([]byte(nil), disc[:]...)
	b = append(b, e.MasterNFTMint[:]...)
	b = append(b, e.InstallerHash[:]...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(e.Version)))
	b = append(b, e.Version...)
	b = append(b, e.PublisherSquadsVault[:]...)
	b = append(b, e.RegisteredBy[:]...)
	b = binary.LittleEndian.AppendUint64(b, uint64(e.RegisteredAt))
	b = append(b, byte(e.Status))
	b = append(b, e.PublisherEd25519Pubkey[:]...)
	b = append(b, e.PublisherSignature[:]...)
	b = append(b, e.SignedPayloadHash[:]...)
	b = append(b, 0, e.Bump)
	b = append(b, e.ReleaseTrustProfileHash[:]...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(e.AdditionalPublisherSignatures)))
	for _, signer := range e.AdditionalPublisherSignatures {
		b = append(b, signer.PublisherEd25519Pubkey[:]...)
		b = append(b, signer.Signature[:]...)
	}
	return append(b, make([]byte, Len-len(b))...)
}

func TestV2TwoOfThreeRealSignaturesAndNamedMutations(t *testing.T) {
	e, trust, keys := v2Fixture(t, 2)
	account := encodeV2(e)
	decoded, err := Decode(account)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.Admit(decoded, e.InstallerHash); err != nil {
		t.Fatalf("2-of-3 positive: %v", err)
	}
	if decoded.Legacy || len(decoded.AdditionalPublisherSignatures) != 1 {
		t.Fatal("V2 account did not retain its second signature")
	}

	for _, tc := range []struct {
		name   string
		change func(*Entry)
		want   error
	}{
		{"one-signature-at-threshold-two", func(x *Entry) { x.AdditionalPublisherSignatures = nil }, ErrThresholdUnmet},
		{"same-key-twice", func(x *Entry) {
			x.AdditionalPublisherSignatures[0].PublisherEd25519Pubkey = x.PublisherEd25519Pubkey
			x.AdditionalPublisherSignatures[0].Signature = x.PublisherSignature
		}, ErrPublisherDuplicate},
		{"untrusted-key", func(x *Entry) {
			seed := sha256.Sum256([]byte("rehearsal/untrusted"))
			foreign := ed25519.NewKeyFromSeed(seed[:])
			for bytes.Compare(foreign.Public().(ed25519.PublicKey), x.PublisherEd25519Pubkey[:]) <= 0 {
				seed = sha256.Sum256(seed[:])
				foreign = ed25519.NewKeyFromSeed(seed[:])
			}
			copy(x.AdditionalPublisherSignatures[0].PublisherEd25519Pubkey[:], foreign.Public().(ed25519.PublicKey))
			copy(x.AdditionalPublisherSignatures[0].Signature[:], ed25519.Sign(foreign, x.SignedPayloadHash[:]))
		}, ErrPublisherUntrusted},
		{"entry-keyset-cannot-replace-profile", func(x *Entry) {
			x.ReleaseTrustProfileHash[0] ^= 1
			x.SignedPayloadHash = PayloadHashV2(x.MasterNFTMint, x.InstallerHash, x.Version,
				x.PublisherSquadsVault, x.PublisherEd25519Pubkey, x.ReleaseTrustProfileHash)
			copy(x.PublisherSignature[:], ed25519.Sign(keys[0], x.SignedPayloadHash[:]))
			copy(x.AdditionalPublisherSignatures[0].Signature[:], ed25519.Sign(keys[1], x.SignedPayloadHash[:]))
		}, ErrProfileMismatch},
		{"payload-byte-flipped-after-signing", func(x *Entry) { x.Version = "1.0.65" }, ErrPayloadHashMismatch},
		{"signature-byte-flipped", func(x *Entry) { x.AdditionalPublisherSignatures[0].Signature[0] ^= 1 }, ErrSignatureInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := e
			x.AdditionalPublisherSignatures = append([]PublisherSignature(nil), e.AdditionalPublisherSignatures...)
			tc.change(&x)
			if err := trust.Admit(x, e.InstallerHash); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
	// A profile with threshold one still checks a real signature and monotonic
	// release state; its historical K3 account remains readable and admissible.
	legacy := e
	legacy.Legacy = true
	legacy.AdditionalPublisherSignatures = nil
	legacy.SignedPayloadHash = PayloadHash(legacy.MasterNFTMint, legacy.InstallerHash, legacy.Version,
		legacy.PublisherSquadsVault, legacy.PublisherEd25519Pubkey)
	copy(legacy.PublisherSignature[:], ed25519.Sign(keys[0], legacy.SignedPayloadHash[:]))
	pubs := [][32]byte{legacy.PublisherEd25519Pubkey}
	one, err := NewTrust(legacy.MasterNFTMint, legacy.PublisherSquadsVault, pubs, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := one.Admit(legacy, legacy.InstallerHash); err != nil {
		t.Fatalf("threshold-one legacy positive: %v", err)
	}
	legacy.PublisherSignature[0] ^= 1
	if err := one.Admit(legacy, legacy.InstallerHash); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("threshold-one signature mutation: %v", err)
	}
}
