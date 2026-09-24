// Package releaseentrytest builds ReleaseEntry accounts for tests: the
// account the license-registry program writes when the owner-authorized
// runner registers one app release. Only _test.go files import it
// (releaseentry.TestReleaseentrytestIsImportedOnlyByTests keeps it so); no
// production binary links it.
//
// It signs with whatever key a test passes. Tests use keys derived from fixed
// public labels, fixtures that hold no authority anywhere.
package releaseentrytest

import (
	"crypto/ed25519"
	"encoding/binary"

	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
)

// RegisteredAt is the chain clock the fixture registrations carry.
const RegisteredAt int64 = 1790000000

// Active is the Active entry the program writes when custodian registers the
// release (masterMint, appHash, appID, releaseHash, version) under key.
func Active(masterMint, custodian, appHash, appID, releaseHash [32]byte, version string, key ed25519.PrivateKey) releaseentry.Entry {
	return Sign(releaseentry.Entry{
		MasterNFTMint:        masterMint,
		AppHash:              appHash,
		AppID:                appID,
		ReleaseHash:          releaseHash,
		Version:              version,
		PublisherSquadsVault: custodian,
		RegisteredBy:         custodian,
		RegisteredAt:         RegisteredAt,
		Status:               releaseentry.StatusActive,
		Bump:                 254,
	}, key)
}

// Sign recomputes e's digest from its fields and signs it with key.
func Sign(e releaseentry.Entry, key ed25519.PrivateKey) releaseentry.Entry {
	copy(e.PublisherEd25519Pubkey[:], key.Public().(ed25519.PublicKey))
	e.SignedPayloadHash = releaseentry.PayloadHash(e.MasterNFTMint, e.AppHash, e.AppID, e.ReleaseHash, e.Version, e.PublisherSquadsVault, e.PublisherEd25519Pubkey)
	copy(e.Signature[:], ed25519.Sign(key, e.SignedPayloadHash[:]))
	return e
}

// Recall is e after revoke_release_entry: status Revoked, revoked_at set.
func Recall(e releaseentry.Entry, at int64) releaseentry.Entry {
	e.Status = releaseentry.StatusRevoked
	e.RevokedAt = &at
	return e
}

// Encode is the account the program stores for e: discriminator, Borsh
// fields in releaseentry.Layout order, zero padding to Len.
func Encode(e releaseentry.Entry) []byte {
	disc := releaseentry.Discriminator()
	b := append([]byte(nil), disc[:]...)
	b = append(b, e.MasterNFTMint[:]...)
	b = append(b, e.AppHash[:]...)
	b = append(b, e.AppID[:]...)
	b = append(b, e.ReleaseHash[:]...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(e.Version)))
	b = append(b, e.Version...)
	b = append(b, e.PublisherSquadsVault[:]...)
	b = append(b, e.PublisherEd25519Pubkey[:]...)
	b = append(b, e.Signature[:]...)
	b = append(b, e.SignedPayloadHash[:]...)
	b = append(b, e.RegisteredBy[:]...)
	b = binary.LittleEndian.AppendUint64(b, uint64(e.RegisteredAt))
	b = append(b, byte(e.Status))
	if e.RevokedAt == nil {
		b = append(b, 0)
	} else {
		b = append(b, 1)
		b = binary.LittleEndian.AppendUint64(b, uint64(*e.RevokedAt))
	}
	b = append(b, e.Bump)
	if len(b) < releaseentry.Len {
		b = append(b, make([]byte, releaseentry.Len-len(b))...)
	}
	return b
}
