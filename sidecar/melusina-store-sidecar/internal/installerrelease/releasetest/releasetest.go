// Package releasetest builds InstallerReleaseEntry accounts and estate
// profiles for tests. Only _test.go files import it
// (installerrelease.TestReleasetestIsImportedOnlyByTests keeps it so); no
// production binary links it.
//
// Every key here is derived from a fixed public label, exactly like the owner
// and publisher keys of testdata/estate-profile-vectors.json
// (internal/estateprofile/fixtures_test.go): test fixtures that hold no
// authority anywhere.
package releasetest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// NewEstateVector is the fictitious new estate of the committed vectors.
const NewEstateVector = "new-estate-revision-1"

// VectorKey is the estate-profile vectors' key for label.
func VectorKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("melusina-estate-profile-vector-key:" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

// TrustedPublisher is a key the new-estate vector's releaseTrust names.
func TrustedPublisher() ed25519.PrivateKey { return VectorKey("rehearsal/publisher-1") }

// UntrustedPublisher is a well-formed key no vector profile names.
func UntrustedPublisher() ed25519.PrivateKey { return VectorKey("rehearsal/not-enrolled-publisher") }

// Profile is one verified estate profile and its canonical digest.
type Profile struct {
	Profile estateprofile.EstateProfileV1
	SHA256  string
}

// LoadProfileVector reads the named profile from the committed vectors file.
func LoadProfileVector(t testing.TB, vectorsPath, name string) Profile {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Profiles []struct {
			Name    string                        `json:"name"`
			Profile estateprofile.EstateProfileV1 `json:"profile"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors.Profiles {
		if v.Name == name {
			digest, err := estateprofile.VerifyProfile(v.Profile)
			if err != nil {
				t.Fatalf("profile vector %s: %v", name, err)
			}
			return Profile{Profile: v.Profile, SHA256: digest}
		}
	}
	t.Fatalf("profile vector %s missing", name)
	return Profile{}
}

// Resign re-signs an edited profile with the vectors' owner keys (owner-a,
// owner-b of its owner policy) and returns it with its new digest.
func Resign(t testing.TB, profile estateprofile.EstateProfileV1) Profile {
	t.Helper()
	profile.Signatures = nil
	digest, err := estateprofile.ProfileSHA256(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, keyID := range []string{"owner-a", "owner-b"} {
		key := VectorKey(profile.OwnerPolicy.PolicyID + "/" + keyID)
		profile.Signatures = append(profile.Signatures, estateprofile.SignatureV1{
			KeyID:     keyID,
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(digest))),
		})
	}
	if _, err := estateprofile.VerifyProfile(profile); err != nil {
		t.Fatalf("re-signed profile: %v", err)
	}
	return Profile{Profile: profile, SHA256: digest}
}

// WithPublishers returns p re-signed with releaseTrust set to keys and threshold.
func WithPublishers(t testing.TB, p Profile, threshold uint32, keys ...ed25519.PrivateKey) Profile {
	t.Helper()
	profile := p.Profile
	profile.ReleaseTrust.PublisherKeys = nil
	for _, key := range keys {
		profile.ReleaseTrust.PublisherKeys = append(profile.ReleaseTrust.PublisherKeys, hex.EncodeToString(key.Public().(ed25519.PublicKey)))
	}
	sort.Strings(profile.ReleaseTrust.PublisherKeys)
	profile.ReleaseTrust.Threshold = threshold
	return Resign(t, profile)
}

// Write writes the profile JSON to a new private file and returns its path.
func Write(t testing.TB, p Profile) string {
	t.Helper()
	raw, err := json.Marshal(p.Profile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "estate-profile.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// CoreVault is the profile's roles.core vault.
func CoreVault(t testing.TB, profile estateprofile.EstateProfileV1) [32]byte {
	t.Helper()
	for _, role := range profile.Roles {
		if role.Role == estateprofile.AuthorityRoleCore {
			return pubkey(t, role.Vault)
		}
	}
	t.Fatal("profile has no core role")
	return [32]byte{}
}

// ProgramID is the profile's programs.license-registry id.
func ProgramID(t testing.TB, profile estateprofile.EstateProfileV1) string {
	t.Helper()
	id, ok := installerrelease.LicenseRegistryProgramID(profile)
	if !ok {
		t.Fatal("profile has no license-registry program")
	}
	return id
}

func pubkey(t testing.TB, b58 string) [32]byte {
	t.Helper()
	k, err := primitives.PubkeyFromBase58(b58)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Entry is the Active InstallerReleaseEntry the program writes when the
// profile's core vault registers installerHash under key: master mint and
// custodian from the profile, the digest over the entry's own fields, and
// key's signature over it.
func Entry(t testing.TB, profile estateprofile.EstateProfileV1, installerHash [32]byte, version string, key ed25519.PrivateKey) installerrelease.Entry {
	t.Helper()
	vault := CoreVault(t, profile)
	return Sign(installerrelease.Entry{
		MasterNFTMint:        pubkey(t, profile.Anchors.MasterMint),
		InstallerHash:        installerHash,
		Version:              version,
		PublisherSquadsVault: vault,
		RegisteredBy:         vault,
		RegisteredAt:         1790000000,
		Status:               0, // Active
		Bump:                 254,
	}, key)
}

// Sign recomputes e's digest from its fields and signs it with key.
func Sign(e installerrelease.Entry, key ed25519.PrivateKey) installerrelease.Entry {
	copy(e.PublisherEd25519Pubkey[:], key.Public().(ed25519.PublicKey))
	e.SignedPayloadHash = installerrelease.PayloadHash(e.MasterNFTMint, e.InstallerHash, e.Version, e.PublisherSquadsVault, e.PublisherEd25519Pubkey)
	copy(e.PublisherSignature[:], ed25519.Sign(key, e.SignedPayloadHash[:]))
	return e
}

// Encode is the account the program stores for e: discriminator, Borsh
// fields in installerrelease.Layout order, zero padding to Len.
func Encode(e installerrelease.Entry) []byte {
	disc := installerrelease.Discriminator()
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
	if e.RevokedAt == nil {
		b = append(b, 0)
	} else {
		b = append(b, 1)
		b = binary.LittleEndian.AppendUint64(b, uint64(*e.RevokedAt))
	}
	b = append(b, e.Bump)
	if len(b) < installerrelease.Len {
		b = append(b, make([]byte, installerrelease.Len-len(b))...)
	}
	return b
}
