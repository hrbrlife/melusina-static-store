package recoveryprofilebridge

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease/releasetest"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func rawFixture(t *testing.T) (Signed, []byte, []byte, Observation, RawReadback) {
	t.Helper()
	b, oldRaw, successorRaw, observed := fixture(t)
	var old estateprofile.EstateProfileV1
	if err := json.Unmarshal(oldRaw, &old); err != nil {
		t.Fatal(err)
	}
	master, err := primitives.PubkeyFromBase58(old.Anchors.MasterMint)
	if err != nil {
		t.Fatal(err)
	}
	program, err := primitives.PubkeyFromBase58(b.Statement.RegistryProgram)
	if err != nil {
		t.Fatal(err)
	}
	core, err := primitives.PubkeyFromBase58(b.Statement.CoreVault)
	if err != nil {
		t.Fatal(err)
	}
	trust := make([]byte, trustAccountSize)
	disc := sha256.Sum256([]byte("account:InstallerReleaseTrust"))
	copy(trust[:8], disc[:8])
	copy(trust[8:40], master[:])
	copy(trust[40:72], core[:])
	profileDigest, _ := hex.DecodeString(b.Statement.OldProfileDigest)
	copy(trust[72:104], profileDigest)
	trust[104] = byte(old.ReleaseTrust.Threshold)
	binary.LittleEndian.PutUint32(trust[105:109], uint32(len(old.ReleaseTrust.PublisherKeys)))
	for index, key := range old.ReleaseTrust.PublisherKeys {
		decoded, _ := hex.DecodeString(key)
		copy(trust[109+index*32:109+(index+1)*32], decoded)
	}
	trust[109+len(old.ReleaseTrust.PublisherKeys)*32] = 255
	b.Statement.LiveTrustRawSHA256 = shaHex(trust)
	intent, err := IntentDigest(b.Statement)
	if err != nil {
		t.Fatal(err)
	}
	observed.FoundationBridgeIntentSHA256 = intent
	trustPDA, _, err := primitives.FindProgramAddress([][]byte{[]byte("installer_release_trust"), master[:]}, program, nil)
	if err != nil {
		t.Fatal(err)
	}
	readback := RawReadback{Trust: RawAccount{Address: trustPDA.Base58(), Owner: program.Base58(), Data: trust}, Entries: map[string]RawAccount{}}
	publisher := releasetest.TrustedPublisher()
	for index, member := range b.Statement.Members {
		artifactBytes, _ := hex.DecodeString(member.ArtifactSHA256)
		var artifact [32]byte
		copy(artifact[:], artifactBytes)
		entry := releasetest.Entry(t, old, artifact, "1.0.50", publisher)
		entry.Legacy = false
		copy(entry.ReleaseTrustProfileHash[:], profileDigest)
		entry.SignedPayloadHash = installerrelease.PayloadHashV2(entry.MasterNFTMint, entry.InstallerHash, entry.Version,
			entry.PublisherSquadsVault, entry.PublisherEd25519Pubkey, entry.ReleaseTrustProfileHash)
		copy(entry.PublisherSignature[:], ed25519.Sign(publisher, entry.SignedPayloadHash[:]))
		_, bump, err := primitives.DeriveInstallerRelease(master, artifact, program)
		if err != nil {
			t.Fatal(err)
		}
		entry.Bump = uint8(bump)
		raw := releasetest.Encode(entry)
		b.Statement.Members[index].EntryRawSHA256 = shaHex(raw)
		readback.Entries[member.Role] = RawAccount{Address: member.EntryPDA, Owner: program.Base58(), Data: raw}
	}
	signBridge(t, &b, old.OwnerPolicy.PolicyID)
	return b, oldRaw, successorRaw, observed, readback
}

func TestRecoveryBridgeRawAccountsPositiveAndDrift(t *testing.T) {
	b, old, successor, observed, readback := rawFixture(t)
	if _, err := VerifyRawReadback(b, old, successor, observed, readback); err != nil {
		t.Fatal(err)
	}
	readback.Trust.Data = append([]byte(nil), readback.Trust.Data...)
	readback.Trust.Data[len(readback.Trust.Data)-1] ^= 1
	if _, err := VerifyRawReadback(b, old, successor, observed, readback); !errors.Is(err, ErrChainDrift) {
		t.Fatalf("raw trust drift: %v", err)
	}
}

func TestRecoveryBridgeRawEntryCannotBeSubstitutedOrMadeInactive(t *testing.T) {
	b, old, successor, observed, readback := rawFixture(t)
	entry := readback.Entries["installer"]
	entry.Data = append([]byte(nil), entry.Data...)
	entry.Data[len(entry.Data)-1] ^= 1
	readback.Entries["installer"] = entry
	if _, err := VerifyRawReadback(b, old, successor, observed, readback); !errors.Is(err, ErrChainDrift) {
		t.Fatalf("substituted entry raw: %v", err)
	}
}
