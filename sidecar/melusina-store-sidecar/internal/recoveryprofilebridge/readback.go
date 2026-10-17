package recoveryprofilebridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const trustAccountSize = 8 + 32 + 32 + 32 + 1 + 4 + 16*32 + 1

type RawAccount struct {
	Address string
	Owner   string
	Data    []byte
}

type RawReadback struct {
	Trust   RawAccount
	Entries map[string]RawAccount
}

// VerifyRawReadback builds the trust and member part of Observation from raw
// finalized program accounts. A caller cannot use decoded values from a
// request as a substitute. The three entries still pass the unchanged old
// profile Trust.Admit rule, including their threshold publisher signatures.
func VerifyRawReadback(b Signed, oldRaw, successorRaw []byte, observed Observation, readback RawReadback) (string, error) {
	old, err := estateprofile.DecodeProfile(oldRaw)
	if err != nil {
		return "", fmt.Errorf("%w: old profile: %v", ErrProfile, err)
	}
	program, err := primitives.PubkeyFromBase58(b.Statement.RegistryProgram)
	if err != nil {
		return "", ErrChainDrift
	}
	master, err := primitives.PubkeyFromBase58(b.Statement.MasterMint)
	if err != nil {
		return "", ErrChainDrift
	}
	trustPDA, _, err := primitives.FindProgramAddress([][]byte{[]byte("installer_release_trust"), master[:]}, program, nil)
	if err != nil || readback.Trust.Address != trustPDA.Base58() || readback.Trust.Owner != program.Base58() ||
		shaHex(readback.Trust.Data) != b.Statement.LiveTrustRawSHA256 {
		return "", ErrChainDrift
	}
	profileDigest, threshold, keys, err := decodeTrustAccount(readback.Trust.Data, master, b.Statement.CoreVault)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrChainDrift, err)
	}
	observed.TrustRawSHA256 = shaHex(readback.Trust.Data)
	observed.TrustProfileDigest = profileDigest
	observed.TrustThreshold = threshold
	observed.TrustPublisherKeys = keys
	oldTrust, _, err := installerrelease.TrustFromProfile(old)
	if err != nil {
		return "", fmt.Errorf("%w: old trust: %v", ErrProfile, err)
	}
	if len(readback.Entries) != 3 {
		return "", ErrMember
	}
	observed.Members = make([]Member, 0, 3)
	for _, member := range b.Statement.Members {
		account, ok := readback.Entries[member.Role]
		if !ok || account.Address != member.EntryPDA || account.Owner != program.Base58() ||
			shaHex(account.Data) != member.EntryRawSHA256 {
			return "", ErrChainDrift
		}
		entry, err := installerrelease.Decode(account.Data)
		if err != nil {
			return "", fmt.Errorf("%w: entry %s: %v", ErrChainDrift, member.Role, err)
		}
		artifactRaw, _ := hex.DecodeString(member.ArtifactSHA256)
		var artifact [32]byte
		copy(artifact[:], artifactRaw)
		_, bump, err := primitives.DeriveInstallerRelease(master, artifact, program)
		if err != nil || entry.Bump != uint8(bump) {
			return "", ErrChainDrift
		}
		if err := oldTrust.Admit(entry, artifact); err != nil {
			return "", fmt.Errorf("%w: entry %s: %v", ErrChainDrift, member.Role, err)
		}
		if entry.Status != verify.AttestationStatusActive {
			return "", ErrChainDrift
		}
		found := member
		found.EntryRawSHA256 = shaHex(account.Data)
		found.EntryProfileDigest = hex.EncodeToString(entry.ReleaseTrustProfileHash[:])
		found.EntryStatus = "Active"
		observed.Members = append(observed.Members, found)
	}
	return Verify(b, oldRaw, successorRaw, observed)
}

func shaHex(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

// decodeTrustAccount checks the exact fixed-size Anchor allocation and the
// Borsh Vec length. The unused account tail must be zero, so a raw SHA-256
// pins one unambiguous threshold/keyset/bump tuple.
func decodeTrustAccount(raw []byte, master primitives.Pubkey, coreVault string) (string, uint32, []string, error) {
	discriminator := sha256.Sum256([]byte("account:InstallerReleaseTrust"))
	if len(raw) != trustAccountSize || !bytes.Equal(raw[:8], discriminator[:8]) ||
		!bytes.Equal(raw[8:40], master[:]) {
		return "", 0, nil, ErrChainDrift
	}
	core, err := primitives.PubkeyFromBase58(coreVault)
	if err != nil || !bytes.Equal(raw[40:72], core[:]) {
		return "", 0, nil, ErrChainDrift
	}
	profile := hex.EncodeToString(raw[72:104])
	threshold := uint32(raw[104])
	count := binary.LittleEndian.Uint32(raw[105:109])
	if count == 0 || count > 16 || threshold == 0 || threshold > count {
		return "", 0, nil, ErrChainDrift
	}
	keys := make([]string, 0, count)
	end := 109 + int(count)*32
	for cursor := 109; cursor < end; cursor += 32 {
		keys = append(keys, hex.EncodeToString(raw[cursor:cursor+32]))
	}
	if !bytes.Equal(raw[end+1:], make([]byte, len(raw)-end-1)) {
		return "", 0, nil, ErrChainDrift
	}
	return profile, threshold, keys, nil
}
