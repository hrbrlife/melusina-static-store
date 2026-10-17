package recoveryprofilebridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"sort"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// VerifyCouncilRaw derives the bridge's signing authority from the finalized
// Squads multisig account. A caller-provided member list is never authority.
func VerifyCouncilRaw(profile estateprofile.EstateProfileV1, statement Statement, account RawAccount) ([]string, uint32, error) {
	programID := ""
	for _, program := range profile.ExternalPrograms {
		if program.Role == estateprofile.ExternalRoleSquadsV4 {
			programID = program.ProgramID
		}
	}
	program, err := primitives.PubkeyFromBase58(programID)
	if err != nil || account.Owner != programID || account.Address != statement.CoreMultisig {
		return nil, 0, ErrChainDrift
	}
	raw := account.Data
	disc := sha256.Sum256([]byte("account:Multisig"))
	if len(raw) != 232 || !bytes.Equal(raw[:8], disc[:8]) ||
		!bytes.Equal(raw[40:72], make([]byte, 32)) ||
		raw[94] != 0 || binary.LittleEndian.Uint32(raw[96:100]) != 4 ||
		binary.LittleEndian.Uint64(raw[78:86]) < 181 {
		return nil, 0, ErrChainDrift
	}
	threshold := uint32(binary.LittleEndian.Uint16(raw[72:74]))
	if threshold != 3 {
		return nil, 0, ErrChainDrift
	}
	core, _, err := primitives.FindProgramAddress([][]byte{[]byte("multisig"), []byte("multisig"), raw[8:40]}, program, nil)
	if err != nil || core.Base58() != statement.CoreMultisig {
		return nil, 0, ErrChainDrift
	}
	vault, _, err := primitives.FindProgramAddress([][]byte{[]byte("multisig"), core[:], []byte("vault"), []byte{0}}, program, nil)
	if err != nil || vault.Base58() != statement.CoreVault {
		return nil, 0, ErrChainDrift
	}
	members := make([]string, 4)
	for i := range members {
		at := 100 + 33*i
		if raw[at+32] != 7 {
			return nil, 0, ErrChainDrift
		}
		var key primitives.Pubkey
		copy(key[:], raw[at:at+32])
		members[i] = key.Base58()
	}
	sort.Strings(members)
	for i := 1; i < len(members); i++ {
		if members[i] == members[i-1] {
			return nil, 0, ErrChainDrift
		}
	}
	return members, threshold, nil
}
