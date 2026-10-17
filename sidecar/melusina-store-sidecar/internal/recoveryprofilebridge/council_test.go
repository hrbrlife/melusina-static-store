package recoveryprofilebridge

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func TestRecoveryBridgeCouncilFromLiveSquadsRaw(t *testing.T) {
	bridge, oldRaw, _, _ := fixture(t)
	var profile estateprofile.EstateProfileV1
	if err := json.Unmarshal(oldRaw, &profile); err != nil {
		t.Fatal(err)
	}
	var program primitives.Pubkey
	for _, external := range profile.ExternalPrograms {
		if external.Role == estateprofile.ExternalRoleSquadsV4 {
			var err error
			program, err = primitives.PubkeyFromBase58(external.ProgramID)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	createKey := sha256.Sum256([]byte("bridge-test-core-create-key"))
	core, _, err := primitives.FindProgramAddress([][]byte{[]byte("multisig"), []byte("multisig"), createKey[:]}, program, nil)
	if err != nil {
		t.Fatal(err)
	}
	vault, _, err := primitives.FindProgramAddress([][]byte{[]byte("multisig"), core[:], []byte("vault"), []byte{0}}, program, nil)
	if err != nil {
		t.Fatal(err)
	}
	bridge.Statement.CoreMultisig, bridge.Statement.CoreVault = core.Base58(), vault.Base58()
	raw := make([]byte, 232)
	disc := sha256.Sum256([]byte("account:Multisig"))
	copy(raw[:8], disc[:8])
	copy(raw[8:40], createKey[:])
	binary.LittleEndian.PutUint16(raw[72:74], 3)
	binary.LittleEndian.PutUint64(raw[78:86], 181)
	binary.LittleEndian.PutUint32(raw[96:100], 4)
	for i := 0; i < 4; i++ {
		key := sha256.Sum256([]byte{byte(i + 1)})
		copy(raw[100+i*33:], key[:])
		raw[100+i*33+32] = 7
	}
	account := RawAccount{Address: core.Base58(), Owner: program.Base58(), Data: raw}
	members, threshold, err := VerifyCouncilRaw(profile, bridge.Statement, account)
	if err != nil || len(members) != 4 || threshold != 3 {
		t.Fatalf("live core refused: %v", err)
	}
	for name, change := range map[string]func(*RawAccount){
		"foreign-owner":      func(a *RawAccount) { a.Owner = testAddress("foreign-squads-program") },
		"short-council":      func(a *RawAccount) { a.Data[72] = 2 },
		"foreign-permission": func(a *RawAccount) { a.Data[132] = 1 },
		"hidden-duplicate":   func(a *RawAccount) { copy(a.Data[133:165], a.Data[100:132]) },
		"stale-index":        func(a *RawAccount) { binary.LittleEndian.PutUint64(a.Data[78:86], 180) },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := account
			mutated.Data = append([]byte(nil), account.Data...)
			change(&mutated)
			if _, _, err := VerifyCouncilRaw(profile, bridge.Statement, mutated); !errors.Is(err, ErrChainDrift) {
				t.Fatalf("mutation accepted: %v", err)
			}
		})
	}
}
