package squadsproof

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type sdkFixture struct {
	SDKVersion              string `json:"sdk_version"`
	ProgramID               string `json:"program_id"`
	CreateKey               string `json:"create_key"`
	MultisigAddress         string `json:"multisig_address"`
	VaultTransactionAddress string `json:"vault_transaction_address"`
	ProposalAddress         string `json:"proposal_address"`
	VaultAddress            string `json:"vault_address"`
	MemoPayload             string `json:"memo_payload"`
	MultisigDataHex         string `json:"multisig_data_hex"`
	ProposalDataHex         string `json:"proposal_data_hex"`
	VaultTransactionDataHex string `json:"vault_transaction_data_hex"`
}

func loadSDKFixture(t *testing.T) sdkFixture {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test fixture")
	}
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata", "squadsproof", "squads-v4-memo-only.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture sdkFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if fixture.SDKVersion != "2.1.4" {
		t.Fatalf("fixture SDK version = %q, want 2.1.4", fixture.SDKVersion)
	}
	return fixture
}

func fixturePubkey(t *testing.T, s string) Pubkey {
	t.Helper()
	key, err := DecodePubkey(s)
	if err != nil {
		t.Fatalf("decode fixture pubkey %q: %v", s, err)
	}
	return key
}

func fixtureData(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode fixture hex: %v", err)
	}
	return b
}

func fixtureAccounts(t *testing.T) (sdkFixture, Pubkey, Account, Account, Account) {
	t.Helper()
	fixture := loadSDKFixture(t)
	programID := fixturePubkey(t, fixture.ProgramID)
	multisig := Account{
		Address: fixturePubkey(t, fixture.MultisigAddress),
		Owner:   programID,
		Data:    fixtureData(t, fixture.MultisigDataHex),
	}
	proposal := Account{
		Address: fixturePubkey(t, fixture.ProposalAddress),
		Owner:   programID,
		Data:    fixtureData(t, fixture.ProposalDataHex),
	}
	vaultTransaction := Account{
		Address: fixturePubkey(t, fixture.VaultTransactionAddress),
		Owner:   programID,
		Data:    fixtureData(t, fixture.VaultTransactionDataHex),
	}
	return fixture, programID, multisig, proposal, vaultTransaction
}

func TestSDKFixtureParsesAndBindsMemoOnlyProof(t *testing.T) {
	fixture, programID, multisigAccount, proposalAccount, vaultTransactionAccount := fixtureAccounts(t)
	if programID != DefaultProgramID {
		t.Fatalf("fixture program id does not match installed Squads v4 default")
	}

	multisig, err := ParseMultisig(multisigAccount, programID)
	if err != nil {
		t.Fatalf("parse multisig fixture: %v", err)
	}
	if multisig.Threshold != 2 || multisig.TransactionIndex != 7 || multisig.StaleTransactionIndex != 0 || len(multisig.Members) != 3 {
		t.Fatalf("unexpected parsed multisig: %#v", multisig)
	}
	if multisig.RentCollector != nil {
		t.Fatal("fixture rent collector unexpectedly set")
	}

	proposal, err := ParseProposal(proposalAccount, programID)
	if err != nil {
		t.Fatalf("parse proposal fixture: %v", err)
	}
	if !proposal.Status.IsExecuted() || !proposal.Status.TimestampSet || proposal.Status.Timestamp != 123456789 {
		t.Fatalf("unexpected parsed proposal status: %#v", proposal.Status)
	}
	if err := multisig.ValidateProposalApprovalSet(proposal); err != nil {
		t.Fatalf("validate fixture approvals: %v", err)
	}

	vaultTransaction, err := ParseVaultTransaction(vaultTransactionAccount, programID)
	if err != nil {
		t.Fatalf("parse vault transaction fixture: %v", err)
	}
	if vaultTransaction.Multisig != multisig.Address || vaultTransaction.Index != proposal.TransactionIndex || vaultTransaction.Index != 7 {
		t.Fatalf("vault transaction did not bind to parsed multisig/proposal: %#v", vaultTransaction)
	}
	if vaultTransaction.Message.NumSigners != 1 || vaultTransaction.Message.NumWritableSigners != 1 || vaultTransaction.Message.NumWritableNonSigners != 0 {
		t.Fatalf("fixture has non-canonical memo header: %#v", vaultTransaction.Message)
	}
	if len(vaultTransaction.Message.AccountKeys) != 2 || vaultTransaction.Message.AccountKeys[0] != fixturePubkey(t, fixture.VaultAddress) || vaultTransaction.Message.AccountKeys[1] != DefaultMemoProgramID {
		t.Fatalf("fixture has non-canonical memo key vector: %#v", vaultTransaction.Message.AccountKeys)
	}
	if len(vaultTransaction.Message.Instructions) != 1 || vaultTransaction.Message.Instructions[0].ProgramIDIndex != 1 || string(vaultTransaction.Message.Instructions[0].AccountIndexes) != string([]byte{0}) {
		t.Fatalf("fixture has non-canonical memo instruction: %#v", vaultTransaction.Message.Instructions)
	}
	if err := ValidateExecutedProposalTransaction(proposal, vaultTransaction); err != nil {
		t.Fatalf("bind executed proposal to vault transaction: %v", err)
	}
	payload, err := vaultTransaction.MemoOnlyPayload(programID, DefaultMemoProgramID)
	if err != nil {
		t.Fatalf("extract memo-only payload: %v", err)
	}
	if string(payload) != fixture.MemoPayload {
		t.Fatalf("memo payload = %q, want %q", payload, fixture.MemoPayload)
	}
}

func TestMultisigAcceptsOnlyCanonicalUnsetRentCollectorPadding(t *testing.T) {
	_, programID, multisig, _, _ := fixtureAccounts(t)

	canonical := multisig
	canonical.Data = append(append([]byte(nil), multisig.Data...), make([]byte, 32)...)
	parsed, err := ParseMultisig(canonical, programID)
	if err != nil {
		t.Fatalf("parse canonical unset-rent-collector padding: %v", err)
	}
	if parsed.RentCollector != nil {
		t.Fatal("canonical padded fixture unexpectedly set rent collector")
	}

	nonzero := canonical
	nonzero.Data = append([]byte(nil), canonical.Data...)
	nonzero.Data[len(nonzero.Data)-1] = 1
	if _, err := ParseMultisig(nonzero, programID); err == nil || !strings.Contains(err.Error(), "nonzero unset rent collector padding") {
		t.Fatalf("nonzero padding error = %v", err)
	}

	wrongLength := multisig
	wrongLength.Data = append(append([]byte(nil), multisig.Data...), make([]byte, 31)...)
	if _, err := ParseMultisig(wrongLength, programID); err == nil || !strings.Contains(err.Error(), "trailing 31 bytes") {
		t.Fatalf("wrong-length padding error = %v", err)
	}
}

// The expected addresses and bumps in this test were emitted by the installed
// @sqds/multisig v2.1.4 SDK's get*Pda helpers.  This keeps the Go helpers tied
// to the actual JS client that creates the production Squads accounts.
func TestPDADerivationsMatchSDKFixture(t *testing.T) {
	fixture, programID, _, _, _ := fixtureAccounts(t)
	createKey := fixturePubkey(t, fixture.CreateKey)
	multisig, multisigBump, err := DeriveMultisigPDA(createKey, programID)
	if err != nil {
		t.Fatalf("derive multisig: %v", err)
	}
	if got, want := multisig, fixturePubkey(t, fixture.MultisigAddress); got != want || multisigBump != 255 {
		t.Fatalf("multisig PDA = %v/%d, want %v/255", got, multisigBump, want)
	}
	vaultTransaction, transactionBump, err := DeriveVaultTransactionPDA(multisig, 7, programID)
	if err != nil {
		t.Fatalf("derive vault transaction: %v", err)
	}
	if got, want := vaultTransaction, fixturePubkey(t, fixture.VaultTransactionAddress); got != want || transactionBump != 255 {
		t.Fatalf("vault transaction PDA = %v/%d, want %v/255", got, transactionBump, want)
	}
	proposal, proposalBump, err := DeriveProposalPDA(multisig, 7, programID)
	if err != nil {
		t.Fatalf("derive proposal: %v", err)
	}
	if got, want := proposal, fixturePubkey(t, fixture.ProposalAddress); got != want || proposalBump != 253 {
		t.Fatalf("proposal PDA = %v/%d, want %v/253", got, proposalBump, want)
	}
	vault, vaultBump, err := DeriveVaultPDA(multisig, 0, programID)
	if err != nil {
		t.Fatalf("derive vault: %v", err)
	}
	if got, want := vault, fixturePubkey(t, fixture.VaultAddress); got != want || vaultBump != 253 {
		t.Fatalf("vault PDA = %v/%d, want %v/253", got, vaultBump, want)
	}
}

func TestParsersFailClosedOnOwnerDiscriminatorPDAAndTrailingBytes(t *testing.T) {
	_, programID, multisig, proposal, vaultTransaction := fixtureAccounts(t)
	wrongOwner := programID
	wrongOwner[0] ^= 0xff

	tests := []struct {
		name string
		call func() error
		want string
	}{
		{
			name: "multisig wrong owner",
			call: func() error {
				a := multisig
				a.Owner = wrongOwner
				_, err := ParseMultisig(a, programID)
				return err
			},
			want: "owner",
		},
		{
			name: "proposal wrong discriminator",
			call: func() error {
				a := proposal
				a.Data = append([]byte(nil), a.Data...)
				a.Data[0] ^= 0xff
				_, err := ParseProposal(a, programID)
				return err
			},
			want: "discriminator",
		},
		{
			name: "vault transaction noncanonical pda",
			call: func() error {
				a := vaultTransaction
				a.Address = proposal.Address
				_, err := ParseVaultTransaction(a, programID)
				return err
			},
			want: "PDA",
		},
		{
			name: "multisig trailing bytes",
			call: func() error {
				a := multisig
				a.Data = append(append([]byte(nil), a.Data...), 0)
				_, err := ParseMultisig(a, programID)
				return err
			},
			want: "trailing",
		},
		{
			name: "proposal unknown status",
			call: func() error {
				a := proposal
				a.Data = append([]byte(nil), a.Data...)
				// 8-byte discriminator + 32-byte multisig + 8-byte index.
				a.Data[48] = 99
				_, err := ParseProposal(a, programID)
				return err
			},
			want: "unknown proposal status",
		},
		{
			name: "truncated vault transaction",
			call: func() error {
				a := vaultTransaction
				a.Data = a.Data[:len(a.Data)-1]
				_, err := ParseVaultTransaction(a, programID)
				return err
			},
			want: "truncated",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestMemoOnlyAndApprovalHelpersRefuseBroaderProofs(t *testing.T) {
	_, programID, multisigAccount, proposalAccount, vaultTransactionAccount := fixtureAccounts(t)
	multisig, err := ParseMultisig(multisigAccount, programID)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := ParseProposal(proposalAccount, programID)
	if err != nil {
		t.Fatal(err)
	}
	vaultTransaction, err := ParseVaultTransaction(vaultTransactionAccount, programID)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("approval threshold", func(t *testing.T) {
		less := proposal
		less.Approved = append([]Pubkey(nil), proposal.Approved[:1]...)
		if err := multisig.ValidateProposalApprovalSet(less); err == nil || !strings.Contains(err.Error(), "below threshold") {
			t.Fatalf("error = %v, want threshold refusal", err)
		}
	})
	t.Run("non-voting approval", func(t *testing.T) {
		nonVoter := proposal
		nonVoter.Approved = []Pubkey{multisig.Members[2].Key, multisig.Members[0].Key}
		if err := multisig.ValidateProposalApprovalSet(nonVoter); err == nil || !strings.Contains(err.Error(), "not a voting member") {
			t.Fatalf("error = %v, want voting-member refusal", err)
		}
	})
	t.Run("extra instruction", func(t *testing.T) {
		broader := vaultTransaction
		broader.Message.Instructions = append(append([]CompiledInstruction(nil), vaultTransaction.Message.Instructions...), CompiledInstruction{})
		if _, err := broader.MemoOnlyPayload(programID, DefaultMemoProgramID); err == nil || !strings.Contains(err.Error(), "2 instructions") {
			t.Fatalf("error = %v, want instruction-count refusal", err)
		}
	})
	t.Run("instruction accounts", func(t *testing.T) {
		broader := vaultTransaction
		broader.Message.Instructions = append([]CompiledInstruction(nil), vaultTransaction.Message.Instructions...)
		broader.Message.Instructions[0].AccountIndexes = []byte{1}
		if _, err := broader.MemoOnlyPayload(programID, DefaultMemoProgramID); err == nil || !strings.Contains(err.Error(), "accounts are not") {
			t.Fatalf("error = %v, want account-index refusal", err)
		}
	})
	t.Run("lookup table", func(t *testing.T) {
		broader := vaultTransaction
		broader.Message.AddressTableLookups = []AddressTableLookup{{}}
		if _, err := broader.MemoOnlyPayload(programID, DefaultMemoProgramID); err == nil || !strings.Contains(err.Error(), "address table") {
			t.Fatalf("error = %v, want lookup refusal", err)
		}
	})
	t.Run("wrong vault key", func(t *testing.T) {
		broader := vaultTransaction
		broader.Message.AccountKeys = append([]Pubkey(nil), vaultTransaction.Message.AccountKeys...)
		broader.Message.AccountKeys[0] = DefaultMemoProgramID
		if _, err := broader.MemoOnlyPayload(programID, DefaultMemoProgramID); err == nil || !strings.Contains(err.Error(), "account keys") {
			t.Fatalf("error = %v, want vault-key refusal", err)
		}
	})
	t.Run("wrong signer header", func(t *testing.T) {
		broader := vaultTransaction
		broader.Message.NumSigners = 0
		if _, err := broader.MemoOnlyPayload(programID, DefaultMemoProgramID); err == nil || !strings.Contains(err.Error(), "signer/writable header") {
			t.Fatalf("error = %v, want header refusal", err)
		}
	})
	t.Run("proposal transaction mismatch", func(t *testing.T) {
		wrong := vaultTransaction
		wrong.Index++
		if err := ValidateExecutedProposalTransaction(proposal, wrong); err == nil || !strings.Contains(err.Error(), "transaction indexes") {
			t.Fatalf("error = %v, want proposal/transaction binding refusal", err)
		}
	})
}

func TestParsedDataDoesNotAliasCallerBytes(t *testing.T) {
	fixture, programID, _, _, vaultTransactionAccount := fixtureAccounts(t)
	vaultTransaction, err := ParseVaultTransaction(vaultTransactionAccount, programID)
	if err != nil {
		t.Fatal(err)
	}
	// The payload starts at a known place only in the fixture; mutating every
	// input byte proves the parser has copied its externally visible byte slices.
	for i := range vaultTransactionAccount.Data {
		vaultTransactionAccount.Data[i] ^= 0xff
	}
	payload, err := vaultTransaction.MemoOnlyPayload(programID, DefaultMemoProgramID)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != fixture.MemoPayload {
		t.Fatalf("payload changed after caller data mutation: %q", payload)
	}
}

func TestDecodePubkeyIsExactAndCanonical(t *testing.T) {
	if _, err := DecodePubkey(DefaultProgramIDBase58); err != nil {
		t.Fatalf("decode default program id: %v", err)
	}
	if _, err := DecodePubkey("not-base58!"); err == nil {
		t.Fatal("invalid base58 accepted")
	}
	if _, err := DecodePubkey("1111111111111111111111111111111"); err == nil {
		t.Fatal("wrong-length pubkey accepted")
	}
}
