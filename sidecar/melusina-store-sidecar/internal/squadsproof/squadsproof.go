// Package squadsproof strictly decodes the small subset of Squads v4 accounts
// needed to prove that a particular VaultTransaction was an executed,
// memo-only governance action.  It deliberately has no RPC or signing code:
// callers supply the address, owner, and account bytes they read from a
// consistent Solana snapshot.
//
// The layouts and PDA seeds in this package mirror @sqds/multisig v2.1.4,
// whose IDL identifies the deployed v4 program as
// SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf.  Unknown account extensions,
// unknown enum values, malformed vectors, a non-canonical PDA, or an owner
// mismatch are all refusals.  That is intentional: this package is an
// authorization proof parser, not a best-effort account inspector.
package squadsproof

import (
	"bytes"
	"encoding/binary"
	"fmt"

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// Pubkey is a 32-byte Solana public key.
type Pubkey = primitives.Pubkey

const (
	// DefaultProgramIDBase58 is @sqds/multisig v2.1.4's v4 program id.
	DefaultProgramIDBase58 = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"
	// DefaultMemoProgramIDBase58 is the Solana SPL Memo v2 program used by
	// memo-only governance proofs.
	DefaultMemoProgramIDBase58 = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"

	// Permission bits from @sqds/multisig/src/types.ts.
	PermissionInitiate uint8 = 0b0000_0001
	PermissionVote     uint8 = 0b0000_0010
	PermissionExecute  uint8 = 0b0000_0100

	maxAccountDataBytes        = 1 << 20 // ample for a Solana transaction account; bounds hostile input.
	maxMembers                 = 65535   // Squads' documented member maximum.
	maxAccountKeys             = 256     // compiled instruction indices are u8.
	maxInstructions            = 4096
	maxInstructionDataBytes    = 1 << 16
	maxEphemeralSignerBumps    = 256
	maxAddressTableLookups     = 256
	maxAddressTableIndexBytes  = 256
	maxInstructionAccountBytes = 256
)

var (
	// DefaultProgramID is the decoded form of DefaultProgramIDBase58.
	DefaultProgramID = mustDecodePubkey(DefaultProgramIDBase58)
	// DefaultMemoProgramID is the decoded form of DefaultMemoProgramIDBase58.
	DefaultMemoProgramID = mustDecodePubkey(DefaultMemoProgramIDBase58)

	multisigDiscriminator         = [8]byte{224, 116, 121, 186, 68, 161, 79, 236}
	proposalDiscriminator         = [8]byte{26, 94, 189, 187, 116, 136, 53, 33}
	vaultTransactionDiscriminator = [8]byte{168, 250, 162, 100, 81, 14, 162, 207}
)

// DecodePubkey parses an exact, canonical base58-encoded Solana public key.
func DecodePubkey(s string) (Pubkey, error) {
	raw, err := primitives.DecodeBase58(s)
	if err != nil {
		return Pubkey{}, fmt.Errorf("squadsproof: decode pubkey: %w", err)
	}
	if len(raw) != len(Pubkey{}) {
		return Pubkey{}, fmt.Errorf("squadsproof: decode pubkey: got %d bytes, want %d", len(raw), len(Pubkey{}))
	}
	if primitives.EncodeBase58(raw) != s {
		return Pubkey{}, fmt.Errorf("squadsproof: decode pubkey: non-canonical base58")
	}
	var out Pubkey
	copy(out[:], raw)
	return out, nil
}

func mustDecodePubkey(s string) Pubkey {
	key, err := DecodePubkey(s)
	if err != nil {
		panic(err)
	}
	return key
}

// Account is the complete account evidence a parser needs.  Address and Owner
// are deliberately mandatory: accepting only data bytes would let a caller
// detach otherwise-valid account contents from their program/PDA binding.
type Account struct {
	Address Pubkey
	Owner   Pubkey
	Data    []byte
}

// Member mirrors the Squads v4 Member struct.
type Member struct {
	Key         Pubkey
	Permissions uint8
}

// CanVote reports whether this member holds Squads' Vote permission.
func (m Member) CanVote() bool { return m.Permissions&PermissionVote != 0 }

// Multisig mirrors @sqds/multisig's Multisig account.  Address is retained so
// a Proposal can be bound to the exact parsed account without a caller-side
// string conversion.
type Multisig struct {
	Address               Pubkey
	CreateKey             Pubkey
	ConfigAuthority       Pubkey
	Threshold             uint16
	TimeLock              uint32
	TransactionIndex      uint64
	StaleTransactionIndex uint64
	RentCollector         *Pubkey
	Bump                  uint8
	Members               []Member
}

// ProposalStatusKind is Squads v4's proposal status enum discriminant.
type ProposalStatusKind uint8

const (
	ProposalStatusDraft ProposalStatusKind = iota
	ProposalStatusActive
	ProposalStatusRejected
	ProposalStatusApproved
	ProposalStatusExecuting
	ProposalStatusExecuted
	ProposalStatusCancelled
)

// ProposalStatus mirrors Squads' ProposalStatus.  Executing is the sole
// status without a timestamp; TimestampSet distinguishes it from a timestamp
// of zero.
type ProposalStatus struct {
	Kind         ProposalStatusKind
	Timestamp    int64
	TimestampSet bool
}

// IsExecuted reports whether the on-chain proposal has reached Executed.
func (s ProposalStatus) IsExecuted() bool { return s.Kind == ProposalStatusExecuted }

// Proposal mirrors @sqds/multisig's Proposal account.
type Proposal struct {
	Address          Pubkey
	Multisig         Pubkey
	TransactionIndex uint64
	Status           ProposalStatus
	Bump             uint8
	Approved         []Pubkey
	Rejected         []Pubkey
	Cancelled        []Pubkey
}

// CompiledInstruction mirrors Squads' MultisigCompiledInstruction.  Its byte
// slices are owned copies, so a later mutation of Account.Data cannot alter a
// parsed proof.
type CompiledInstruction struct {
	ProgramIDIndex uint8
	AccountIndexes []byte
	Data           []byte
}

// AddressTableLookup mirrors Squads' MultisigMessageAddressTableLookup.
type AddressTableLookup struct {
	AccountKey      Pubkey
	WritableIndexes []byte
	ReadonlyIndexes []byte
}

// VaultTransactionMessage mirrors Squads' VaultTransactionMessage.
type VaultTransactionMessage struct {
	NumSigners            uint8
	NumWritableSigners    uint8
	NumWritableNonSigners uint8
	AccountKeys           []Pubkey
	Instructions          []CompiledInstruction
	AddressTableLookups   []AddressTableLookup
}

// VaultTransaction mirrors @sqds/multisig's VaultTransaction account.
type VaultTransaction struct {
	Address              Pubkey
	Multisig             Pubkey
	Creator              Pubkey
	Index                uint64
	Bump                 uint8
	VaultIndex           uint8
	VaultBump            uint8
	EphemeralSignerBumps []byte
	Message              VaultTransactionMessage
}

// DeriveMultisigPDA mirrors getMultisigPda({createKey, programId}).
func DeriveMultisigPDA(createKey, programID Pubkey) (Pubkey, uint8, error) {
	return derivePDA(programID, [][]byte{[]byte("multisig"), []byte("multisig"), createKey[:]})
}

// DeriveVaultPDA mirrors getVaultPda({multisigPda, index, programId}).
func DeriveVaultPDA(multisig Pubkey, index uint8, programID Pubkey) (Pubkey, uint8, error) {
	return derivePDA(programID, [][]byte{[]byte("multisig"), multisig[:], []byte("vault"), []byte{index}})
}

// DeriveVaultTransactionPDA mirrors getTransactionPda({multisigPda, index,
// programId}).  Squads calls this account a Transaction PDA even though the
// account type is VaultTransaction.
func DeriveVaultTransactionPDA(multisig Pubkey, index uint64, programID Pubkey) (Pubkey, uint8, error) {
	return derivePDA(programID, [][]byte{[]byte("multisig"), multisig[:], []byte("transaction"), u64LE(index)})
}

// DeriveProposalPDA mirrors getProposalPda({multisigPda, transactionIndex,
// programId}).
func DeriveProposalPDA(multisig Pubkey, transactionIndex uint64, programID Pubkey) (Pubkey, uint8, error) {
	return derivePDA(programID, [][]byte{[]byte("multisig"), multisig[:], []byte("transaction"), u64LE(transactionIndex), []byte("proposal")})
}

func derivePDA(programID Pubkey, seeds [][]byte) (Pubkey, uint8, error) {
	if isZero(programID) {
		return Pubkey{}, 0, fmt.Errorf("squadsproof: program id is zero")
	}
	key, bump, err := primitives.FindProgramAddress(seeds, programID, nil)
	if err != nil {
		return Pubkey{}, 0, fmt.Errorf("squadsproof: derive PDA: %w", err)
	}
	return key, bump, nil
}

func u64LE(n uint64) []byte {
	var out [8]byte
	binary.LittleEndian.PutUint64(out[:], n)
	return out[:]
}

// ParseMultisig parses and binds a Squads v4 Multisig account to its expected
// program owner and canonical PDA.
func ParseMultisig(account Account, programID Pubkey) (Multisig, error) {
	d, err := newDecoder(account, programID, multisigDiscriminator, "multisig")
	if err != nil {
		return Multisig{}, err
	}

	var out Multisig
	out.Address = account.Address
	if out.CreateKey, err = d.pubkey("create_key"); err != nil {
		return Multisig{}, err
	}
	if out.ConfigAuthority, err = d.pubkey("config_authority"); err != nil {
		return Multisig{}, err
	}
	if out.Threshold, err = d.u16("threshold"); err != nil {
		return Multisig{}, err
	}
	if out.TimeLock, err = d.u32("time_lock"); err != nil {
		return Multisig{}, err
	}
	if out.TransactionIndex, err = d.u64("transaction_index"); err != nil {
		return Multisig{}, err
	}
	if out.StaleTransactionIndex, err = d.u64("stale_transaction_index"); err != nil {
		return Multisig{}, err
	}
	if out.RentCollector, err = d.optionalPubkey("rent_collector"); err != nil {
		return Multisig{}, err
	}
	if out.Bump, err = d.u8("bump"); err != nil {
		return Multisig{}, err
	}
	memberCount, err := d.vecCount("members", maxMembers, 33)
	if err != nil {
		return Multisig{}, err
	}
	out.Members = make([]Member, memberCount)
	seenMembers := make(map[Pubkey]struct{}, memberCount)
	voteMembers := 0
	for i := range out.Members {
		if out.Members[i].Key, err = d.pubkey(fmt.Sprintf("members[%d].key", i)); err != nil {
			return Multisig{}, err
		}
		if out.Members[i].Permissions, err = d.u8(fmt.Sprintf("members[%d].permissions", i)); err != nil {
			return Multisig{}, err
		}
		if out.Members[i].Permissions&^(PermissionInitiate|PermissionVote|PermissionExecute) != 0 {
			return Multisig{}, fmt.Errorf("squadsproof: multisig: members[%d] has unknown permissions", i)
		}
		if _, exists := seenMembers[out.Members[i].Key]; exists {
			return Multisig{}, fmt.Errorf("squadsproof: multisig: duplicate member at index %d", i)
		}
		seenMembers[out.Members[i].Key] = struct{}{}
		if out.Members[i].CanVote() {
			voteMembers++
		}
	}
	if err := d.done("multisig"); err != nil {
		return Multisig{}, err
	}
	if out.Threshold == 0 || int(out.Threshold) > voteMembers {
		return Multisig{}, fmt.Errorf("squadsproof: multisig: threshold %d is invalid for %d voting members", out.Threshold, voteMembers)
	}
	if out.StaleTransactionIndex > out.TransactionIndex {
		return Multisig{}, fmt.Errorf("squadsproof: multisig: stale transaction index exceeds transaction index")
	}
	derived, bump, err := DeriveMultisigPDA(out.CreateKey, programID)
	if err != nil {
		return Multisig{}, err
	}
	if account.Address != derived || out.Bump != bump {
		return Multisig{}, fmt.Errorf("squadsproof: multisig: PDA or bump does not match create key")
	}
	return out, nil
}

// ParseProposal parses and binds a Squads v4 Proposal account to its expected
// program owner and canonical Proposal PDA.
func ParseProposal(account Account, programID Pubkey) (Proposal, error) {
	d, err := newDecoder(account, programID, proposalDiscriminator, "proposal")
	if err != nil {
		return Proposal{}, err
	}
	var out Proposal
	out.Address = account.Address
	if out.Multisig, err = d.pubkey("multisig"); err != nil {
		return Proposal{}, err
	}
	if out.TransactionIndex, err = d.u64("transaction_index"); err != nil {
		return Proposal{}, err
	}
	if out.Status, err = d.proposalStatus("status"); err != nil {
		return Proposal{}, err
	}
	if out.Bump, err = d.u8("bump"); err != nil {
		return Proposal{}, err
	}
	if out.Approved, err = d.pubkeyVec("approved", maxMembers); err != nil {
		return Proposal{}, err
	}
	if out.Rejected, err = d.pubkeyVec("rejected", maxMembers); err != nil {
		return Proposal{}, err
	}
	if out.Cancelled, err = d.pubkeyVec("cancelled", maxMembers); err != nil {
		return Proposal{}, err
	}
	if err := d.done("proposal"); err != nil {
		return Proposal{}, err
	}
	if err := requireDistinctPubkeys(out.Approved, "proposal approved"); err != nil {
		return Proposal{}, err
	}
	if err := requireDistinctPubkeys(out.Rejected, "proposal rejected"); err != nil {
		return Proposal{}, err
	}
	if err := requireDistinctPubkeys(out.Cancelled, "proposal cancelled"); err != nil {
		return Proposal{}, err
	}
	derived, bump, err := DeriveProposalPDA(out.Multisig, out.TransactionIndex, programID)
	if err != nil {
		return Proposal{}, err
	}
	if account.Address != derived || out.Bump != bump {
		return Proposal{}, fmt.Errorf("squadsproof: proposal: PDA or bump does not match multisig and transaction index")
	}
	return out, nil
}

// ParseVaultTransaction parses and binds a Squads v4 VaultTransaction account
// to its expected program owner, canonical transaction PDA, and canonical
// vault bump.
func ParseVaultTransaction(account Account, programID Pubkey) (VaultTransaction, error) {
	d, err := newDecoder(account, programID, vaultTransactionDiscriminator, "vault transaction")
	if err != nil {
		return VaultTransaction{}, err
	}
	var out VaultTransaction
	out.Address = account.Address
	if out.Multisig, err = d.pubkey("multisig"); err != nil {
		return VaultTransaction{}, err
	}
	if out.Creator, err = d.pubkey("creator"); err != nil {
		return VaultTransaction{}, err
	}
	if out.Index, err = d.u64("index"); err != nil {
		return VaultTransaction{}, err
	}
	if out.Bump, err = d.u8("bump"); err != nil {
		return VaultTransaction{}, err
	}
	if out.VaultIndex, err = d.u8("vault_index"); err != nil {
		return VaultTransaction{}, err
	}
	if out.VaultBump, err = d.u8("vault_bump"); err != nil {
		return VaultTransaction{}, err
	}
	if out.EphemeralSignerBumps, err = d.byteVec("ephemeral_signer_bumps", maxEphemeralSignerBumps); err != nil {
		return VaultTransaction{}, err
	}
	if out.Message, err = d.vaultTransactionMessage(); err != nil {
		return VaultTransaction{}, err
	}
	if err := d.done("vault transaction"); err != nil {
		return VaultTransaction{}, err
	}
	derived, bump, err := DeriveVaultTransactionPDA(out.Multisig, out.Index, programID)
	if err != nil {
		return VaultTransaction{}, err
	}
	if account.Address != derived || out.Bump != bump {
		return VaultTransaction{}, fmt.Errorf("squadsproof: vault transaction: PDA or bump does not match multisig and index")
	}
	_, vaultBump, err := DeriveVaultPDA(out.Multisig, out.VaultIndex, programID)
	if err != nil {
		return VaultTransaction{}, err
	}
	if out.VaultBump != vaultBump {
		return VaultTransaction{}, fmt.Errorf("squadsproof: vault transaction: vault bump does not match multisig and vault index")
	}
	return out, nil
}

// ValidateProposalApprovalSet proves that Proposal's approvals bind to this
// parsed Multisig's current member set and threshold.  It intentionally does
// not impose a status or staleness policy; the purpose-specific verifier must
// decide whether it needs an Executed proposal and whether a past execution is
// acceptable after a configuration revision.
func (m Multisig) ValidateProposalApprovalSet(proposal Proposal) error {
	if proposal.Multisig != m.Address {
		return fmt.Errorf("squadsproof: proposal does not belong to parsed multisig")
	}
	if proposal.TransactionIndex == 0 || proposal.TransactionIndex > m.TransactionIndex {
		return fmt.Errorf("squadsproof: proposal transaction index is outside multisig range")
	}
	voters := make(map[Pubkey]bool, len(m.Members))
	for _, member := range m.Members {
		voters[member.Key] = member.CanVote()
	}
	seen := make(map[Pubkey]struct{}, len(proposal.Approved))
	votes := 0
	for i, key := range proposal.Approved {
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("squadsproof: proposal approved has duplicate key at index %d", i)
		}
		seen[key] = struct{}{}
		canVote, member := voters[key]
		if !member || !canVote {
			return fmt.Errorf("squadsproof: proposal approved key at index %d is not a voting member", i)
		}
		votes++
	}
	if votes < int(m.Threshold) {
		return fmt.Errorf("squadsproof: proposal has %d approvals, below threshold %d", votes, m.Threshold)
	}
	return nil
}

// ValidateExecutedProposalTransaction binds an executed Proposal to the exact
// VaultTransaction it authorizes.  The caller still supplies the purpose
// policy (for example, an exact memo payload), but cannot accidentally compare
// a proposal's threshold proof with a transaction from another multisig or
// another transaction index.
func ValidateExecutedProposalTransaction(proposal Proposal, transaction VaultTransaction) error {
	if !proposal.Status.IsExecuted() {
		return fmt.Errorf("squadsproof: proposal is not executed")
	}
	if proposal.Multisig != transaction.Multisig {
		return fmt.Errorf("squadsproof: proposal and vault transaction have different multisigs")
	}
	if proposal.TransactionIndex != transaction.Index {
		return fmt.Errorf("squadsproof: proposal and vault transaction have different transaction indexes")
	}
	return nil
}

// MemoOnlyPayload returns the sole memo instruction payload after proving that
// this VaultTransaction cannot execute any other instruction.  It rejects
// address-table lookups and ephemeral signer bumps too, so the transaction has
// no hidden loaded accounts or extra signers beyond its one, account-free Memo
// invocation.
func (v VaultTransaction) MemoOnlyPayload(memoProgramID Pubkey) ([]byte, error) {
	if isZero(memoProgramID) {
		return nil, fmt.Errorf("squadsproof: memo program id is zero")
	}
	if len(v.EphemeralSignerBumps) != 0 {
		return nil, fmt.Errorf("squadsproof: memo-only transaction has ephemeral signer bumps")
	}
	if len(v.Message.AddressTableLookups) != 0 {
		return nil, fmt.Errorf("squadsproof: memo-only transaction has address table lookups")
	}
	if len(v.Message.Instructions) != 1 {
		return nil, fmt.Errorf("squadsproof: memo-only transaction has %d instructions", len(v.Message.Instructions))
	}
	instruction := v.Message.Instructions[0]
	if int(instruction.ProgramIDIndex) >= len(v.Message.AccountKeys) {
		return nil, fmt.Errorf("squadsproof: memo-only transaction has invalid program id index")
	}
	if v.Message.AccountKeys[instruction.ProgramIDIndex] != memoProgramID {
		return nil, fmt.Errorf("squadsproof: memo-only transaction does not invoke the expected Memo program")
	}
	if len(instruction.AccountIndexes) != 0 {
		return nil, fmt.Errorf("squadsproof: memo-only transaction passes %d account indexes", len(instruction.AccountIndexes))
	}
	return append([]byte(nil), instruction.Data...), nil
}

type decoder struct {
	data []byte
	off  int
}

func newDecoder(account Account, programID Pubkey, discriminator [8]byte, kind string) (*decoder, error) {
	if isZero(programID) {
		return nil, fmt.Errorf("squadsproof: %s: expected program id is zero", kind)
	}
	if isZero(account.Address) {
		return nil, fmt.Errorf("squadsproof: %s: account address is zero", kind)
	}
	if account.Owner != programID {
		return nil, fmt.Errorf("squadsproof: %s: owner does not match expected Squads program", kind)
	}
	if len(account.Data) < len(discriminator) || len(account.Data) > maxAccountDataBytes {
		return nil, fmt.Errorf("squadsproof: %s: invalid account data length %d", kind, len(account.Data))
	}
	if !bytes.Equal(account.Data[:len(discriminator)], discriminator[:]) {
		return nil, fmt.Errorf("squadsproof: %s: discriminator mismatch", kind)
	}
	return &decoder{data: account.Data, off: len(discriminator)}, nil
}

func (d *decoder) remaining() int { return len(d.data) - d.off }

func (d *decoder) take(n int, field string) ([]byte, error) {
	if n < 0 || n > d.remaining() {
		return nil, fmt.Errorf("squadsproof: %s: truncated (need %d bytes, have %d)", field, n, d.remaining())
	}
	part := d.data[d.off : d.off+n]
	d.off += n
	return part, nil
}

func (d *decoder) u8(field string) (uint8, error) {
	part, err := d.take(1, field)
	if err != nil {
		return 0, err
	}
	return part[0], nil
}

func (d *decoder) u16(field string) (uint16, error) {
	part, err := d.take(2, field)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(part), nil
}

func (d *decoder) u32(field string) (uint32, error) {
	part, err := d.take(4, field)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(part), nil
}

func (d *decoder) u64(field string) (uint64, error) {
	part, err := d.take(8, field)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(part), nil
}

func (d *decoder) i64(field string) (int64, error) {
	v, err := d.u64(field)
	return int64(v), err
}

func (d *decoder) pubkey(field string) (Pubkey, error) {
	part, err := d.take(32, field)
	if err != nil {
		return Pubkey{}, err
	}
	var key Pubkey
	copy(key[:], part)
	return key, nil
}

func (d *decoder) optionalPubkey(field string) (*Pubkey, error) {
	tag, err := d.u8(field + ".tag")
	if err != nil {
		return nil, err
	}
	switch tag {
	case 0:
		return nil, nil
	case 1:
		key, err := d.pubkey(field)
		if err != nil {
			return nil, err
		}
		return &key, nil
	default:
		return nil, fmt.Errorf("squadsproof: %s: invalid option tag %d", field, tag)
	}
}

func (d *decoder) vecCount(field string, maximum, minElementBytes int) (int, error) {
	count, err := d.u32(field + ".len")
	if err != nil {
		return 0, err
	}
	if uint64(count) > uint64(maximum) {
		return 0, fmt.Errorf("squadsproof: %s: length %d exceeds maximum %d", field, count, maximum)
	}
	if minElementBytes > 0 && uint64(count)*uint64(minElementBytes) > uint64(d.remaining()) {
		return 0, fmt.Errorf("squadsproof: %s: length %d cannot fit in remaining data", field, count)
	}
	return int(count), nil
}

func (d *decoder) byteVec(field string, maximum int) ([]byte, error) {
	count, err := d.vecCount(field, maximum, 1)
	if err != nil {
		return nil, err
	}
	part, err := d.take(count, field)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), part...), nil
}

func (d *decoder) pubkeyVec(field string, maximum int) ([]Pubkey, error) {
	count, err := d.vecCount(field, maximum, 32)
	if err != nil {
		return nil, err
	}
	keys := make([]Pubkey, count)
	for i := range keys {
		if keys[i], err = d.pubkey(fmt.Sprintf("%s[%d]", field, i)); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

func (d *decoder) proposalStatus(field string) (ProposalStatus, error) {
	tag, err := d.u8(field + ".tag")
	if err != nil {
		return ProposalStatus{}, err
	}
	if tag > uint8(ProposalStatusCancelled) {
		return ProposalStatus{}, fmt.Errorf("squadsproof: %s: unknown proposal status tag %d", field, tag)
	}
	out := ProposalStatus{Kind: ProposalStatusKind(tag)}
	if out.Kind == ProposalStatusExecuting {
		return out, nil
	}
	if out.Timestamp, err = d.i64(field + ".timestamp"); err != nil {
		return ProposalStatus{}, err
	}
	out.TimestampSet = true
	return out, nil
}

func (d *decoder) vaultTransactionMessage() (VaultTransactionMessage, error) {
	var out VaultTransactionMessage
	var err error
	if out.NumSigners, err = d.u8("message.num_signers"); err != nil {
		return VaultTransactionMessage{}, err
	}
	if out.NumWritableSigners, err = d.u8("message.num_writable_signers"); err != nil {
		return VaultTransactionMessage{}, err
	}
	if out.NumWritableNonSigners, err = d.u8("message.num_writable_non_signers"); err != nil {
		return VaultTransactionMessage{}, err
	}
	keyCount, err := d.vecCount("message.account_keys", maxAccountKeys, 32)
	if err != nil {
		return VaultTransactionMessage{}, err
	}
	out.AccountKeys = make([]Pubkey, keyCount)
	for i := range out.AccountKeys {
		if out.AccountKeys[i], err = d.pubkey(fmt.Sprintf("message.account_keys[%d]", i)); err != nil {
			return VaultTransactionMessage{}, err
		}
	}
	if err := requireDistinctPubkeys(out.AccountKeys, "message account keys"); err != nil {
		return VaultTransactionMessage{}, err
	}
	if int(out.NumSigners) > len(out.AccountKeys) || out.NumWritableSigners > out.NumSigners || int(out.NumWritableNonSigners) > len(out.AccountKeys)-int(out.NumSigners) {
		return VaultTransactionMessage{}, fmt.Errorf("squadsproof: message: invalid signer/writable header")
	}
	instructionCount, err := d.vecCount("message.instructions", maxInstructions, 9)
	if err != nil {
		return VaultTransactionMessage{}, err
	}
	out.Instructions = make([]CompiledInstruction, instructionCount)
	for i := range out.Instructions {
		instruction := &out.Instructions[i]
		if instruction.ProgramIDIndex, err = d.u8(fmt.Sprintf("message.instructions[%d].program_id_index", i)); err != nil {
			return VaultTransactionMessage{}, err
		}
		if instruction.AccountIndexes, err = d.byteVec(fmt.Sprintf("message.instructions[%d].account_indexes", i), maxInstructionAccountBytes); err != nil {
			return VaultTransactionMessage{}, err
		}
		if instruction.Data, err = d.byteVec(fmt.Sprintf("message.instructions[%d].data", i), maxInstructionDataBytes); err != nil {
			return VaultTransactionMessage{}, err
		}
		if int(instruction.ProgramIDIndex) >= len(out.AccountKeys) {
			return VaultTransactionMessage{}, fmt.Errorf("squadsproof: message.instructions[%d]: program id index %d out of range", i, instruction.ProgramIDIndex)
		}
		for j, index := range instruction.AccountIndexes {
			if int(index) >= len(out.AccountKeys) {
				return VaultTransactionMessage{}, fmt.Errorf("squadsproof: message.instructions[%d].account_indexes[%d]: index %d out of range", i, j, index)
			}
		}
	}
	lookupCount, err := d.vecCount("message.address_table_lookups", maxAddressTableLookups, 40)
	if err != nil {
		return VaultTransactionMessage{}, err
	}
	out.AddressTableLookups = make([]AddressTableLookup, lookupCount)
	for i := range out.AddressTableLookups {
		lookup := &out.AddressTableLookups[i]
		if lookup.AccountKey, err = d.pubkey(fmt.Sprintf("message.address_table_lookups[%d].account_key", i)); err != nil {
			return VaultTransactionMessage{}, err
		}
		if lookup.WritableIndexes, err = d.byteVec(fmt.Sprintf("message.address_table_lookups[%d].writable_indexes", i), maxAddressTableIndexBytes); err != nil {
			return VaultTransactionMessage{}, err
		}
		if lookup.ReadonlyIndexes, err = d.byteVec(fmt.Sprintf("message.address_table_lookups[%d].readonly_indexes", i), maxAddressTableIndexBytes); err != nil {
			return VaultTransactionMessage{}, err
		}
	}
	return out, nil
}

func (d *decoder) done(kind string) error {
	if d.remaining() != 0 {
		return fmt.Errorf("squadsproof: %s: trailing %d bytes", kind, d.remaining())
	}
	return nil
}

func requireDistinctPubkeys(keys []Pubkey, field string) error {
	seen := make(map[Pubkey]struct{}, len(keys))
	for i, key := range keys {
		if _, exists := seen[key]; exists {
			return fmt.Errorf("squadsproof: %s: duplicate key at index %d", field, i)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func isZero(key Pubkey) bool { return key == Pubkey{} }
