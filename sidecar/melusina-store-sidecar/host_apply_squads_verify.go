package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/squadsproof"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

var hostApplyComputeBudgetProgramID = mustHostApplyProofPubkey("ComputeBudget111111111111111111111111111111")

func mustHostApplyProofPubkey(raw string) squadsproof.Pubkey {
	key, err := squadsproof.DecodePubkey(raw)
	if err != nil {
		panic(err)
	}
	return key
}

func decodeHostApplyBase58(raw string, wantLen int, label string) ([]byte, error) {
	decoded, err := primitives.DecodeBase58(raw)
	if err != nil || len(decoded) != wantLen || primitives.EncodeBase58(decoded) != raw {
		return nil, fmt.Errorf("%s is not canonical base58", label)
	}
	return decoded, nil
}

func hostApplyTransactionAccountFlags(header hostApplyTxHeader, index, count int) (signer, writable bool, err error) {
	required := int(header.NumRequiredSignatures)
	readonlySigned := int(header.NumReadonlySignedAccounts)
	readonlyUnsigned := int(header.NumReadonlyUnsignedAccounts)
	if count == 0 || required == 0 || required > count || readonlySigned > required || readonlyUnsigned > count-required || index < 0 || index >= count {
		return false, false, errors.New("invalid finalized Squads execution message header")
	}
	if index < required {
		return true, index < required-readonlySigned, nil
	}
	return false, index < count-readonlyUnsigned, nil
}

func hostApplyDecodeTxKeys(keys []string) ([]squadsproof.Pubkey, error) {
	if len(keys) < 6 || len(keys) > 256 {
		return nil, errors.New("finalized Squads execution has an invalid static key count")
	}
	decoded := make([]squadsproof.Pubkey, len(keys))
	seen := make(map[squadsproof.Pubkey]struct{}, len(keys))
	for i, raw := range keys {
		key, err := squadsproof.DecodePubkey(raw)
		if err != nil {
			return nil, fmt.Errorf("finalized Squads execution key %d: %w", i, err)
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("finalized Squads execution duplicates static key %d", i)
		}
		seen[key] = struct{}{}
		decoded[i] = key
	}
	return decoded, nil
}

func hostApplyMarkInstructionUsed(used map[int]struct{}, ix hostApplyCompiledInstruction, keyCount int) error {
	if int(ix.ProgramIDIndex) >= keyCount {
		return errors.New("finalized Squads execution has an invalid program key index")
	}
	used[int(ix.ProgramIDIndex)] = struct{}{}
	for _, account := range ix.Accounts {
		if int(account) >= keyCount {
			return errors.New("finalized Squads execution has an invalid instruction account index")
		}
		used[int(account)] = struct{}{}
	}
	return nil
}

type hostApplyExecutionTranscript struct {
	Proposal            squadsproof.Pubkey
	VaultTransaction    squadsproof.Pubkey
	ExecutingMember     squadsproof.Pubkey
	ExecuteOuterIndex   int
	VaultStaticKeyIndex uint8
}

func verifyHostApplyExecutionTranscript(plan hostApplyPlan, tx hostApplyFinalizedTransaction) (hostApplyExecutionTranscript, error) {
	var zero hostApplyExecutionTranscript
	if tx.Failed || tx.Slot == 0 || len(tx.Signatures) != 1 || tx.Signatures[0] != tx.Signature {
		return zero, errors.New("finalized Squads execution transaction failed or has an invalid signature transcript")
	}
	if _, err := decodeHostApplyBase58(tx.Signature, 64, "execution signature"); err != nil {
		return zero, err
	}
	if tx.Header.NumRequiredSignatures != 1 || tx.Header.NumReadonlySignedAccounts != 0 || tx.AddressTableLookups != 0 {
		return zero, errors.New("finalized Squads execution is not the exact one-member no-lookup form")
	}
	keys, err := hostApplyDecodeTxKeys(tx.AccountKeys)
	if err != nil {
		return zero, err
	}
	program, err := squadsproof.DecodePubkey(plan.SquadsProgramID)
	if err != nil {
		return zero, fmt.Errorf("plan Squads program: %w", err)
	}
	multisig, err := squadsproof.DecodePubkey(plan.SquadsMultisig)
	if err != nil {
		return zero, fmt.Errorf("plan Squads multisig: %w", err)
	}
	vault, err := squadsproof.DecodePubkey(plan.SquadsVault)
	if err != nil {
		return zero, fmt.Errorf("plan Squads vault: %w", err)
	}
	if keys[0] == (squadsproof.Pubkey{}) {
		return zero, errors.New("finalized Squads execution has an empty fee payer")
	}
	used := map[int]struct{}{0: {}}
	var execute *hostApplyCompiledInstruction
	executeIndex := -1
	for i := range tx.Instructions {
		ix := &tx.Instructions[i]
		if err := hostApplyMarkInstructionUsed(used, *ix, len(keys)); err != nil {
			return zero, err
		}
		ixProgram := keys[ix.ProgramIDIndex]
		if ixProgram == hostApplyComputeBudgetProgramID {
			if len(ix.Accounts) != 0 {
				return zero, errors.New("compute budget instruction unexpectedly has accounts")
			}
			continue
		}
		if ixProgram != program || execute != nil {
			return zero, errors.New("finalized approval may contain only compute budget instructions and one Squads execute")
		}
		data, err := decodeHostApplyBase58(ix.Data, 8, "Squads execute instruction data")
		if err != nil || !bytesEqual(data, []byte{194, 8, 161, 87, 153, 164, 25, 171}) {
			return zero, errors.New("Squads instruction is not vaultTransactionExecute")
		}
		execute = ix
		executeIndex = i
	}
	if execute == nil || len(execute.Accounts) != 6 {
		return zero, errors.New("finalized Squads execution lacks the exact six-account execute transcript")
	}
	indexes := execute.Accounts
	expected := []struct {
		key      squadsproof.Pubkey
		signer   bool
		writable bool
	}{
		{key: multisig},
		{writable: true},
		{},
		{signer: true, writable: true},
		{key: vault, writable: true},
		{key: squadsproof.DefaultMemoProgramID},
	}
	for i, index := range indexes {
		if int(index) >= len(keys) {
			return zero, errors.New("finalized Squads execute account index is invalid")
		}
		key := keys[index]
		if i == 1 || i == 2 || i == 3 {
			// Proposal, VaultTransaction, and member are bound below after the
			// account cohort has been parsed; their exact flags are still fixed.
		} else if key != expected[i].key {
			return zero, errors.New("finalized Squads execute account order does not match the approved plan")
		}
		signer, writable, err := hostApplyTransactionAccountFlags(tx.Header, int(index), len(keys))
		if err != nil || signer != expected[i].signer || writable != expected[i].writable {
			return zero, errors.New("finalized Squads execute account flags do not match the exact transcript")
		}
	}
	// The executing member must be the one writable signer/fee payer, and the
	// complete static key list must be consumed by the admitted outer transcript.
	if keys[indexes[3]] != keys[0] {
		return zero, errors.New("finalized Squads execute member is not the sole fee payer signer")
	}
	if len(used) != len(keys) {
		return zero, errors.New("finalized Squads execution has unused static account keys")
	}
	if len(tx.InnerInstructions) != 1 || tx.InnerInstructions[0].Index != executeIndex || len(tx.InnerInstructions[0].Instructions) != 1 {
		return zero, errors.New("finalized Squads execution must have exactly one memo inner instruction")
	}
	inner := tx.InnerInstructions[0].Instructions[0]
	if int(inner.ProgramIDIndex) >= len(keys) || keys[inner.ProgramIDIndex] != squadsproof.DefaultMemoProgramID ||
		len(inner.Accounts) != 1 || inner.Accounts[0] != indexes[4] {
		return zero, errors.New("finalized Squads execution inner instruction is not the canonical vault memo")
	}
	payload, err := decodeHostApplyBase58(inner.Data, len(plan.Memo()), "Squads memo data")
	if err != nil || string(payload) != plan.Memo() {
		return zero, errors.New("finalized Squads execution inner memo does not bind the host-apply plan")
	}
	return hostApplyExecutionTranscript{
		Proposal: keys[indexes[1]], VaultTransaction: keys[indexes[2]], ExecutingMember: keys[indexes[3]],
		ExecuteOuterIndex: executeIndex, VaultStaticKeyIndex: indexes[4],
	}, nil
}

func hostApplyFrozenMember(plan hostApplyPlan, key squadsproof.Pubkey) (hostApplySquadsMember, bool) {
	for _, member := range plan.SquadsMembers {
		if member.Pubkey == key.Base58() {
			return member, true
		}
	}
	return hostApplySquadsMember{}, false
}

func hostApplyCurrentMember(multisig squadsproof.Multisig, key squadsproof.Pubkey) (squadsproof.Member, bool) {
	for _, member := range multisig.Members {
		if member.Key == key {
			return member, true
		}
	}
	return squadsproof.Member{}, false
}

func verifyHostApplyFrozenApprovals(plan hostApplyPlan, proposal squadsproof.Proposal) error {
	seen := make(map[squadsproof.Pubkey]struct{}, len(proposal.Approved))
	votes := 0
	for i, key := range proposal.Approved {
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("finalized Squads proposal repeats approver %d", i)
		}
		seen[key] = struct{}{}
		member, ok := hostApplyFrozenMember(plan, key)
		if !ok || member.Permissions&squadsproof.PermissionVote == 0 {
			return fmt.Errorf("finalized Squads proposal approver %d is not a frozen vote-capable member", i)
		}
		votes++
	}
	if votes < int(plan.SquadsThreshold) {
		return errors.New("finalized Squads proposal has fewer frozen approvals than the plan threshold")
	}
	return nil
}

// verifyHostApplySquadsProof observes and validates a finalized exact Squads
// execution. It is called before receipt issuance and again on every receipt
// retrieval, so policy/operator/cascade or Squads-config revocation cannot be
// bypassed by retaining a previously downloaded short-lived receipt.
func verifyHostApplySquadsProof(ctx context.Context, cr chainReader, plan hostApplyPlan, signature string, now time.Time) (hostApplySquadsProof, error) {
	var zero hostApplySquadsProof
	if err := plan.Validate(now); err != nil {
		return zero, err
	}
	if _, err := decodeHostApplyBase58(signature, 64, "execution signature"); err != nil {
		return zero, err
	}
	reader, ok := cr.(hostApplySquadsProofReader)
	if !ok {
		return zero, errors.New("chain reader lacks finalized Squads proof support")
	}
	tx, err := reader.fetchFinalizedHostApplyTransaction(ctx, signature)
	if err != nil {
		return zero, err
	}
	transcript, err := verifyHostApplyExecutionTranscript(plan, tx)
	if err != nil {
		return zero, err
	}
	cohort, err := reader.fetchFinalizedHostApplyAccounts(ctx, []string{
		plan.SquadsMultisig, transcript.Proposal.Base58(), transcript.VaultTransaction.Base58(),
	}, tx.Slot)
	if err != nil || cohort.ContextSlot < tx.Slot || len(cohort.Accounts) != 3 {
		return zero, fmt.Errorf("fetch finalized Squads proof account cohort: %w", err)
	}
	program, err := squadsproof.DecodePubkey(plan.SquadsProgramID)
	if err != nil {
		return zero, err
	}
	toAccount := func(raw hostApplyFinalizedAccount) (squadsproof.Account, error) {
		address, err := squadsproof.DecodePubkey(raw.Address)
		if err != nil {
			return squadsproof.Account{}, err
		}
		owner, err := squadsproof.DecodePubkey(raw.Owner)
		if err != nil {
			return squadsproof.Account{}, err
		}
		return squadsproof.Account{Address: address, Owner: owner, Data: raw.Data}, nil
	}
	multisigAccount, err := toAccount(cohort.Accounts[0])
	if err != nil {
		return zero, err
	}
	proposalAccount, err := toAccount(cohort.Accounts[1])
	if err != nil {
		return zero, err
	}
	vaultTransactionAccount, err := toAccount(cohort.Accounts[2])
	if err != nil {
		return zero, err
	}
	multisig, err := squadsproof.ParseMultisig(multisigAccount, program)
	if err != nil {
		return zero, err
	}
	proposal, err := squadsproof.ParseProposal(proposalAccount, program)
	if err != nil {
		return zero, err
	}
	vaultTransaction, err := squadsproof.ParseVaultTransaction(vaultTransactionAccount, program)
	if err != nil {
		return zero, err
	}
	if multisig.Address.Base58() != plan.SquadsMultisig || hostApplySquadsStableConfigSHA256(multisig) != plan.SquadsStableConfigSHA256 ||
		multisig.Threshold != plan.SquadsThreshold || multisig.TransactionIndex < proposal.TransactionIndex ||
		proposal.TransactionIndex <= plan.SquadsTransactionIndexFloor || vaultTransaction.VaultIndex != 0 {
		return zero, errors.New("finalized Squads accounts no longer match the immutable host-apply plan")
	}
	if err := multisig.ValidateProposalApprovalSet(proposal); err != nil {
		return zero, err
	}
	if err := verifyHostApplyFrozenApprovals(plan, proposal); err != nil {
		return zero, err
	}
	if err := squadsproof.ValidateExecutedProposalTransaction(proposal, vaultTransaction); err != nil {
		return zero, err
	}
	derivedVault, _, err := squadsproof.DeriveVaultPDA(multisig.Address, 0, program)
	if err != nil || derivedVault.Base58() != plan.SquadsVault {
		return zero, errors.New("finalized Squads vault does not match the target license custody")
	}
	if payload, err := vaultTransaction.MemoOnlyPayload(program, squadsproof.DefaultMemoProgramID); err != nil || string(payload) != plan.Memo() {
		return zero, errors.New("finalized Squads vault transaction is not the exact host-apply memo")
	}
	executor, currentExecutor := hostApplyCurrentMember(multisig, transcript.ExecutingMember)
	frozenExecutor, frozenExecutorOK := hostApplyFrozenMember(plan, transcript.ExecutingMember)
	if !currentExecutor || !frozenExecutorOK || executor.Permissions&squadsproof.PermissionExecute == 0 || frozenExecutor.Permissions&squadsproof.PermissionExecute == 0 {
		return zero, errors.New("finalized Squads execution signer is not current and frozen execute-capable")
	}
	creator, currentCreator := hostApplyCurrentMember(multisig, vaultTransaction.Creator)
	frozenCreator, frozenCreatorOK := hostApplyFrozenMember(plan, vaultTransaction.Creator)
	if !currentCreator || !frozenCreatorOK || creator.Permissions&squadsproof.PermissionInitiate == 0 || frozenCreator.Permissions&squadsproof.PermissionInitiate == 0 {
		return zero, errors.New("finalized Squads vault transaction creator is not current and frozen initiate-capable")
	}
	approvedBy := make([]string, len(proposal.Approved))
	for i, approver := range proposal.Approved {
		approvedBy[i] = approver.Base58()
	}
	memoHash := sha256.Sum256([]byte(plan.Memo()))
	proof := hostApplySquadsProof{
		Schema: hostApplySquadsProofSchema, PlanDigest: plan.Digest(), ExecutionSignature: signature,
		TransactionIndex: proposal.TransactionIndex, Slot: tx.Slot, ProposalPDA: proposal.Address.Base58(),
		VaultTransactionPDA: vaultTransaction.Address.Base58(), ExecutedBy: transcript.ExecutingMember.Base58(),
		ApprovedBy: approvedBy, Threshold: multisig.Threshold, MemoSHA256: hex.EncodeToString(memoHash[:]),
		VerifiedAt: now.UTC().Truncate(time.Second),
	}
	if err := proof.Validate(plan, now); err != nil {
		return zero, err
	}
	return proof, nil
}
