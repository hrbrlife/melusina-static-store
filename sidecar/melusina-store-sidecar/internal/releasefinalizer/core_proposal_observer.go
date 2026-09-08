package releasefinalizer

// The production observer owns one default-Bazaar authority and performs only
// finalized account reads. It is not a transaction executor or a caller-selected
// RPC relay. Layouts and instruction bytes follow the canonical release tool's
// release/{instruction,account,crypto}.go and the pinned Squads v4 parser.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/squadsproof"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	coreRegistryProgram          = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"
	coreReleaseMaster            = "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe"
	coreReleaseMultisig          = "4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V"
	coreReleaseVault             = "3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3"
	coreReleasePublisher         = "ARX39MQQR1c7cT8L9ARbeg7AWw975gPGr9EE9oygKv1P"
	registerProposalDigestDomain = "bazaar-control-register-release-proposal-v1\x00"
)

// CoreProposalObserverConfig is service-owned public configuration. The four
// original members must be independently provisioned; they are never learned
// from a job, descriptor, or the same untrusted proposal being verified.
type CoreProposalObserverConfig struct {
	RPCURL  string
	Members [4]string
}

type coreObserverPins struct {
	registry, master, multisig, vault, publisher squadsproof.Pubkey
	members                                      [4]squadsproof.Pubkey
}

type CoreProposalObserver struct {
	pins     coreObserverPins
	endpoint string
	client   *http.Client
	now      func() time.Time
}

func NewCoreProposalObserver(config CoreProposalObserverConfig) (*CoreProposalObserver, error) {
	client, err := newCoreObserverHTTPClient(config.RPCURL)
	if err != nil {
		return nil, err
	}
	pins := coreObserverPins{registry: observerKey(coreRegistryProgram), master: observerKey(coreReleaseMaster), multisig: observerKey(coreReleaseMultisig), vault: observerKey(coreReleaseVault), publisher: observerKey(coreReleasePublisher)}
	seen := make(map[squadsproof.Pubkey]bool)
	for index, text := range config.Members {
		key, err := squadsproof.DecodePubkey(text)
		if err != nil || key == (squadsproof.Pubkey{}) || seen[key] {
			return nil, errors.New("Core observer requires four distinct independently pinned members")
		}
		pins.members[index], seen[key] = key, true
	}
	return &CoreProposalObserver{pins: pins, endpoint: config.RPCURL, client: client, now: time.Now}, nil
}

func observerKey(text string) squadsproof.Pubkey {
	key, err := squadsproof.DecodePubkey(text)
	if err != nil {
		panic(err)
	}
	return key
}

// RegisterProposalDigest is the exact preparation/browser/observer contract.
// Reference is the canonical VaultTransaction PDA. Its immutable data, owner
// program and address are hashed, never mutable proposal vote/status bytes or
// a JSON serialization. The preparation result separately binds stage, Store,
// source/candidate, app/release and policy/grant into the human authorization.
func RegisterProposalDigest(account squadsproof.Account) (string, error) {
	if _, err := squadsproof.ParseVaultTransaction(account, squadsproof.DefaultProgramID); err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(registerProposalDigestDomain))
	h.Write(account.Owner[:])
	h.Write(account.Address[:])
	h.Write(account.Data)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (o *CoreProposalObserver) ObserveExecution(ctx context.Context, want ProposalExpectation) (ProposalObservation, error) {
	var zero ProposalObservation
	if o == nil || o.client == nil || o.now == nil || len(want.AppID) != 52 || !appID(want.AppID) || strings.Contains(want.AppID, "-") || !safeText(want.Version, 32) || !lowerHex(want.Digest, 64) || !lowerHex(want.AppHash, 64) || !lowerHex(want.Release, 64) || !lowerHex(want.StageID, 64) {
		return zero, errors.New("Core observer expectation is incomplete")
	}
	address, err := squadsproof.DecodePubkey(want.Reference)
	if err != nil {
		return zero, errors.New("proposal reference must be its canonical VaultTransaction PDA")
	}
	initial, slot, err := o.readAccounts(ctx, []squadsproof.Pubkey{address}, 0)
	if err != nil {
		return zero, err
	}
	transaction, err := squadsproof.ParseVaultTransaction(initial[0], squadsproof.DefaultProgramID)
	if err != nil {
		return zero, err
	}
	register, err := o.verifyRegister(transaction, initial[0], want)
	if err != nil {
		return zero, err
	}
	proposalAddress, _, err := squadsproof.DeriveProposalPDA(o.pins.multisig, transaction.Index, squadsproof.DefaultProgramID)
	if err != nil {
		return zero, err
	}
	cohort, finalSlot, err := o.readAccounts(ctx, []squadsproof.Pubkey{address, o.pins.multisig, proposalAddress, register.entry}, slot)
	if err != nil {
		return zero, err
	}
	if cohort[0].Owner != initial[0].Owner || !bytes.Equal(cohort[0].Data, initial[0].Data) {
		return zero, errors.New("immutable proposal changed between finalized reads")
	}
	multisig, err := squadsproof.ParseMultisig(cohort[1], squadsproof.DefaultProgramID)
	if err != nil {
		return zero, err
	}
	if err := o.verifyCore(multisig, transaction.Creator); err != nil {
		return zero, err
	}
	proposal, err := squadsproof.ParseProposal(cohort[2], squadsproof.DefaultProgramID)
	if err != nil {
		return zero, err
	}
	if proposal.Multisig != o.pins.multisig || proposal.TransactionIndex != transaction.Index || transaction.Index > multisig.TransactionIndex {
		return zero, errors.New("proposal is outside the fixed Core transaction scope")
	}
	observation := ProposalObservation{Reference: want.Reference, Digest: want.Digest, AppHash: want.AppHash, Release: want.Release, StageID: want.StageID, VerifiedSlot: finalSlot}
	if !proposal.Status.IsExecuted() {
		switch proposal.Status.Kind {
		case squadsproof.ProposalStatusDraft, squadsproof.ProposalStatusActive, squadsproof.ProposalStatusApproved, squadsproof.ProposalStatusExecuting:
			if transaction.Index <= multisig.StaleTransactionIndex {
				return zero, errors.New("pending proposal was invalidated by a Core configuration change")
			}
			observation.State = ProposalPending
			return observation, nil
		default:
			return zero, errors.New("proposal was rejected or cancelled")
		}
	}
	if err := squadsproof.ValidateExecutedProposalTransaction(proposal, transaction); err != nil {
		return zero, err
	}
	if err := multisig.ValidateProposalApprovalSet(proposal); err != nil {
		return zero, err
	}
	if len(proposal.Rejected) != 0 || len(proposal.Cancelled) != 0 || !proposal.Status.TimestampSet || proposal.Status.Timestamp <= 0 || proposal.Status.Timestamp > o.now().UTC().Add(2*time.Minute).Unix() {
		return zero, errors.New("executed proposal has inconsistent votes or time")
	}
	registeredAt, err := o.verifyActiveRelease(cohort[3], register)
	if err != nil {
		return zero, err
	}
	if registeredAt != proposal.Status.Timestamp {
		return zero, errors.New("release registration time differs from the proposal execution")
	}
	observation.State, observation.ExecutedAt = ProposalExecuted, time.Unix(proposal.Status.Timestamp, 0).UTC()
	observation.RegisteredAt, observation.ReleaseEntryPDA = time.Unix(registeredAt, 0).UTC(), primitives.EncodeBase58(register.entry[:])
	observation.AuthorSignatureBase64 = base64.StdEncoding.EncodeToString(register.signature[:])
	observation.MasterNftMint, observation.PublisherSquadsVault = primitives.EncodeBase58(o.pins.master[:]), primitives.EncodeBase58(o.pins.vault[:])
	observation.SquadsMultisig, observation.Threshold, observation.MemberCount = primitives.EncodeBase58(multisig.Address[:]), int(multisig.Threshold), len(multisig.Members)
	return observation, nil
}

func (o *CoreProposalObserver) verifyCore(multisig squadsproof.Multisig, creator squadsproof.Pubkey) error {
	if multisig.Address != o.pins.multisig || multisig.Threshold != 3 || len(multisig.Members) != 4 {
		return errors.New("live governance is not the independently configured Core 3-of-4")
	}
	seen := make(map[squadsproof.Pubkey]bool)
	for _, key := range o.pins.members {
		seen[key] = true
	}
	creatorOK := false
	for _, member := range multisig.Members {
		if !seen[member.Key] || !member.CanVote() {
			return errors.New("live Core member scope changed")
		}
		if member.Key == creator && member.Permissions&squadsproof.PermissionInitiate != 0 {
			creatorOK = true
		}
	}
	if !creatorOK {
		return errors.New("proposal creator lacks the pinned Core initiation scope")
	}
	return nil
}

type observedRegister struct {
	entry     squadsproof.Pubkey
	entryBump uint8
	data      []byte
	signature [64]byte
}

func (o *CoreProposalObserver) verifyRegister(transaction squadsproof.VaultTransaction, account squadsproof.Account, want ProposalExpectation) (observedRegister, error) {
	var result observedRegister
	digest, err := RegisterProposalDigest(account)
	if err != nil || digest != want.Digest || transaction.Multisig != o.pins.multisig || transaction.VaultIndex != 0 || len(transaction.EphemeralSignerBumps) != 0 {
		return result, errors.New("stored proposal does not bind the approved Core digest")
	}
	message := transaction.Message
	if message.NumSigners != 1 || message.NumWritableSigners != 1 || message.NumWritableNonSigners != 1 || len(message.AccountKeys) != 8 || len(message.Instructions) != 1 || len(message.AddressTableLookups) != 0 || message.AccountKeys[0] != o.pins.vault {
		return result, errors.New("release proposal has an unsupported instruction or privilege shape")
	}
	appHash, _ := hex.DecodeString(want.AppHash)
	var appHash32 [32]byte
	copy(appHash32[:], appHash)
	result.entry, result.entryBump, err = primitives.DeriveReleaseV2(o.pins.master, appHash32, o.pins.registry)
	if err != nil || message.AccountKeys[1] != result.entry {
		return result, errors.New("proposal release entry PDA does not bind the approved app hash")
	}
	token := observerKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
	ata, _, err := primitives.FindProgramAddress([][]byte{o.pins.vault[:], token[:], o.pins.master[:]}, observerKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"), nil)
	if err != nil {
		return result, err
	}
	wantAccounts := []squadsproof.Pubkey{result.entry, o.pins.vault, o.pins.master, ata, observerKey("Sysvar1nstructions1111111111111111111111111"), observerKey("11111111111111111111111111111111"), token}
	instruction := message.Instructions[0]
	if message.AccountKeys[instruction.ProgramIDIndex] != o.pins.registry || len(instruction.AccountIndexes) != len(wantAccounts) {
		return result, errors.New("proposal does not contain exactly register_release_entry")
	}
	for index, expected := range wantAccounts {
		if message.AccountKeys[instruction.AccountIndexes[index]] != expected {
			return result, errors.New("register_release_entry accounts differ from the canonical instruction")
		}
	}
	data := instruction.Data
	discriminator := sha256.Sum256([]byte("global:register_release_entry"))
	if len(data) < 268 || !bytes.Equal(data[:8], discriminator[:8]) {
		return result, errors.New("register_release_entry data is malformed")
	}
	versionLength := int(binary.LittleEndian.Uint32(data[104:108]))
	if versionLength < 1 || versionLength > 32 || len(data) != 268+versionLength || string(data[108:108+versionLength]) != want.Version {
		return result, errors.New("register_release_entry version or data length differs")
	}
	appIDHash := sha256.Sum256([]byte(want.AppID))
	releaseHash, _ := hex.DecodeString(want.Release)
	tail := data[108+versionLength:]
	if !bytes.Equal(data[8:40], appHash) || !bytes.Equal(data[40:72], appIDHash[:]) || !bytes.Equal(data[72:104], releaseHash) || !bytes.Equal(tail[:32], o.pins.vault[:]) || !bytes.Equal(tail[32:64], o.pins.publisher[:]) {
		return result, errors.New("register_release_entry author, app or release scope differs")
	}
	h := sha256.New()
	for _, part := range [][]byte{[]byte("melusina-release-entry-v1"), o.pins.master[:], appHash, appIDHash[:], releaseHash, []byte(want.Version), o.pins.vault[:], o.pins.publisher[:]} {
		h.Write(part)
	}
	payloadHash := h.Sum(nil)
	if !bytes.Equal(tail[128:], payloadHash) || !ed25519.Verify(ed25519.PublicKey(o.pins.publisher[:]), payloadHash, tail[64:128]) {
		return result, errors.New("register_release_entry author signature does not verify")
	}
	copy(result.signature[:], tail[64:128])
	result.data = append([]byte(nil), data...)
	return result, nil
}

func (o *CoreProposalObserver) verifyActiveRelease(account squadsproof.Account, register observedRegister) (int64, error) {
	data := account.Data
	discriminator := sha256.Sum256([]byte("account:ReleaseEntry"))
	// Anchor reserves MAX_RELEASE_VERSION_LEN=32 and an eight-byte Option
	// payload. Accept only the exact serialized record or that exact allocation
	// with zero padding; unknown account extensions remain refusals.
	const allocatedReleaseBytes = 8 + 32*4 + 4 + 32 + 32*2 + 64 + 32 + 32 + 8 + 1 + 9 + 1
	prefixEnd := 40 + len(register.data) - 8
	actualSize := prefixEnd + 32 + 8 + 1 + 1 + 1
	if account.Address != register.entry || account.Owner != o.pins.registry || len(data) < actualSize || (len(data) != actualSize && len(data) != allocatedReleaseBytes) || !bytes.Equal(data[:8], discriminator[:8]) || !bytes.Equal(data[8:40], o.pins.master[:]) || !bytes.Equal(data[40:prefixEnd], register.data[8:]) || !bytes.Equal(data[prefixEnd:prefixEnd+32], o.pins.vault[:]) {
		return 0, errors.New("Active ReleaseEntry does not match the exact registered instruction")
	}
	registeredAt := int64(binary.LittleEndian.Uint64(data[prefixEnd+32 : prefixEnd+40]))
	if registeredAt <= 0 || data[prefixEnd+40] != 0 || data[prefixEnd+41] != 0 || data[prefixEnd+42] != register.entryBump {
		return 0, errors.New("ReleaseEntry is not the exact active unrecalled registration")
	}
	for _, value := range data[actualSize:] {
		if value != 0 {
			return 0, fmt.Errorf("ReleaseEntry has nonzero unrecognized allocation bytes")
		}
	}
	return registeredAt, nil
}

var _ ProposalObserver = (*CoreProposalObserver)(nil)
