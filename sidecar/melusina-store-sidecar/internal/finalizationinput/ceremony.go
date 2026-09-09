package finalizationinput

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/squadsproof"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// CeremonyState is the complete public author state emitted by the canonical
// governed provider. Its original bytes stay in the reviewed vault input. The
// dry-run label describes author preparation, never proof of chain execution.
type CeremonyState struct {
	Schema                 string              `json:"$schema"`
	Status                 string              `json:"status"`
	DryRun                 bool                `json:"dryRun"`
	AppHash                string              `json:"appHash"`
	ReleaseHash            string              `json:"releaseHash"`
	ReleaseNonce           string              `json:"releaseNonce"`
	Version                string              `json:"version"`
	AppID                  string              `json:"appId"`
	AppIDHash              string              `json:"appIdHash"`
	LicenseMint            string              `json:"licenseMint"`
	MasterNftMint          string              `json:"masterNftMint"`
	ProgramID              string              `json:"programId"`
	SquadsProgramID        string              `json:"squadsProgramId"`
	MultisigPDA            string              `json:"multisigPda"`
	LicenseSquadsVault     string              `json:"licenseSquadsVault"`
	MasterNFTATA           string              `json:"masterNftAta"`
	TransactionIndex       uint64              `json:"transactionIndex"`
	TransactionPDA         string              `json:"transactionPda"`
	ProposalPDA            string              `json:"proposalPda"`
	ReleaseEntryPDA        string              `json:"releaseEntryPda"`
	PublisherEd25519Pubkey string              `json:"publisherEd25519Pubkey"`
	SignedPayloadHash      string              `json:"signedPayloadHash"`
	AuthorSig              string              `json:"authorSig"`
	CreatedAtUnix          int64               `json:"createdAtUnix"`
	Ed25519Instruction     CeremonyInstruction `json:"ed25519Instruction"`
	RegisterReleaseEntry   CeremonyInstruction `json:"registerReleaseEntryInstruction"`
	QuorumPolicy           ReleaseQuorum       `json:"quorumPolicy"`
}

type CeremonyInstruction struct {
	ProgramID string            `json:"programId"`
	Accounts  []CeremonyAccount `json:"accounts"`
	Data      string            `json:"data"`
}

type CeremonyAccount struct {
	Pubkey     string `json:"pubkey"`
	IsSigner   bool   `json:"isSigner"`
	IsWritable bool   `json:"isWritable"`
}

// Registration contains independently verified chain facts, never HTTP input
// or caller-asserted execution. The engine obtains it only from its fixed
// ProposalObserver after the exact reviewed proposal has executed.
type Registration struct {
	ProposalReference      string
	RegisteredAtUnix       int64
	ProgramID              string
	MasterNftMint          string
	LicenseSquadsVault     string
	ReleaseEntryPDA        string
	PublisherEd25519Pubkey string
	SignedPayloadHash      string
	AuthorSig              string
	QuorumPolicy           ReleaseQuorum
}

// Decode preserves the explicit v1/v2 boundary and rejects duplicate or aliased
// claims before Go's case-insensitive decoder sees a content-addressed input.
func Decode(raw []byte, maxCandidateBytes int64) (Input, error) {
	var input Input
	allowed := map[string]bool{"schema": true, "dossierId": true, "storeId": true, "appId": true, "version": true, "candidate": true, "artifactSha256": true, "metadataSha256": true, "runtimeContractSha256": false, "packageId": true, "appHash": true, "releaseHash": true, "stageId": true, "releaseB64": false, "ceremonyB64": false, "developer": false, "repo": false, "slug": false}
	fields, err := exactReleaseObject(raw, allowed)
	if err != nil {
		return input, err
	}
	if _, err := exactReleaseObject(fields["candidate"], map[string]bool{"sha256": true, "bytes": true}); err != nil {
		return input, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&input); err != nil || d.Decode(&struct{}{}) != io.EOF {
		return input, errors.New("finalization input is not closed JSON")
	}
	if (input.Schema == Schema && (fields["releaseB64"] == nil || fields["ceremonyB64"] != nil)) || (input.Schema == PreparedSchema && (fields["ceremonyB64"] == nil || fields["releaseB64"] != nil)) {
		return input, errors.New("finalization input mixes prepared and completed state")
	}
	return input, input.Validate(maxCandidateBytes)
}

func (i Input) preparedCeremony() ([]byte, CeremonyState, error) {
	var state CeremonyState
	raw, err := base64.StdEncoding.Strict().DecodeString(i.CeremonyB64)
	if err != nil || len(raw) == 0 || len(raw) > 128<<10 || base64.StdEncoding.EncodeToString(raw) != i.CeremonyB64 {
		return nil, state, errors.New("prepared ceremony encoding is invalid")
	}
	state, err = decodeCeremony(raw)
	return raw, state, err
}

// WithRegistration produces a new, complete descriptor only after an exact
// chain observation. It never updates the original input, ceremony bytes or
// signed preparation digest. Candidate decoding must precede this call, and
// SidecarPublishBody rechecks the package against the immutable input again.
func (i Input) WithRegistration(observed Registration, maxCandidateBytes int64) (Input, error) {
	if err := i.Validate(maxCandidateBytes); err != nil {
		return Input{}, err
	}
	if observed.RegisteredAtUnix <= 0 {
		return Input{}, errors.New("release registration has no actual chain time")
	}
	if i.Schema == Schema {
		_, claims, err := i.Release(maxCandidateBytes)
		if err != nil || claims.SignedAtUnix != observed.RegisteredAtUnix || !sameRegistration(claims, observed) {
			return Input{}, errors.New("complete release differs from observed registration")
		}
		return i, nil
	}
	_, state, err := i.preparedCeremony()
	if err != nil {
		return Input{}, err
	}
	if state.TransactionPDA != observed.ProposalReference || state.ProgramID != observed.ProgramID || state.PublisherEd25519Pubkey != observed.PublisherEd25519Pubkey || state.SignedPayloadHash != observed.SignedPayloadHash || state.CreatedAtUnix > observed.RegisteredAtUnix+120 {
		return Input{}, errors.New("prepared author state differs from observed proposal or registration")
	}
	claims := ReleaseClaims{Schema: "melusina-release-v1", AppHash: state.AppHash, ReleaseHash: state.ReleaseHash, Version: state.Version, SignedAtUnix: observed.RegisteredAtUnix, MasterNftMint: state.MasterNftMint, LicenseSquadsVault: state.LicenseSquadsVault, ReleaseEntryPDA: state.ReleaseEntryPDA, AuthorSig: state.AuthorSig, QuorumPolicy: state.QuorumPolicy, ReleaseNonce: state.ReleaseNonce, RuntimeContractSHA256: i.RuntimeSHA}
	if i.RuntimeSHA != "" {
		claims.RuntimeContractSchema = "melusina-app-runtime-contract-v1"
	}
	if !sameRegistration(claims, observed) {
		return Input{}, errors.New("prepared release authority differs from observed registration")
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		return Input{}, err
	}
	i.Schema, i.CeremonyB64, i.ReleaseB64 = Schema, "", base64.StdEncoding.EncodeToString(raw)
	if err := i.Validate(maxCandidateBytes); err != nil {
		return Input{}, err
	}
	return i, nil
}

func sameRegistration(claims ReleaseClaims, observed Registration) bool {
	return claims.MasterNftMint == observed.MasterNftMint && claims.LicenseSquadsVault == observed.LicenseSquadsVault && claims.ReleaseEntryPDA == observed.ReleaseEntryPDA && claims.AuthorSig == observed.AuthorSig && claims.QuorumPolicy == observed.QuorumPolicy
}

func decodeCeremony(raw []byte) (CeremonyState, error) {
	var state CeremonyState
	allowed := map[string]bool{}
	for _, key := range []string{"$schema", "status", "dryRun", "appHash", "releaseHash", "releaseNonce", "version", "appId", "appIdHash", "licenseMint", "masterNftMint", "programId", "squadsProgramId", "multisigPda", "licenseSquadsVault", "masterNftAta", "transactionIndex", "transactionPda", "proposalPda", "releaseEntryPda", "publisherEd25519Pubkey", "signedPayloadHash", "authorSig", "createdAtUnix", "ed25519Instruction", "registerReleaseEntryInstruction", "quorumPolicy"} {
		allowed[key] = true
	}
	fields, err := exactReleaseObject(raw, allowed)
	if err != nil {
		return state, err
	}
	if _, err := exactReleaseObject(fields["quorumPolicy"], map[string]bool{"threshold": true, "memberCount": true, "multisigPda": true}); err != nil {
		return state, err
	}
	for _, name := range []string{"ed25519Instruction", "registerReleaseEntryInstruction"} {
		instruction, err := exactReleaseObjectWithNulls(fields[name], map[string]bool{"programId": true, "accounts": true, "data": true}, map[string]bool{"accounts": name == "ed25519Instruction"})
		if err != nil {
			return state, err
		}
		var accounts []json.RawMessage
		if err := json.Unmarshal(instruction["accounts"], &accounts); err != nil {
			return state, err
		}
		if len(accounts) > 7 {
			return state, errors.New("ceremony contains extra account privileges")
		}
		for _, account := range accounts {
			if _, err := exactReleaseObject(account, map[string]bool{"pubkey": true, "isSigner": true, "isWritable": true}); err != nil {
				return state, err
			}
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&state); err != nil || d.Decode(&struct{}{}) != io.EOF {
		return state, errors.New("ceremony is not closed JSON")
	}
	if err := state.validate(); err != nil {
		return CeremonyState{}, err
	}
	return state, nil
}

// DecodePreparedCeremony validates original author preparation bytes without
// claiming that a proposal exists or has executed.
func DecodePreparedCeremony(raw []byte) (CeremonyState, error) { return decodeCeremony(raw) }

func (s CeremonyState) validate() error {
	if s.Schema != "melusina-release-ceremony-v1" || s.Status != "dry-run-prepared" || !s.DryRun || s.CreatedAtUnix <= 0 || len(s.AppID) != 52 || !appID(s.AppID) || strings.Contains(s.AppID, "-") || s.AppIDHash != digest([]byte(s.AppID)) || !lowerHex(s.AppHash, 64) || !lowerHex(s.ReleaseHash, 64) || !safeText(s.Version, 32) || len(s.Version) > 32 || !safeText(s.ReleaseNonce, 256) || s.ReleaseHash != digest([]byte(s.AppHash+s.Version+s.ReleaseNonce)) || !lowerHex(s.SignedPayloadHash, 64) || s.TransactionIndex == 0 {
		return errors.New("prepared ceremony identity, nonce, status or time is invalid")
	}
	keys := map[string]squadsproof.Pubkey{}
	for _, value := range []string{s.MasterNftMint, s.ProgramID, s.SquadsProgramID, s.MultisigPDA, s.LicenseSquadsVault, s.MasterNFTATA, s.TransactionPDA, s.ProposalPDA, s.ReleaseEntryPDA, s.PublisherEd25519Pubkey} {
		key, err := squadsproof.DecodePubkey(value)
		if err != nil {
			return errors.New("prepared ceremony authority is malformed")
		}
		keys[value] = key
	}
	if s.LicenseMint != s.MasterNftMint || keys[s.SquadsProgramID] != squadsproof.DefaultProgramID || s.QuorumPolicy.MultisigPDA != s.MultisigPDA || s.QuorumPolicy.Threshold < 1 || s.QuorumPolicy.MemberCount < s.QuorumPolicy.Threshold || s.QuorumPolicy.MemberCount > 65535 {
		return errors.New("prepared ceremony quorum or license scope differs")
	}
	multisig, master, registry, vault := keys[s.MultisigPDA], keys[s.MasterNftMint], keys[s.ProgramID], keys[s.LicenseSquadsVault]
	derivedVault, _, err := squadsproof.DeriveVaultPDA(multisig, 0, squadsproof.DefaultProgramID)
	if err != nil || derivedVault != vault {
		return errors.New("prepared ceremony vault does not derive from its quorum")
	}
	tx, _, err := squadsproof.DeriveVaultTransactionPDA(multisig, s.TransactionIndex, squadsproof.DefaultProgramID)
	if err != nil || tx != keys[s.TransactionPDA] {
		return errors.New("prepared ceremony transaction PDA differs")
	}
	proposal, _, err := squadsproof.DeriveProposalPDA(multisig, s.TransactionIndex, squadsproof.DefaultProgramID)
	if err != nil || proposal != keys[s.ProposalPDA] {
		return errors.New("prepared ceremony proposal PDA differs")
	}
	appHash, _ := hex.DecodeString(s.AppHash)
	var appHash32 [32]byte
	copy(appHash32[:], appHash)
	entry, _, err := primitives.DeriveReleaseV2(master, appHash32, registry)
	if err != nil || entry != keys[s.ReleaseEntryPDA] {
		return errors.New("prepared ceremony release PDA differs")
	}
	token, _ := squadsproof.DecodePubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
	ataProgram, _ := squadsproof.DecodePubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
	ata, _, err := primitives.FindProgramAddress([][]byte{vault[:], token[:], master[:]}, ataProgram, nil)
	if err != nil || ata != keys[s.MasterNFTATA] {
		return errors.New("prepared ceremony Master NFT account differs")
	}
	appIDHash, _ := hex.DecodeString(s.AppIDHash)
	releaseHash, _ := hex.DecodeString(s.ReleaseHash)
	author := keys[s.PublisherEd25519Pubkey]
	h := sha256.New()
	for _, part := range [][]byte{[]byte("melusina-release-entry-v1"), master[:], appHash, appIDHash, releaseHash, []byte(s.Version), vault[:], author[:]} {
		h.Write(part)
	}
	payload := h.Sum(nil)
	signature, err := base64.StdEncoding.Strict().DecodeString(s.AuthorSig)
	if err != nil || base64.StdEncoding.EncodeToString(signature) != s.AuthorSig || s.SignedPayloadHash != hex.EncodeToString(payload) || !ed25519.Verify(ed25519.PublicKey(author[:]), payload, signature) {
		return errors.New("prepared ceremony author signature does not bind its exact payload")
	}
	disc := sha256.Sum256([]byte("global:register_release_entry"))
	register := bytes.NewBuffer(disc[:8])
	register.Write(appHash)
	register.Write(appIDHash)
	register.Write(releaseHash)
	_ = binary.Write(register, binary.LittleEndian, uint32(len(s.Version)))
	register.WriteString(s.Version)
	register.Write(vault[:])
	register.Write(author[:])
	register.Write(signature)
	register.Write(payload)
	wantAccounts := []CeremonyAccount{{Pubkey: s.ReleaseEntryPDA, IsWritable: true}, {Pubkey: s.LicenseSquadsVault, IsSigner: true, IsWritable: true}, {Pubkey: s.MasterNftMint}, {Pubkey: s.MasterNFTATA}, {Pubkey: "Sysvar1nstructions1111111111111111111111111"}, {Pubkey: "11111111111111111111111111111111"}, {Pubkey: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"}}
	if s.RegisterReleaseEntry.ProgramID != s.ProgramID || s.RegisterReleaseEntry.Data != base64.StdEncoding.EncodeToString(register.Bytes()) || len(s.RegisterReleaseEntry.Accounts) != len(wantAccounts) {
		return errors.New("prepared register instruction differs from its signed payload")
	}
	for i, account := range wantAccounts {
		if s.RegisterReleaseEntry.Accounts[i] != account {
			return errors.New("prepared register instruction has different account privileges")
		}
	}
	ed := []byte{1, 0, 16, 0, 255, 255, 80, 0, 255, 255, 112, 0, 32, 0, 255, 255}
	ed = append(ed, signature...)
	ed = append(ed, author[:]...)
	ed = append(ed, payload...)
	if s.Ed25519Instruction.ProgramID != "Ed25519SigVerify111111111111111111111111111" || len(s.Ed25519Instruction.Accounts) != 0 || s.Ed25519Instruction.Data != base64.StdEncoding.EncodeToString(ed) {
		return errors.New("prepared ed25519 instruction differs from its author signature")
	}
	return nil
}
