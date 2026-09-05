package main

// Chain decoding for Bazaar Control policy/grant accounts. The sidecar reads
// the program accounts itself rather than trusting a Pearl-supplied policy
// description. Any unknown enum, truncated account, PDA mismatch, or account
// owner mismatch refuses the command.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	storeControlPolicySeed    = "store_control_policy"
	storePublisherGrantSeed   = "store_publisher_grant"
	storePolicyStatusActive   = 0
	storePolicyStatusRetired  = 1
	storeGrantStatusActive    = 0
	storeGrantStatusSuspended = 1
	storeGrantStatusRevoked   = 2
)

func readStoreControlPolicyMeta(data []byte) (storeControlPolicyMeta, error) {
	var meta storeControlPolicyMeta
	if len(data) < verify.AccountDiscriminatorLen || !bytes.Equal(data[:verify.AccountDiscriminatorLen], accountDiscriminator("StoreControlPolicy")) {
		return meta, errors.New("store_control_policy: discriminator mismatch")
	}
	offset := verify.AccountDiscriminatorLen
	var err error
	if offset, err = copyFixed(data, offset, meta.LicenseNFTMint[:], "store_control_policy", "license_nft_mint"); err != nil {
		return meta, err
	}
	if offset, err = copyFixed(data, offset, meta.StoreDomainHash[:], "store_control_policy", "store_domain_hash"); err != nil {
		return meta, err
	}
	if offset, err = copyFixed(data, offset, meta.StoreAuthority[:], "store_control_policy", "store_authority"); err != nil {
		return meta, err
	}
	if offset, err = copyFixed(data, offset, meta.StoreOperatorAuthorization[:], "store_control_policy", "store_operator_authorization"); err != nil {
		return meta, err
	}
	if offset, err = copyFixed(data, offset, meta.PearlCommandPublicKey[:], "store_control_policy", "pearl_command_ed25519_pubkey"); err != nil {
		return meta, err
	}
	if offset, err = copyFixed(data, offset, meta.HumanApprovalPublicKey[:], "store_control_policy", "human_approval_ed25519_pubkey"); err != nil {
		return meta, err
	}
	if offset+8 > len(data) {
		return meta, errors.New("store_control_policy: policy_epoch: buffer too short")
	}
	meta.PolicyEpoch = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset >= len(data) {
		return meta, errors.New("store_control_policy: status: buffer too short")
	}
	switch data[offset] {
	case storePolicyStatusActive:
		meta.Active = true
	case storePolicyStatusRetired:
		meta.Active = false
	default:
		return meta, fmt.Errorf("store_control_policy: invalid status %d", data[offset])
	}
	offset++
	// created_by, created_at, updated_by, updated_at, retired_at, bump.
	if offset, err = skipFixed(data, offset, 32+8+32+8, "store_control_policy", "audit fields"); err != nil {
		return meta, err
	}
	if offset, err = skipI64Option(data, offset, "store_control_policy", "retired_at"); err != nil {
		return meta, err
	}
	if offset, err = skipFixed(data, offset, 1, "store_control_policy", "bump"); err != nil {
		return meta, err
	}
	if offset != len(data) {
		return meta, errors.New("store_control_policy: unexpected trailing bytes")
	}
	return meta, nil
}

func readStorePublisherGrantMeta(data []byte) (storePublisherGrantMeta, error) {
	var meta storePublisherGrantMeta
	if len(data) < verify.AccountDiscriminatorLen || !bytes.Equal(data[:verify.AccountDiscriminatorLen], accountDiscriminator("StorePublisherGrant")) {
		return meta, errors.New("store_publisher_grant: discriminator mismatch")
	}
	offset := verify.AccountDiscriminatorLen
	var policy pda.Pubkey
	var err error
	if offset, err = copyFixed(data, offset, policy[:], "store_publisher_grant", "policy"); err != nil {
		return meta, err
	}
	meta.Policy = policy.Base58()
	if offset, err = copyFixed(data, offset, meta.AppID[:], "store_publisher_grant", "app_id"); err != nil {
		return meta, err
	}
	if offset, err = copyFixed(data, offset, meta.PublisherSquadsVault[:], "store_publisher_grant", "publisher_squads_vault"); err != nil {
		return meta, err
	}
	if offset, err = copyFixed(data, offset, meta.PublisherEd25519Pubkey[:], "store_publisher_grant", "publisher_ed25519_pubkey"); err != nil {
		return meta, err
	}
	if offset+2+8+8+8 > len(data) {
		return meta, errors.New("store_publisher_grant: authority fields: buffer too short")
	}
	meta.Actions = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	meta.NotBefore = time.Unix(int64(binary.LittleEndian.Uint64(data[offset:offset+8])), 0).UTC()
	offset += 8
	meta.ExpiresAt = time.Unix(int64(binary.LittleEndian.Uint64(data[offset:offset+8])), 0).UTC()
	offset += 8
	meta.GrantEpoch = binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8
	if offset >= len(data) {
		return meta, errors.New("store_publisher_grant: status: buffer too short")
	}
	switch data[offset] {
	case storeGrantStatusActive:
		meta.Active = true
	case storeGrantStatusSuspended, storeGrantStatusRevoked:
		meta.Active = false
	default:
		return meta, fmt.Errorf("store_publisher_grant: invalid status %d", data[offset])
	}
	offset++
	if offset, err = skipPubkeyOption(data, offset, "store_publisher_grant", "previous_grant"); err != nil {
		return meta, err
	}
	if offset, err = skipFixed(data, offset, 32+8+32+8, "store_publisher_grant", "audit fields"); err != nil {
		return meta, err
	}
	if offset, err = skipI64Option(data, offset, "store_publisher_grant", "revoked_at"); err != nil {
		return meta, err
	}
	if offset, err = skipPubkeyOption(data, offset, "store_publisher_grant", "revoked_by"); err != nil {
		return meta, err
	}
	if offset, err = skipFixed(data, offset, 1, "store_publisher_grant", "bump"); err != nil {
		return meta, err
	}
	if offset != len(data) {
		return meta, errors.New("store_publisher_grant: unexpected trailing bytes")
	}
	return meta, nil
}

func skipI64Option(data []byte, offset int, account, field string) (int, error) {
	if offset >= len(data) {
		return -1, fmt.Errorf("%s: %s option: buffer too short", account, field)
	}
	switch data[offset] {
	case 0:
		return offset + 1, nil
	case 1:
		return skipFixed(data, offset+1, 8, account, field)
	default:
		return -1, fmt.Errorf("%s: %s option tag %d is invalid", account, field, data[offset])
	}
}

func skipPubkeyOption(data []byte, offset int, account, field string) (int, error) {
	if offset >= len(data) {
		return -1, fmt.Errorf("%s: %s option: buffer too short", account, field)
	}
	switch data[offset] {
	case 0:
		return offset + 1, nil
	case 1:
		return skipFixed(data, offset+1, 32, account, field)
	default:
		return -1, fmt.Errorf("%s: %s option tag %d is invalid", account, field, data[offset])
	}
}

func deriveStoreControlPolicy(licenseMint pda.Pubkey, domainHash [32]byte, program pda.Pubkey) (pda.Pubkey, error) {
	key, _, err := primitives.FindProgramAddress([][]byte{[]byte(storeControlPolicySeed), licenseMint[:], domainHash[:]}, program, nil)
	return key, err
}

func deriveStorePublisherGrant(policy pda.Pubkey, appID [32]byte, publisherKey [32]byte, program pda.Pubkey) (pda.Pubkey, error) {
	key, _, err := primitives.FindProgramAddress([][]byte{[]byte(storePublisherGrantSeed), policy[:], appID[:], publisherKey[:]}, program, nil)
	return key, err
}

func fetchRawProgramAccount(ctx context.Context, cr chainReader, expectedAddress pda.Pubkey, expectedProgram pda.Pubkey) ([]byte, error) {
	raw, ok := cr.(rawAccountReader)
	if !ok {
		return nil, errors.New("chain reader lacks raw account support required for Bazaar Control")
	}
	data, owner, err := raw.fetchRawAccount(ctx, expectedAddress.Base58())
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(owner) != expectedProgram.Base58() {
		return nil, errors.New("account owner is not the configured license registry program")
	}
	return data, nil
}

func fetchActiveStoreControlPolicy(ctx context.Context, cfg Config, cr chainReader) (storeControlPolicyMeta, error) {
	var zero storeControlPolicyMeta
	licenseMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(cfg.LicenseNFTMint))
	if err != nil {
		return zero, fmt.Errorf("policy license mint: %w", err)
	}
	program, err := primitives.PubkeyFromBase58(strings.TrimSpace(cfg.ProgramID))
	if err != nil {
		return zero, fmt.Errorf("policy program id: %w", err)
	}
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	policyPDA, err := deriveStoreControlPolicy(licenseMint, domainHash, program)
	if err != nil {
		return zero, fmt.Errorf("derive StoreControlPolicy: %w", err)
	}
	data, err := fetchRawProgramAccount(ctx, cr, policyPDA, program)
	if err != nil {
		return zero, fmt.Errorf("fetch StoreControlPolicy: %w", err)
	}
	meta, err := readStoreControlPolicyMeta(data)
	if err != nil {
		return zero, err
	}
	meta.PDA = policyPDA.Base58()
	storeAuthority, err := primitives.PubkeyFromBase58(strings.TrimSpace(cfg.StoreAuthority))
	if err != nil {
		return zero, fmt.Errorf("policy store authority: %w", err)
	}
	authz, _, err := pda.StoreOperatorAuthorization(licenseMint, domainHash, program)
	if err != nil {
		return zero, fmt.Errorf("derive StoreOperatorAuthorization: %w", err)
	}
	if !meta.Active || meta.PolicyEpoch == 0 || meta.LicenseNFTMint != licenseMint || meta.StoreDomainHash != domainHash || meta.StoreAuthority != storeAuthority || meta.StoreOperatorAuthorization != authz || meta.PearlCommandPublicKey == [32]byte{} || meta.HumanApprovalPublicKey == [32]byte{} {
		return zero, errors.New("StoreControlPolicy does not bind this active store")
	}
	return meta, nil
}

func fetchStorePublisherGrant(ctx context.Context, cfg Config, cr chainReader, policy storeControlPolicyMeta, appID [32]byte, publisherKey [32]byte) (storePublisherGrantMeta, error) {
	var zero storePublisherGrantMeta
	program, err := primitives.PubkeyFromBase58(strings.TrimSpace(cfg.ProgramID))
	if err != nil {
		return zero, fmt.Errorf("grant program id: %w", err)
	}
	policyPDA, err := primitives.PubkeyFromBase58(policy.PDA)
	if err != nil {
		return zero, fmt.Errorf("grant policy address: %w", err)
	}
	grantPDA, err := deriveStorePublisherGrant(policyPDA, appID, publisherKey, program)
	if err != nil {
		return zero, fmt.Errorf("derive StorePublisherGrant: %w", err)
	}
	data, err := fetchRawProgramAccount(ctx, cr, grantPDA, program)
	if err != nil {
		return zero, fmt.Errorf("fetch StorePublisherGrant: %w", err)
	}
	meta, err := readStorePublisherGrantMeta(data)
	if err != nil {
		return zero, err
	}
	meta.PDA = grantPDA.Base58()
	if meta.Policy != policy.PDA || meta.AppID != appID || meta.PublisherEd25519Pubkey != publisherKey {
		return zero, errors.New("StorePublisherGrant identity does not match its PDA")
	}
	return meta, nil
}
