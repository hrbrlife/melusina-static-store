package main

// Per-release StoreReleaseListing registration.
//
// The whole-catalog listing bootstrap was deliberately an operator recovery
// tool. A normal publish has a different safety requirement: it must obtain an
// exact active listing for its already-verified release *before* moving the
// catalog selector. This file keeps that authority deliberately narrow. It can
// only construct register_store_release_listing for facts the sidecar has
// independently derived; it is not a transaction/signing API.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	listingRegistrationStateSchema = "melusina-store-release-listing-registration-v1"
	listingRegistrationStatePrefix = "store-release-listing-registration-v1-"
)

// listingRegistrar is the only publish-path authority boundary for a listing.
// The Pearl will eventually submit a separately authenticated control command,
// but it must never supply transaction bytes, account lists, or a signer to
// this interface.
type listingRegistrar interface {
	EnsureActive(context.Context, listingRegistrationIntent) (listingRegistrationReceipt, error)
}

// listingRegistrationIntent is assembled from a durably staged candidate and
// the ReleaseEntry that VerifyPublish just proved active. None of its fields
// are accepted directly from a control-plane client.
type listingRegistrationIntent struct {
	StageID       string
	AppID         string
	AppHash       string
	MasterNFTMint string
}

// listingRegistrationReceipt is evidence, not an additional authority. The
// serve gate still independently reads and validates this exact on-chain
// listing before it serves the release.
type listingRegistrationReceipt struct {
	Listing               string `json:"listing"`
	ReleaseEntry          string `json:"releaseEntry"`
	StoreAuthority        string `json:"storeAuthority"`
	OperatorAuthorization string `json:"operatorAuthorization"`
	TransactionSignature  string `json:"transactionSignature,omitempty"`
	AlreadyActive         bool   `json:"alreadyActive"`
}

type boundedListingRegistrar struct {
	cfg      Config
	cr       chainReader
	operator *identity.Private
	rpc      *listingBootstrapRPC
	signer   listingTransactionSigner
}

func newBoundedListingRegistrar(cfg Config, cr chainReader, operator *identity.Private) listingRegistrar {
	if strings.TrimSpace(cfg.StoreAuthority) == "" || cr == nil || operator == nil {
		return nil
	}
	return &boundedListingRegistrar{
		cfg:      cfg,
		cr:       cr,
		operator: operator,
		rpc:      newListingBootstrapRPC(cfg),
		signer:   newListingTransactionSigner(cfg, cr, operator),
	}
}

type listingRegistrationState struct {
	Schema                string               `json:"schema"`
	StageID               string               `json:"stageId"`
	StoreAuthority        string               `json:"storeAuthority"`
	LicenseNFTMint        string               `json:"licenseNftMint"`
	StoreDomainHash       string               `json:"storeDomainHash"`
	StoreCertFingerprint  string               `json:"storeCertFingerprint"`
	OperatorAuthorization string               `json:"operatorAuthorization"`
	Item                  listingBootstrapItem `json:"item"`
}

func (r *boundedListingRegistrar) EnsureActive(ctx context.Context, intent listingRegistrationIntent) (listingRegistrationReceipt, error) {
	var receipt listingRegistrationReceipt
	if r == nil || r.cr == nil || r.operator == nil || r.rpc == nil || r.signer == nil {
		return receipt, errors.New("listing registrar is not initialized")
	}
	if err := requireSecureDirectory(r.cfg.CatalogMigrationStateDir, 0o700); err != nil {
		return receipt, fmt.Errorf("listing state directory: %w", err)
	}

	state, storeAuthority, authzPDA, _, domainHash, err := r.expectedState(ctx, intent)
	if err != nil {
		return receipt, err
	}
	statePath, err := listingRegistrationStatePath(r.cfg.CatalogMigrationStateDir, intent.StageID)
	if err != nil {
		return receipt, err
	}
	if existing, exists, err := readListingRegistrationState(statePath); err != nil {
		return receipt, fmt.Errorf("read listing registration state: %w", err)
	} else if exists {
		if err := mergeListingRegistrationState(&state, existing); err != nil {
			return receipt, fmt.Errorf("existing listing registration state: %w", err)
		}
	}

	active, err := bootstrapListingActive(ctx, r.cr, state.Item, storeAuthority, authzPDA, domainHash)
	if err != nil {
		return receipt, err
	}
	if active {
		wasActive := state.Item.State == "active"
		state.Item.State = "active"
		state.Item.LastError = ""
		if err := writeListingRegistrationState(statePath, state); err != nil {
			return receipt, err
		}
		return listingRegistrationReceipt{
			Listing:               state.Item.Listing,
			ReleaseEntry:          state.Item.ReleaseEntry,
			StoreAuthority:        state.StoreAuthority,
			OperatorAuthorization: state.OperatorAuthorization,
			TransactionSignature:  state.Item.TransactionSignature,
			AlreadyActive:         wasActive,
		}, nil
	}
	if state.Item.State == "active" {
		return receipt, fmt.Errorf("listing registration state marks %s active but its exact on-chain listing is absent", state.Item.AppID)
	}

	if err := reconcilePreparedListingBootstrapTransaction(ctx, r.rpc, r.cr, &state.Item, storeAuthority, authzPDA, domainHash); err != nil {
		state.Item.LastError = err.Error()
		_ = writeListingRegistrationState(statePath, state)
		return receipt, err
	}
	if state.Item.State == "active" {
		if err := writeListingRegistrationState(statePath, state); err != nil {
			return receipt, err
		}
		return listingRegistrationReceipt{
			Listing:               state.Item.Listing,
			ReleaseEntry:          state.Item.ReleaseEntry,
			StoreAuthority:        state.StoreAuthority,
			OperatorAuthorization: state.OperatorAuthorization,
			TransactionSignature:  state.Item.TransactionSignature,
			AlreadyActive:         true,
		}, nil
	}

	prepared, err := r.signer.Prepare(ctx, state, intent)
	if err != nil {
		return receipt, err
	}
	state.Item.Attempts++
	state.Item.State = "prepared"
	state.Item.TransactionSignature = prepared.Signature
	state.Item.RecentBlockhash = prepared.RecentBlockhash
	state.Item.LastError = ""
	if err := writeListingRegistrationState(statePath, state); err != nil {
		return receipt, err
	}
	if err := r.rpc.sendTransaction(ctx, prepared.Wire, prepared.Signature); err != nil {
		state.Item.LastError = err.Error()
		_ = writeListingRegistrationState(statePath, state)
		return receipt, fmt.Errorf("submit StoreReleaseListing for %s (%s): %w", state.Item.AppID, prepared.Signature, err)
	}
	state.Item.State = "submitted"
	if err := writeListingRegistrationState(statePath, state); err != nil {
		return receipt, err
	}
	if err := r.rpc.confirmTransaction(ctx, prepared.Signature); err != nil {
		state.Item.LastError = err.Error()
		_ = writeListingRegistrationState(statePath, state)
		return receipt, fmt.Errorf("confirm StoreReleaseListing for %s (%s): %w", state.Item.AppID, prepared.Signature, err)
	}
	if err := waitForBootstrapListing(ctx, r.cr, state.Item, storeAuthority, authzPDA, domainHash); err != nil {
		state.Item.LastError = err.Error()
		_ = writeListingRegistrationState(statePath, state)
		return receipt, err
	}
	state.Item.State = "active"
	state.Item.LastError = ""
	if err := writeListingRegistrationState(statePath, state); err != nil {
		return receipt, err
	}
	return listingRegistrationReceipt{
		Listing:               state.Item.Listing,
		ReleaseEntry:          state.Item.ReleaseEntry,
		StoreAuthority:        state.StoreAuthority,
		OperatorAuthorization: state.OperatorAuthorization,
		TransactionSignature:  state.Item.TransactionSignature,
	}, nil
}

func (r *boundedListingRegistrar) expectedState(ctx context.Context, intent listingRegistrationIntent) (listingRegistrationState, pda.Pubkey, pda.Pubkey, pda.Pubkey, [32]byte, error) {
	var zero listingRegistrationState
	var zeroKey pda.Pubkey
	var zeroHash [32]byte
	if _, err := listingHex32(intent.StageID); err != nil {
		return zero, zeroKey, zeroKey, zeroKey, zeroHash, fmt.Errorf("stage id: %w", err)
	}
	if !isSafePathSegment(intent.AppID) {
		return zero, zeroKey, zeroKey, zeroKey, zeroHash, errors.New("unsafe app id")
	}
	operatorRaw, err := signPubkey32(r.operator.Public())
	if err != nil {
		return zero, zeroKey, zeroKey, zeroKey, zeroHash, fmt.Errorf("operator public key: %w", err)
	}
	storeAuthority := pda.Pubkey(operatorRaw)
	if strings.TrimSpace(r.cfg.StoreAuthority) != storeAuthority.Base58() {
		return zero, zeroKey, zeroKey, zeroKey, zeroHash, fmt.Errorf("configured store_authority %q differs from boot-identity operator %s", r.cfg.StoreAuthority, storeAuthority.Base58())
	}
	allowedTierMask, licenseMint, err := VerifyStoreOperator(ctx, r.cr, r.cfg, operatorRaw, false)
	if err != nil {
		return zero, zeroKey, zeroKey, zeroKey, zeroHash, err
	}
	domainHash := primitives.StoreDomainHash(r.cfg.Domain)
	authzPDA, _, err := pda.StoreOperatorAuthorization(licenseMint, domainHash, programID)
	if err != nil {
		return zero, zeroKey, zeroKey, zeroKey, zeroHash, fmt.Errorf("derive StoreOperatorAuthorization: %w", err)
	}
	certFingerprint, err := tlsCertFingerprint(bootIdentityTLSCertPath(r.cfg))
	if err != nil {
		return zero, zeroKey, zeroKey, zeroKey, zeroHash, fmt.Errorf("store TLS certificate fingerprint: %w", err)
	}
	appHash, err := hash32FromHex(intent.AppHash)
	if err != nil {
		return zero, zeroKey, zeroKey, zeroKey, zeroHash, fmt.Errorf("app hash: %w", err)
	}
	masterMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(intent.MasterNFTMint))
	if err != nil {
		return zero, zeroKey, zeroKey, zeroKey, zeroHash, fmt.Errorf("master NFT mint: %w", err)
	}
	releasePDA, _, err := pda.Release(masterMint, appHash, programID)
	if err != nil {
		return zero, zeroKey, zeroKey, zeroKey, zeroHash, fmt.Errorf("derive ReleaseEntry: %w", err)
	}
	chainAppID, err := r.cr.FetchReleaseEntryAppID(ctx, releasePDA.Base58())
	if err != nil {
		return zero, zeroKey, zeroKey, zeroKey, zeroHash, fmt.Errorf("fetch ReleaseEntry app id: %w", err)
	}
	foundationPDA, _, err := pda.FoundationApp(chainAppID, programID)
	if err != nil {
		return zero, zeroKey, zeroKey, zeroKey, zeroHash, fmt.Errorf("derive FoundationAppEntry: %w", err)
	}
	if tier, err := resolveFoundationTier(ctx, r.cr, releasePDA); err != nil {
		return zero, zeroKey, zeroKey, zeroKey, zeroHash, err
	} else if tier != 0 && (allowedTierMask&tier) != tier {
		return zero, zeroKey, zeroKey, zeroKey, zeroHash, fmt.Errorf("Store operator tier mask 0x%02x does not cover %s tier 0x%02x", allowedTierMask, intent.AppID, tier)
	}
	listingPDA, _, err := pda.StoreReleaseListing(storeAuthority, appHash, programID)
	if err != nil {
		return zero, zeroKey, zeroKey, zeroKey, zeroHash, fmt.Errorf("derive StoreReleaseListing: %w", err)
	}
	state := listingRegistrationState{
		Schema:                listingRegistrationStateSchema,
		StageID:               strings.ToLower(intent.StageID),
		StoreAuthority:        storeAuthority.Base58(),
		LicenseNFTMint:        licenseMint.Base58(),
		StoreDomainHash:       fmt.Sprintf("%x", domainHash),
		StoreCertFingerprint:  fmt.Sprintf("%x", certFingerprint),
		OperatorAuthorization: authzPDA.Base58(),
		Item: listingBootstrapItem{
			AppID:         intent.AppID,
			AppHash:       strings.ToLower(intent.AppHash),
			ReleaseEntry:  releasePDA.Base58(),
			FoundationApp: foundationPDA.Base58(),
			Listing:       listingPDA.Base58(),
			State:         "pending",
		},
	}
	return state, storeAuthority, authzPDA, licenseMint, domainHash, nil
}

func listingRegistrationStatePath(stateDir, stageID string) (string, error) {
	if _, err := listingHex32(stageID); err != nil {
		return "", fmt.Errorf("stage id: %w", err)
	}
	return filepath.Join(stateDir, listingRegistrationStatePrefix+strings.ToLower(stageID)+".json"), nil
}

func readListingRegistrationState(path string) (listingRegistrationState, bool, error) {
	var state listingRegistrationState
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, false, nil
	}
	if err != nil {
		return state, false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maxCatalogBootstrapJSON {
		return state, false, errors.New("listing registration state must be a bounded mode-0600 regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return state, false, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return state, false, err
	}
	if err := validateListingRegistrationState(state); err != nil {
		return state, false, err
	}
	return state, true, nil
}

func writeListingRegistrationState(path string, state listingRegistrationState) error {
	if err := validateListingRegistrationState(state); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteListingBootstrapFile(path, append(raw, '\n'), 0o600)
}

func validateListingRegistrationState(state listingRegistrationState) error {
	if state.Schema != listingRegistrationStateSchema {
		return errors.New("schema mismatch")
	}
	if _, err := listingHex32(state.StageID); err != nil {
		return fmt.Errorf("stageId: %w", err)
	}
	for name, value := range map[string]string{
		"storeAuthority":        state.StoreAuthority,
		"licenseNftMint":        state.LicenseNFTMint,
		"operatorAuthorization": state.OperatorAuthorization,
	} {
		if _, err := primitives.PubkeyFromBase58(value); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	for name, value := range map[string]string{
		"storeDomainHash":      state.StoreDomainHash,
		"storeCertFingerprint": state.StoreCertFingerprint,
	} {
		if _, err := listingHex32(value); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	item := state.Item
	if !isSafePathSegment(item.AppID) || item.PackageID != "" {
		return errors.New("invalid listing registration app item")
	}
	if _, err := listingHex32(item.AppHash); err != nil {
		return fmt.Errorf("appHash: %w", err)
	}
	for name, value := range map[string]string{
		"releaseEntry":  item.ReleaseEntry,
		"foundationApp": item.FoundationApp,
		"listing":       item.Listing,
	} {
		if _, err := primitives.PubkeyFromBase58(value); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if item.State != "pending" && item.State != "prepared" && item.State != "submitted" && item.State != "active" {
		return fmt.Errorf("invalid item state %q", item.State)
	}
	if item.Attempts < 0 || len(item.TransactionSignature) > 128 || len(item.RecentBlockhash) > 64 || len(item.LastError) > 4096 {
		return errors.New("invalid listing registration transaction evidence")
	}
	if (item.State == "prepared" || item.State == "submitted") && (strings.TrimSpace(item.TransactionSignature) == "" || strings.TrimSpace(item.RecentBlockhash) == "") {
		return errors.New("prepared listing registration lacks transaction provenance")
	}
	return nil
}

func mergeListingRegistrationState(current *listingRegistrationState, existing listingRegistrationState) error {
	if current == nil {
		return errors.New("missing current listing registration state")
	}
	if err := validateListingRegistrationState(existing); err != nil {
		return err
	}
	if current.StageID != existing.StageID || current.StoreAuthority != existing.StoreAuthority || current.LicenseNFTMint != existing.LicenseNFTMint || current.StoreDomainHash != existing.StoreDomainHash || current.StoreCertFingerprint != existing.StoreCertFingerprint || current.OperatorAuthorization != existing.OperatorAuthorization || current.Item.AppID != existing.Item.AppID || current.Item.AppHash != existing.Item.AppHash || current.Item.ReleaseEntry != existing.Item.ReleaseEntry || current.Item.FoundationApp != existing.Item.FoundationApp || current.Item.Listing != existing.Item.Listing {
		return errors.New("verified listing registration inputs differ from the durable state")
	}
	current.Item.State = existing.Item.State
	current.Item.Attempts = existing.Item.Attempts
	current.Item.TransactionSignature = existing.Item.TransactionSignature
	current.Item.RecentBlockhash = existing.Item.RecentBlockhash
	current.Item.LastError = existing.Item.LastError
	return nil
}

func mustListingHex32(value string) [32]byte {
	decoded, err := listingHex32(value)
	if err != nil {
		panic("validated listing registration state: " + err.Error())
	}
	return decoded
}

var _ listingRegistrar = (*boundedListingRegistrar)(nil)
