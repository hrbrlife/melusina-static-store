package main

// Target-scoped StoreReleaseListing bootstrap.
//
// Existing releases were published before the StoreReleaseListing policy was
// enabled. This command closes that gap without inventing a second publisher:
// it runs only under the boot-identity-bound Store binary, reads the immutable
// current catalog generation, re-verifies every release against the one shared
// Squads authority, creates the corresponding on-chain listing with the Store
// operator key, persists each transition in a resumable WAL, and only then can
// atomically opt the Store into listing enforcement.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	listingBootstrapStateName   = "store-release-listing-bootstrap-v1.json"
	listingBootstrapStateSchema = "melusina-store-release-listing-bootstrap-v1"
	listingAccountSpace         = 251
	listingFeeReserveLamports   = uint64(10_000)
	listingRPCTimeout           = 20 * time.Second
	listingConfirmTimeout       = 45 * time.Second
)

type listingBootstrapOptions struct {
	configPath          string
	expectedIndexSHA256 string
	expectedAppCount    int
	dryRun              bool
	activate            bool
}

type listingBootstrapState struct {
	Schema                 string                 `json:"schema"`
	State                  string                 `json:"state"`
	SnapshotID             string                 `json:"snapshotId"`
	IndexSHA256            string                 `json:"indexSha256"`
	ExpectedAppCount       int                    `json:"expectedAppCount"`
	StoreAuthority         string                 `json:"storeAuthority"`
	LicenseNFTMint         string                 `json:"licenseNftMint"`
	ProgramID              string                 `json:"programId"`
	StoreDomainHash        string                 `json:"storeDomainHash"`
	StoreCertFingerprint   string                 `json:"storeCertFingerprint"`
	RentPerListingLamports uint64                 `json:"rentPerListingLamports"`
	RequiredLamports       uint64                 `json:"requiredLamports"`
	ConfigSHA256Before     string                 `json:"configSha256Before,omitempty"`
	ConfigSHA256After      string                 `json:"configSha256After,omitempty"`
	Items                  []listingBootstrapItem `json:"items"`
}

type listingBootstrapItem struct {
	AppID                string `json:"appId"`
	PackageID            string `json:"packageId"`
	AppHash              string `json:"appHash"`
	ReleaseEntry         string `json:"releaseEntry"`
	FoundationApp        string `json:"foundationApp"`
	Listing              string `json:"listing"`
	State                string `json:"state"`
	Attempts             int    `json:"attempts,omitempty"`
	TransactionSignature string `json:"transactionSignature,omitempty"`
	RecentBlockhash      string `json:"recentBlockhash,omitempty"`
	LastError            string `json:"lastError,omitempty"`
}

type listingBootstrapReport struct {
	State                  string `json:"state"`
	SnapshotID             string `json:"snapshotId"`
	IndexSHA256            string `json:"indexSha256"`
	Apps                   int    `json:"apps"`
	AlreadyActive          int    `json:"alreadyActive"`
	RegisteredThisRun      int    `json:"registeredThisRun"`
	RentPerListingLamports uint64 `json:"rentPerListingLamports"`
	RequiredLamports       uint64 `json:"requiredLamports"`
	StoreAuthority         string `json:"storeAuthority"`
}

func runListingBootstrapSubcommand(args []string) {
	fs := flag.NewFlagSet("listing-bootstrap", flag.ExitOnError)
	opts := listingBootstrapOptions{}
	fs.StringVar(&opts.configPath, "config", "store.config.json", "path to operator config (JSON)")
	fs.StringVar(&opts.expectedIndexSHA256, "expected-index-sha256", "", "required SHA-256 of the current immutable apps/index.json")
	fs.IntVar(&opts.expectedAppCount, "expected-app-count", 0, "required exact current catalog app count")
	fs.BoolVar(&opts.dryRun, "dry-run", false, "verify and calculate the exact bootstrap without sending transactions")
	fs.BoolVar(&opts.activate, "activate", false, "after every listing is active, atomically enable store_authority in the config")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		log.Fatalf("listing-bootstrap: unexpected positional arguments: %v", fs.Args())
	}
	if opts.expectedAppCount <= 0 {
		log.Fatalf("listing-bootstrap: --expected-app-count must be positive")
	}
	if _, err := listingHex32(opts.expectedIndexSHA256); err != nil {
		log.Fatalf("listing-bootstrap: --expected-index-sha256: %v", err)
	}
	if opts.dryRun && opts.activate {
		log.Fatalf("listing-bootstrap: --activate cannot be combined with --dry-run")
	}

	cfg, err := LoadConfig(opts.configPath)
	if err != nil {
		log.Fatalf("listing-bootstrap config: %v", err)
	}
	if err := validateCatalogStorageRoots(cfg); err != nil {
		log.Fatalf("listing-bootstrap config: %v", err)
	}
	setProgramIDFromConfig(cfg.ProgramID)
	if cfg.RPCURL == "" {
		log.Fatalf("listing-bootstrap requires rpc_url")
	}
	cr := newConfiguredStoreRPCReader(cfg)
	bootCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	operator, err := deriveOperatorIdentity(bootCtx, cfg, cr)
	cancel()
	if err != nil {
		log.Fatalf("listing-bootstrap boot identity: %v", err)
	}
	if operator == nil {
		log.Fatalf("listing-bootstrap requires a write-capable boot identity")
	}

	writerLock, err := acquireExistingWriterLock(filepath.Join(cfg.CatalogMigrationStateDir, "writer.lock"))
	if err != nil {
		log.Fatalf("listing-bootstrap catalog writer exclusion: %v", err)
	}
	defer writerLock.Close()

	ctx, cancelRun := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancelRun()
	report, err := runListingBootstrap(ctx, cfg, cr, operator, opts)
	if err != nil {
		log.Fatalf("listing-bootstrap: %v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		log.Fatalf("listing-bootstrap report: %v", err)
	}
}

func runListingBootstrap(ctx context.Context, cfg Config, cr chainReader, operator *identity.Private, opts listingBootstrapOptions) (listingBootstrapReport, error) {
	var report listingBootstrapReport
	if operator == nil || cr == nil {
		return report, errors.New("requires a verified operator and chain reader")
	}
	operatorRaw, err := signPubkey32(operator.Public())
	if err != nil {
		return report, fmt.Errorf("operator public key: %w", err)
	}
	storeAuthority := pda.Pubkey(operatorRaw)
	if strings.TrimSpace(cfg.StoreAuthority) != "" && strings.TrimSpace(cfg.StoreAuthority) != storeAuthority.Base58() {
		return report, fmt.Errorf("configured store_authority %q differs from boot-identity operator %s", cfg.StoreAuthority, storeAuthority.Base58())
	}
	allowedTierMask, licenseMint, err := VerifyStoreOperator(ctx, cr, cfg, operatorRaw, false)
	if err != nil {
		return report, err
	}
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	authzPDA, _, err := pda.StoreOperatorAuthorization(licenseMint, domainHash, programID)
	if err != nil {
		return report, fmt.Errorf("derive StoreOperatorAuthorization: %w", err)
	}
	certFingerprint, err := tlsCertFingerprint(bootIdentityTLSCertPath(cfg))
	if err != nil {
		return report, fmt.Errorf("store TLS certificate fingerprint: %w", err)
	}

	store := AppCatalogGenerationStore{Root: cfg.CatalogGenerationRoot}
	snapshot, err := store.ResolveCurrent()
	if err != nil {
		return report, fmt.Errorf("resolve current catalog generation: %w", err)
	}
	indexBytes, err := readSnapshotFileBounded(snapshot, "apps/index.json", maxAppCatalogJSONBytes)
	if err != nil {
		return report, fmt.Errorf("read current apps/index.json: %w", err)
	}
	indexSHA := sha256.Sum256(indexBytes)
	indexSHAHex := hex.EncodeToString(indexSHA[:])
	if indexSHAHex != strings.ToLower(strings.TrimSpace(opts.expectedIndexSHA256)) {
		return report, fmt.Errorf("current apps/index.json SHA-256 %s differs from required %s", indexSHAHex, strings.ToLower(strings.TrimSpace(opts.expectedIndexSHA256)))
	}
	var index catalogIndex
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		return report, fmt.Errorf("decode current apps/index.json: %w", err)
	}
	if len(index.Apps) != opts.expectedAppCount {
		return report, fmt.Errorf("current apps/index.json has %d apps, want %d", len(index.Apps), opts.expectedAppCount)
	}

	preflightCfg := cfg
	preflightCfg.StoreAuthority = "" // prove global release facts before listings exist.
	items, err := buildListingBootstrapItems(ctx, snapshot, index.Apps, preflightCfg, cr, storeAuthority, domainHash, allowedTierMask)
	if err != nil {
		return report, err
	}
	state := listingBootstrapState{
		Schema:               listingBootstrapStateSchema,
		State:                "registering",
		SnapshotID:           snapshot.ID,
		IndexSHA256:          indexSHAHex,
		ExpectedAppCount:     opts.expectedAppCount,
		StoreAuthority:       storeAuthority.Base58(),
		LicenseNFTMint:       licenseMint.Base58(),
		ProgramID:            programID.Base58(),
		StoreDomainHash:      hex.EncodeToString(domainHash[:]),
		StoreCertFingerprint: hex.EncodeToString(certFingerprint[:]),
		Items:                items,
	}
	statePath := filepath.Join(cfg.CatalogMigrationStateDir, listingBootstrapStateName)
	if existing, exists, err := readListingBootstrapState(statePath); err != nil {
		return report, err
	} else if exists {
		if err := mergeListingBootstrapState(&state, existing); err != nil {
			return report, err
		}
	}
	if state.State == "activated" && strings.TrimSpace(cfg.StoreAuthority) != storeAuthority.Base58() {
		return report, errors.New("listing bootstrap WAL is activated but the loaded config no longer enables its verified store authority")
	}

	rpc := newListingBootstrapRPC(cfg)
	if err := reconcileListingBootstrapState(ctx, cr, &state, storeAuthority, authzPDA, domainHash); err != nil {
		return report, err
	}
	missing := countPendingListingItems(state.Items)
	if (state.State == "registered" || state.State == "activated") && missing != 0 {
		return report, fmt.Errorf("listing bootstrap WAL is %s but %d exact active listing(s) are absent", state.State, missing)
	}
	state.RentPerListingLamports = 0
	state.RequiredLamports = 0
	if missing > 0 {
		rent, err := rpc.minimumBalanceForRentExemption(ctx, listingAccountSpace)
		if err != nil {
			return report, err
		}
		state.RentPerListingLamports = rent
		state.RequiredLamports = uint64(missing) * (rent + listingFeeReserveLamports)
	}
	report = listingBootstrapReport{
		State:                  state.State,
		SnapshotID:             state.SnapshotID,
		IndexSHA256:            state.IndexSHA256,
		Apps:                   len(state.Items),
		AlreadyActive:          len(state.Items) - missing,
		RentPerListingLamports: state.RentPerListingLamports,
		RequiredLamports:       state.RequiredLamports,
		StoreAuthority:         state.StoreAuthority,
	}
	if opts.dryRun {
		return report, nil
	}
	if err := writeListingBootstrapState(statePath, state); err != nil {
		return report, fmt.Errorf("persist listing bootstrap WAL: %w", err)
	}
	if missing > 0 {
		balance, err := rpc.balance(ctx, storeAuthority)
		if err != nil {
			return report, err
		}
		if balance < state.RequiredLamports {
			return report, fmt.Errorf("store authority %s has %d lamports; bootstrap requires at least %d for %d missing listings", storeAuthority.Base58(), balance, state.RequiredLamports, missing)
		}
	}

	for index := range state.Items {
		item := &state.Items[index]
		active, err := bootstrapListingActive(ctx, cr, *item, storeAuthority, authzPDA, domainHash)
		if err != nil {
			return report, err
		}
		if active {
			item.State = "active"
			item.LastError = ""
			if err := writeListingBootstrapState(statePath, state); err != nil {
				return report, err
			}
			continue
		}
		if item.State == "active" {
			return report, fmt.Errorf("listing bootstrap WAL marks %s active but its exact on-chain listing is absent", item.AppID)
		}
		if err := reconcilePreparedListingBootstrapTransaction(ctx, rpc, cr, item, storeAuthority, authzPDA, domainHash); err != nil {
			item.LastError = err.Error()
			_ = writeListingBootstrapState(statePath, state)
			return report, err
		}
		active, err = bootstrapListingActive(ctx, cr, *item, storeAuthority, authzPDA, domainHash)
		if err != nil {
			return report, err
		}
		if active {
			item.State = "active"
			item.LastError = ""
			report.RegisteredThisRun++
			if err := writeListingBootstrapState(statePath, state); err != nil {
				return report, err
			}
			continue
		}
		prepared, err := prepareListingBootstrapTransaction(ctx, rpc, operator, storeAuthority, authzPDA, licenseMint, domainHash, certFingerprint, *item)
		if err != nil {
			return report, err
		}
		item.Attempts++
		item.State = "prepared"
		item.TransactionSignature = prepared.Signature
		item.RecentBlockhash = prepared.RecentBlockhash
		item.LastError = ""
		if err := writeListingBootstrapState(statePath, state); err != nil {
			return report, err
		}
		if err := rpc.sendTransaction(ctx, prepared.Wire, prepared.Signature); err != nil {
			item.LastError = err.Error()
			_ = writeListingBootstrapState(statePath, state)
			return report, fmt.Errorf("submit StoreReleaseListing for %s (%s): %w", item.AppID, prepared.Signature, err)
		}
		item.State = "submitted"
		if err := writeListingBootstrapState(statePath, state); err != nil {
			return report, err
		}
		if err := rpc.confirmTransaction(ctx, prepared.Signature); err != nil {
			item.LastError = err.Error()
			_ = writeListingBootstrapState(statePath, state)
			return report, fmt.Errorf("confirm StoreReleaseListing for %s (%s): %w", item.AppID, prepared.Signature, err)
		}
		if err := waitForBootstrapListing(ctx, cr, *item, storeAuthority, authzPDA, domainHash); err != nil {
			item.LastError = err.Error()
			_ = writeListingBootstrapState(statePath, state)
			return report, err
		}
		item.State = "active"
		item.LastError = ""
		report.RegisteredThisRun++
		if err := writeListingBootstrapState(statePath, state); err != nil {
			return report, err
		}
	}
	if state.State != "activated" {
		state.State = "registered"
	}
	if opts.activate {
		before, after, err := activateStoreListingPolicy(opts.configPath, storeAuthority.Base58())
		if err != nil {
			return report, err
		}
		state.ConfigSHA256Before = before
		state.ConfigSHA256After = after
		state.State = "activated"
	}
	if err := writeListingBootstrapState(statePath, state); err != nil {
		return report, err
	}
	report.State = state.State
	return report, nil
}

func buildListingBootstrapItems(ctx context.Context, snapshot AppCatalogSnapshot, entries []catalogIndexApp, cfg Config, cr chainReader, storeAuthority pda.Pubkey, domainHash [32]byte, allowedTierMask uint8) ([]listingBootstrapItem, error) {
	seenAppID := make(map[string]struct{}, len(entries))
	seenPackageID := make(map[string]struct{}, len(entries))
	items := make([]listingBootstrapItem, 0, len(entries))
	for _, entry := range entries {
		appID := strings.TrimSpace(entry.AppID)
		packageID := strings.ToLower(strings.TrimSpace(entry.PackageID))
		if !isSafePathSegment(appID) || !validCatalogPackageID(packageID) {
			return nil, fmt.Errorf("current catalog has unsafe appId/packageId %q/%q", appID, packageID)
		}
		if _, duplicate := seenAppID[appID]; duplicate {
			return nil, fmt.Errorf("current catalog repeats appId %q", appID)
		}
		if _, duplicate := seenPackageID[packageID]; duplicate {
			return nil, fmt.Errorf("current catalog repeats packageId %q", packageID)
		}
		seenAppID[appID] = struct{}{}
		seenPackageID[packageID] = struct{}{}
		releaseBytes, err := readSnapshotFileBounded(snapshot, filepath.ToSlash(filepath.Join("attest", appID, "RELEASE.json")), maxAppCatalogJSONBytes)
		if err != nil {
			return nil, fmt.Errorf("read current release for %s: %w", appID, err)
		}
		rel, ok := parseReleaseClaim(releaseBytes)
		if !ok {
			return nil, fmt.Errorf("current release for %s is malformed", appID)
		}
		if err := VerifyServeHash(ctx, cr, cfg, rel.AppHash, rel); err != nil {
			return nil, fmt.Errorf("current release %s does not pass global serve verification: %w", appID, err)
		}
		appHash, err := hash32FromHex(rel.AppHash)
		if err != nil {
			return nil, fmt.Errorf("current release %s app hash: %w", appID, err)
		}
		masterMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(rel.MasterNftMint))
		if err != nil {
			return nil, fmt.Errorf("current release %s master mint: %w", appID, err)
		}
		releasePDA, _, err := pda.Release(masterMint, appHash, programID)
		if err != nil {
			return nil, fmt.Errorf("derive current ReleaseEntry for %s: %w", appID, err)
		}
		chainAppID, err := cr.FetchReleaseEntryAppID(ctx, releasePDA.Base58())
		if err != nil {
			return nil, fmt.Errorf("fetch current ReleaseEntry app id for %s: %w", appID, err)
		}
		foundationPDA, _, err := pda.FoundationApp(chainAppID, programID)
		if err != nil {
			return nil, fmt.Errorf("derive FoundationAppEntry for %s: %w", appID, err)
		}
		if tier, err := resolveFoundationTier(ctx, cr, releasePDA); err != nil {
			return nil, fmt.Errorf("resolve Foundation tier for %s: %w", appID, err)
		} else if tier != 0 && (allowedTierMask&tier) != tier {
			return nil, fmt.Errorf("Store operator tier mask 0x%02x does not cover %s tier 0x%02x", allowedTierMask, appID, tier)
		}
		listingPDA, _, err := pda.StoreReleaseListing(storeAuthority, appHash, programID)
		if err != nil {
			return nil, fmt.Errorf("derive StoreReleaseListing for %s: %w", appID, err)
		}
		items = append(items, listingBootstrapItem{
			AppID:         appID,
			PackageID:     packageID,
			AppHash:       strings.ToLower(rel.AppHash),
			ReleaseEntry:  releasePDA.Base58(),
			FoundationApp: foundationPDA.Base58(),
			Listing:       listingPDA.Base58(),
			State:         "pending",
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].AppID < items[j].AppID })
	return items, nil
}

func countPendingListingItems(items []listingBootstrapItem) int {
	count := 0
	for _, item := range items {
		if item.State != "active" {
			count++
		}
	}
	return count
}

func bootstrapListingActive(ctx context.Context, cr chainReader, item listingBootstrapItem, storeAuthority, authzPDA pda.Pubkey, domainHash [32]byte) (bool, error) {
	listing, err := cr.FetchStoreReleaseListingMeta(ctx, item.Listing)
	if errors.Is(err, verify.ErrPDANotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("fetch StoreReleaseListing for %s: %w", item.AppID, err)
	}
	appHash, err := hash32FromHex(item.AppHash)
	if err != nil {
		return false, err
	}
	release, err := primitives.PubkeyFromBase58(item.ReleaseEntry)
	if err != nil {
		return false, err
	}
	if listing.Status != storeListingStatusActive || listing.StoreAuthority != storeAuthority || listing.AppHash != appHash || listing.ReleaseEntry != release || listing.StoreDomainHash != domainHash || listing.OperatorAuthorization != authzPDA {
		return false, fmt.Errorf("existing StoreReleaseListing for %s is not the exact active target projection", item.AppID)
	}
	return true, nil
}

func waitForBootstrapListing(ctx context.Context, cr chainReader, item listingBootstrapItem, storeAuthority, authzPDA pda.Pubkey, domainHash [32]byte) error {
	deadline := time.NewTimer(listingConfirmTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(750 * time.Millisecond)
	defer tick.Stop()
	for {
		active, err := bootstrapListingActive(ctx, cr, item, storeAuthority, authzPDA, domainHash)
		if err != nil {
			return err
		}
		if active {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("StoreReleaseListing for %s did not become active within %s", item.AppID, listingConfirmTimeout)
		case <-tick.C:
		}
	}
}

// reconcileListingBootstrapState treats chain state as authoritative over the
// local WAL. A recovered WAL may have been written just before an RPC response
// or process exit; an exact active listing therefore wins. The reverse does not:
// a WAL that says an active listing disappeared is a governance anomaly and
// must stop rather than silently recreate a possibly-delisted projection.
func reconcileListingBootstrapState(ctx context.Context, cr chainReader, state *listingBootstrapState, storeAuthority, authzPDA pda.Pubkey, domainHash [32]byte) error {
	if state == nil {
		return errors.New("missing listing bootstrap state")
	}
	for index := range state.Items {
		item := &state.Items[index]
		active, err := bootstrapListingActive(ctx, cr, *item, storeAuthority, authzPDA, domainHash)
		if err != nil {
			return err
		}
		if active {
			item.State = "active"
			item.LastError = ""
			continue
		}
		if item.State == "active" {
			return fmt.Errorf("listing bootstrap WAL marks %s active but its exact on-chain listing is absent", item.AppID)
		}
	}
	return nil
}

type preparedListingBootstrapTransaction struct {
	Wire            []byte
	Signature       string
	RecentBlockhash string
}

// reconcilePreparedListingBootstrapTransaction avoids blindly replacing a
// transaction after a crash. A known prior signature is first checked against
// RPC and, if confirmed, its exact listing is awaited. Only an absent or known
// failed signature falls through to a fresh, deterministic registration.
func reconcilePreparedListingBootstrapTransaction(ctx context.Context, rpc *listingBootstrapRPC, cr chainReader, item *listingBootstrapItem, storeAuthority, authzPDA pda.Pubkey, domainHash [32]byte) error {
	if item == nil || (item.State != "prepared" && item.State != "submitted") || strings.TrimSpace(item.TransactionSignature) == "" {
		return nil
	}
	found, confirmed, transactionErr, err := rpc.transactionStatus(ctx, item.TransactionSignature)
	if err != nil {
		return fmt.Errorf("check prior StoreReleaseListing transaction %s: %w", item.TransactionSignature, err)
	}
	if !found {
		return nil
	}
	if transactionErr != "" {
		item.State = "pending"
		item.LastError = "prior StoreReleaseListing transaction failed: " + transactionErr
		return nil
	}
	if !confirmed {
		if err := rpc.confirmTransaction(ctx, item.TransactionSignature); err != nil {
			return fmt.Errorf("confirm prior StoreReleaseListing transaction %s: %w", item.TransactionSignature, err)
		}
	}
	if err := waitForBootstrapListing(ctx, cr, *item, storeAuthority, authzPDA, domainHash); err != nil {
		return fmt.Errorf("await prior StoreReleaseListing transaction %s: %w", item.TransactionSignature, err)
	}
	item.State = "active"
	item.LastError = ""
	return nil
}

func prepareListingBootstrapTransaction(ctx context.Context, rpc *listingBootstrapRPC, operator *identity.Private, storeAuthority, authzPDA, licenseMint pda.Pubkey, domainHash, certFingerprint [32]byte, item listingBootstrapItem) (preparedListingBootstrapTransaction, error) {
	var prepared preparedListingBootstrapTransaction
	blockhash, err := rpc.latestBlockhash(ctx)
	if err != nil {
		return prepared, err
	}
	appHash, err := hash32FromHex(item.AppHash)
	if err != nil {
		return prepared, err
	}
	listing, err := primitives.PubkeyFromBase58(item.Listing)
	if err != nil {
		return prepared, err
	}
	release, err := primitives.PubkeyFromBase58(item.ReleaseEntry)
	if err != nil {
		return prepared, err
	}
	foundation, err := primitives.PubkeyFromBase58(item.FoundationApp)
	if err != nil {
		return prepared, err
	}
	wire, signature, err := buildRegisterStoreReleaseListingTransaction(operator, storeAuthority, listing, release, authzPDA, foundation, licenseMint, appHash, domainHash, certFingerprint, blockhash)
	if err != nil {
		return prepared, fmt.Errorf("build StoreReleaseListing transaction for %s: %w", item.AppID, err)
	}
	prepared.Wire = wire
	prepared.Signature = signature
	prepared.RecentBlockhash = primitives.EncodeBase58(blockhash[:])
	return prepared, nil
}

func mergeListingBootstrapState(current *listingBootstrapState, existing listingBootstrapState) error {
	if err := validateListingBootstrapState(existing); err != nil {
		return fmt.Errorf("existing listing bootstrap WAL: %w", err)
	}
	for name, got := range map[string][2]string{
		"snapshotId":      [2]string{existing.SnapshotID, current.SnapshotID},
		"indexSha256":     [2]string{existing.IndexSHA256, current.IndexSHA256},
		"storeAuthority":  [2]string{existing.StoreAuthority, current.StoreAuthority},
		"licenseNftMint":  [2]string{existing.LicenseNFTMint, current.LicenseNFTMint},
		"programId":       [2]string{existing.ProgramID, current.ProgramID},
		"storeDomainHash": [2]string{existing.StoreDomainHash, current.StoreDomainHash},
		"certFingerprint": [2]string{existing.StoreCertFingerprint, current.StoreCertFingerprint},
	} {
		if got[0] != got[1] {
			return fmt.Errorf("existing listing bootstrap WAL %s differs from current verified input", name)
		}
	}
	if existing.ExpectedAppCount != current.ExpectedAppCount || len(existing.Items) != len(current.Items) {
		return errors.New("existing listing bootstrap WAL has a different catalog scope")
	}
	previous := make(map[string]listingBootstrapItem, len(existing.Items))
	for _, item := range existing.Items {
		previous[item.AppID] = item
	}
	for index := range current.Items {
		old, ok := previous[current.Items[index].AppID]
		if !ok || old.PackageID != current.Items[index].PackageID || old.AppHash != current.Items[index].AppHash || old.ReleaseEntry != current.Items[index].ReleaseEntry || old.FoundationApp != current.Items[index].FoundationApp || old.Listing != current.Items[index].Listing {
			return fmt.Errorf("existing listing bootstrap WAL item %q differs from current verified catalog", current.Items[index].AppID)
		}
		current.Items[index].State = old.State
		current.Items[index].Attempts = old.Attempts
		current.Items[index].TransactionSignature = old.TransactionSignature
		current.Items[index].RecentBlockhash = old.RecentBlockhash
		current.Items[index].LastError = old.LastError
	}
	current.State = existing.State
	current.RentPerListingLamports = existing.RentPerListingLamports
	current.RequiredLamports = existing.RequiredLamports
	current.ConfigSHA256Before = existing.ConfigSHA256Before
	current.ConfigSHA256After = existing.ConfigSHA256After
	return nil
}

func validateListingBootstrapState(state listingBootstrapState) error {
	if state.Schema != listingBootstrapStateSchema {
		return errors.New("schema mismatch")
	}
	if state.State != "registering" && state.State != "registered" && state.State != "activated" {
		return fmt.Errorf("invalid state %q", state.State)
	}
	if state.ExpectedAppCount <= 0 || len(state.Items) != state.ExpectedAppCount {
		return errors.New("item count does not match expected app count")
	}
	for name, value := range map[string]string{
		"storeAuthority": state.StoreAuthority,
		"licenseNftMint": state.LicenseNFTMint,
		"programId":      state.ProgramID,
	} {
		if _, err := primitives.PubkeyFromBase58(value); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	for name, value := range map[string]string{
		"indexSha256":          state.IndexSHA256,
		"storeDomainHash":      state.StoreDomainHash,
		"storeCertFingerprint": state.StoreCertFingerprint,
	} {
		if _, err := listingHex32(value); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	seen := make(map[string]struct{}, len(state.Items))
	for _, item := range state.Items {
		if !isSafePathSegment(item.AppID) || !validCatalogPackageID(item.PackageID) {
			return errors.New("invalid appId/packageId")
		}
		if _, duplicate := seen[item.AppID]; duplicate {
			return fmt.Errorf("duplicate appId %q", item.AppID)
		}
		seen[item.AppID] = struct{}{}
		if _, err := listingHex32(item.AppHash); err != nil {
			return fmt.Errorf("app %s appHash: %w", item.AppID, err)
		}
		for name, value := range map[string]string{
			"releaseEntry":  item.ReleaseEntry,
			"foundationApp": item.FoundationApp,
			"listing":       item.Listing,
		} {
			if _, err := primitives.PubkeyFromBase58(value); err != nil {
				return fmt.Errorf("app %s %s: %w", item.AppID, name, err)
			}
		}
		if item.State != "pending" && item.State != "prepared" && item.State != "submitted" && item.State != "active" {
			return fmt.Errorf("app %s has invalid state %q", item.AppID, item.State)
		}
		if item.Attempts < 0 {
			return fmt.Errorf("app %s has a negative attempt count", item.AppID)
		}
		if len(item.TransactionSignature) > 128 || len(item.RecentBlockhash) > 64 || len(item.LastError) > 4096 {
			return fmt.Errorf("app %s has oversized WAL transaction data", item.AppID)
		}
		if item.State == "prepared" || item.State == "submitted" {
			if strings.TrimSpace(item.TransactionSignature) == "" || strings.TrimSpace(item.RecentBlockhash) == "" {
				return fmt.Errorf("app %s %s state is missing transaction provenance", item.AppID, item.State)
			}
			if _, err := primitives.PubkeyFromBase58(item.RecentBlockhash); err != nil {
				return fmt.Errorf("app %s recent blockhash: %w", item.AppID, err)
			}
		}
		if state.State != "registering" && item.State != "active" {
			return fmt.Errorf("%s bootstrap WAL has non-active app %s", state.State, item.AppID)
		}
	}
	if state.State == "activated" && (state.ConfigSHA256Before == "" || state.ConfigSHA256After == "") {
		return errors.New("activated bootstrap WAL lacks the config activation hashes")
	}
	return nil
}

func readListingBootstrapState(path string) (listingBootstrapState, bool, error) {
	var state listingBootstrapState
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, false, nil
	}
	if err != nil {
		return state, false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return state, false, errors.New("listing bootstrap WAL must be a mode-0600 regular file")
	}
	if info.Size() < 1 || info.Size() > maxCatalogBootstrapJSON {
		return state, false, errors.New("listing bootstrap WAL has an unsafe size")
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
	if err := validateListingBootstrapState(state); err != nil {
		return state, false, err
	}
	return state, true, nil
}

func writeListingBootstrapState(path string, state listingBootstrapState) error {
	if err := validateListingBootstrapState(state); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return atomicWriteListingBootstrapFile(path, raw, 0o600)
}

func atomicWriteListingBootstrapFile(path string, body []byte, mode os.FileMode) error {
	if len(body) == 0 || len(body) > maxCatalogBootstrapJSON {
		return errors.New("unsafe listing bootstrap write size")
	}
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != mode) {
		return errors.New("refusing to replace unsafe listing bootstrap file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".listing-bootstrap-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	dirFile, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirFile.Close()
	if err := dirFile.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}

func activateStoreListingPolicy(configPath, authority string) (string, string, error) {
	info, err := os.Lstat(configPath)
	if err != nil {
		return "", "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", "", errors.New("store config must be a private regular file")
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return "", "", err
	}
	before := sha256.Sum256(raw)
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", "", err
	}
	if existing, ok := doc["store_authority"]; ok {
		var value string
		if err := json.Unmarshal(existing, &value); err != nil {
			return "", "", errors.New("store_authority is not a JSON string")
		}
		if strings.TrimSpace(value) != "" && strings.TrimSpace(value) != authority {
			return "", "", fmt.Errorf("store_authority %q differs from verified bootstrap authority %s", value, authority)
		}
	}
	encodedAuthority, _ := json.Marshal(authority)
	doc["store_authority"] = encodedAuthority
	next, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", "", err
	}
	next = append(next, '\n')
	if err := atomicWriteListingBootstrapFile(configPath, next, info.Mode().Perm()); err != nil {
		return "", "", err
	}
	validated, err := LoadConfig(configPath)
	if err != nil {
		return "", "", fmt.Errorf("re-read activated config: %w", err)
	}
	if validated.StoreAuthority != authority {
		return "", "", errors.New("activated config did not retain verified store authority")
	}
	after := sha256.Sum256(next)
	return hex.EncodeToString(before[:]), hex.EncodeToString(after[:]), nil
}

func listingHex32(raw string) ([32]byte, error) {
	var out [32]byte
	value := strings.TrimSpace(raw)
	if len(value) != 64 || value != strings.ToLower(value) {
		return out, errors.New("must be lowercase 64-hex")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(out) {
		return out, errors.New("must be lowercase 64-hex")
	}
	copy(out[:], decoded)
	return out, nil
}

// The transaction code below implements only the legacy Solana message shape
// needed for this fixed single-signer bootstrap instruction. It deliberately
// does not expose a generic signing endpoint.
type listingTxAccountMeta struct {
	Key        pda.Pubkey
	IsSigner   bool
	IsWritable bool
}

type listingTxInstruction struct {
	ProgramID pda.Pubkey
	Accounts  []listingTxAccountMeta
	Data      []byte
}

func buildRegisterStoreReleaseListingTransaction(operator *identity.Private, storeAuthority, listing, release, operatorAuthorization, foundation, licenseMint pda.Pubkey, appHash, domainHash, certFingerprint, blockhash [32]byte) ([]byte, string, error) {
	if operator == nil {
		return nil, "", errors.New("missing operator signer")
	}
	systemProgram, err := primitives.PubkeyFromBase58("11111111111111111111111111111111")
	if err != nil {
		return nil, "", err
	}
	discriminator := sha256.Sum256([]byte("global:register_store_release_listing"))
	data := make([]byte, 0, 8+32+32+32+32)
	data = append(data, discriminator[:8]...)
	data = append(data, appHash[:]...)
	data = append(data, certFingerprint[:]...)
	data = append(data, licenseMint[:]...)
	data = append(data, domainHash[:]...)
	return buildListingLegacyTransaction([]listingTxInstruction{{
		ProgramID: programID,
		Accounts: []listingTxAccountMeta{
			{Key: listing, IsWritable: true},
			{Key: release},
			{Key: operatorAuthorization},
			{Key: foundation},
			{Key: storeAuthority, IsSigner: true, IsWritable: true},
			{Key: systemProgram},
		},
		Data: data,
	}}, operator, storeAuthority, blockhash)
}

func buildListingLegacyTransaction(instructions []listingTxInstruction, signer *identity.Private, payer pda.Pubkey, blockhash [32]byte) ([]byte, string, error) {
	if len(instructions) == 0 {
		return nil, "", errors.New("no instructions")
	}
	type account struct {
		key      pda.Pubkey
		signer   bool
		writable bool
	}
	seen := make(map[pda.Pubkey]*account)
	order := make([]pda.Pubkey, 0, 8)
	add := func(key pda.Pubkey, isSigner, isWritable bool) {
		if current, ok := seen[key]; ok {
			current.signer = current.signer || isSigner
			current.writable = current.writable || isWritable
			return
		}
		seen[key] = &account{key: key, signer: isSigner, writable: isWritable}
		order = append(order, key)
	}
	add(payer, true, true)
	for _, instruction := range instructions {
		for _, meta := range instruction.Accounts {
			add(meta.Key, meta.IsSigner, meta.IsWritable)
		}
		add(instruction.ProgramID, false, false)
	}
	accounts := make([]account, 0, len(order))
	for _, key := range order {
		accounts = append(accounts, *seen[key])
	}
	rank := func(item account) int {
		switch {
		case item.signer && item.writable:
			return 0
		case item.signer:
			return 1
		case item.writable:
			return 2
		default:
			return 3
		}
	}
	sort.SliceStable(accounts, func(i, j int) bool { return rank(accounts[i]) < rank(accounts[j]) })
	if len(accounts) > 255 {
		return nil, "", errors.New("too many transaction accounts")
	}
	indices := make(map[pda.Pubkey]byte, len(accounts))
	required, readonlySigners, readonlyUnsigned := 0, 0, 0
	for index, account := range accounts {
		indices[account.key] = byte(index)
		if account.signer {
			required++
			if !account.writable {
				readonlySigners++
			}
		} else if !account.writable {
			readonlyUnsigned++
		}
	}
	if required != 1 || accounts[0].key != payer {
		return nil, "", errors.New("bootstrap transaction must have exactly one writable payer signer")
	}
	message := make([]byte, 0, 512)
	message = append(message, byte(required), byte(readonlySigners), byte(readonlyUnsigned))
	message = append(message, listingCompactU16(len(accounts))...)
	for _, account := range accounts {
		message = append(message, account.key[:]...)
	}
	message = append(message, blockhash[:]...)
	message = append(message, listingCompactU16(len(instructions))...)
	for _, instruction := range instructions {
		message = append(message, indices[instruction.ProgramID])
		message = append(message, listingCompactU16(len(instruction.Accounts))...)
		for _, meta := range instruction.Accounts {
			message = append(message, indices[meta.Key])
		}
		message = append(message, listingCompactU16(len(instruction.Data))...)
		message = append(message, instruction.Data...)
	}
	signature := signer.Sign(message)
	if len(signature) != 64 {
		return nil, "", errors.New("operator returned a non-ed25519 transaction signature")
	}
	wire := make([]byte, 0, 1+len(signature)+len(message))
	wire = append(wire, listingCompactU16(1)...)
	wire = append(wire, signature...)
	wire = append(wire, message...)
	return wire, primitives.EncodeBase58(signature), nil
}

func listingCompactU16(value int) []byte {
	switch {
	case value < 0:
		return nil
	case value < 0x80:
		return []byte{byte(value)}
	case value < 0x4000:
		return []byte{byte(value&0x7f) | 0x80, byte(value >> 7)}
	default:
		return []byte{byte(value&0x7f) | 0x80, byte((value>>7)&0x7f) | 0x80, byte(value >> 14)}
	}
}

type listingBootstrapRPC struct {
	endpoints []string
	attempts  int
	client    *http.Client
	nextID    uint64
}

func newListingBootstrapRPC(cfg Config) *listingBootstrapRPC {
	endpoints := append([]string{cfg.RPCURL}, cfg.RPCFallbackURLs...)
	return &listingBootstrapRPC{endpoints: endpoints, attempts: cfg.RPCAttempts, client: &http.Client{Timeout: listingRPCTimeout}}
}

func (r *listingBootstrapRPC) call(ctx context.Context, method string, params any, out any) error {
	if len(r.endpoints) == 0 {
		return errors.New("no RPC endpoint configured")
	}
	if r.attempts <= 0 {
		r.attempts = defaultRPCAttempts
	}
	paramsRaw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	var failures []string
	for _, endpoint := range r.endpoints {
		for attempt := 0; attempt < r.attempts; attempt++ {
			r.nextID++
			body, err := json.Marshal(struct {
				JSONRPC string          `json:"jsonrpc"`
				ID      uint64          `json:"id"`
				Method  string          `json:"method"`
				Params  json.RawMessage `json:"params"`
			}{JSONRPC: "2.0", ID: r.nextID, Method: method, Params: paramsRaw})
			if err != nil {
				return err
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/json")
			response, err := r.client.Do(req)
			if err != nil {
				failures = append(failures, "transport")
				continue
			}
			payload, readErr := io.ReadAll(io.LimitReader(response.Body, 4<<20))
			_ = response.Body.Close()
			if readErr != nil || response.StatusCode != http.StatusOK {
				failures = append(failures, "response")
				continue
			}
			var envelope struct {
				Result json.RawMessage `json:"result"`
				Error  *struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(payload, &envelope); err != nil {
				failures = append(failures, "decode")
				continue
			}
			if envelope.Error != nil {
				return fmt.Errorf("RPC %s: %d %s", method, envelope.Error.Code, envelope.Error.Message)
			}
			if out != nil {
				if err := json.Unmarshal(envelope.Result, out); err != nil {
					return fmt.Errorf("decode RPC %s result: %w", method, err)
				}
			}
			return nil
		}
	}
	return fmt.Errorf("RPC %s unavailable after %d transport/decode failure(s)", method, len(failures))
}

func (r *listingBootstrapRPC) minimumBalanceForRentExemption(ctx context.Context, space int) (uint64, error) {
	var result uint64
	if err := r.call(ctx, "getMinimumBalanceForRentExemption", []any{space, map[string]string{"commitment": "confirmed"}}, &result); err != nil {
		return 0, fmt.Errorf("get listing rent: %w", err)
	}
	return result, nil
}

func (r *listingBootstrapRPC) balance(ctx context.Context, address pda.Pubkey) (uint64, error) {
	var result struct {
		Value uint64 `json:"value"`
	}
	if err := r.call(ctx, "getBalance", []any{address.Base58(), map[string]string{"commitment": "confirmed"}}, &result); err != nil {
		return 0, fmt.Errorf("get Store operator balance: %w", err)
	}
	return result.Value, nil
}

func (r *listingBootstrapRPC) latestBlockhash(ctx context.Context) ([32]byte, error) {
	var zero [32]byte
	var result struct {
		Value struct {
			Blockhash string `json:"blockhash"`
		} `json:"value"`
	}
	if err := r.call(ctx, "getLatestBlockhash", []any{map[string]string{"commitment": "confirmed"}}, &result); err != nil {
		return zero, fmt.Errorf("get latest blockhash: %w", err)
	}
	value, err := primitives.PubkeyFromBase58(result.Value.Blockhash)
	if err != nil {
		return zero, fmt.Errorf("decode latest blockhash: %w", err)
	}
	return value, nil
}

func (r *listingBootstrapRPC) sendTransaction(ctx context.Context, wire []byte, expectedSignature string) error {
	var signature string
	params := []any{base64.StdEncoding.EncodeToString(wire), map[string]any{
		"encoding": "base64", "skipPreflight": false, "preflightCommitment": "confirmed", "maxRetries": 3,
	}}
	if err := r.call(ctx, "sendTransaction", params, &signature); err != nil {
		return err
	}
	if strings.TrimSpace(signature) == "" {
		return errors.New("RPC returned an empty transaction signature")
	}
	if signature != expectedSignature {
		return fmt.Errorf("RPC returned transaction signature %s, want locally signed %s", signature, expectedSignature)
	}
	return nil
}

func (r *listingBootstrapRPC) transactionStatus(ctx context.Context, signature string) (found, confirmed bool, transactionErr string, err error) {
	var result struct {
		Value []*struct {
			Err                json.RawMessage `json:"err"`
			ConfirmationStatus string          `json:"confirmationStatus"`
		} `json:"value"`
	}
	if err := r.call(ctx, "getSignatureStatuses", []any{[]string{signature}, map[string]bool{"searchTransactionHistory": true}}, &result); err != nil {
		return false, false, "", err
	}
	if len(result.Value) != 1 {
		return false, false, "", errors.New("RPC returned an invalid signature-status result")
	}
	status := result.Value[0]
	if status == nil {
		return false, false, "", nil
	}
	if len(status.Err) > 0 && string(status.Err) != "null" {
		return true, false, string(status.Err), nil
	}
	confirmed = status.ConfirmationStatus == "confirmed" || status.ConfirmationStatus == "finalized"
	return true, confirmed, "", nil
}

func (r *listingBootstrapRPC) confirmTransaction(ctx context.Context, signature string) error {
	deadline := time.NewTimer(listingConfirmTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(700 * time.Millisecond)
	defer tick.Stop()
	for {
		found, confirmed, transactionErr, err := r.transactionStatus(ctx, signature)
		if err == nil && found {
			if transactionErr != "" {
				return fmt.Errorf("transaction failed: %s", transactionErr)
			}
			if confirmed {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("transaction %s was not confirmed within %s", signature, listingConfirmTimeout)
		case <-tick.C:
		}
	}
}
