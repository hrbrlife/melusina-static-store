package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// buildValidFixtureWithArtifact keeps a package's real metadata and SPK
// together, so native Shell acceptance can consume the published release.
func buildValidFixtureWithArtifact(t *testing.T, cfg Config, masterMintB58 string, spk, metadata []byte) publishFixture {
	t.Helper()
	// Individual tests often construct only the fields they exercise. Give
	// fixture-backed release tests a complete shared-authority tuple while
	// keeping production Config validation fail-closed for an omitted tuple.
	if _, err := cfg.sharedSquadsAuthority(); err != nil {
		cfg.ReleaseSquadsAuthority = ReleaseSquadsAuthority{
			Multisig:    testStoreAuthority,
			Vault:       testReleaseCustodianVault,
			ProgramID:   testStoreAuthority,
			Threshold:   defaultBazaarSquadsThreshold,
			MemberCount: defaultBazaarSquadsMemberCount,
		}
		configureReleaseAuthorityFixtureForBuild(&cfg, t.TempDir())
	}

	// A Store that publishes holds its own licence to verify_license's rule
	// under its estate's master mint (verifyStoreOwnLicence), which is the
	// mint its releases are registered under. A test that names no
	// release_master_nft_mint gets the app's.
	if strings.TrimSpace(cfg.ReleaseMasterNftMint) == "" {
		cfg.ReleaseMasterNftMint = masterMintB58
	}

	spkSum := sha256.Sum256(spk)
	var packageMetadata struct {
		AppID     string `json:"appId"`
		PackageID string `json:"packageId"`
		Version   string `json:"version"`
	}
	if err := json.Unmarshal(metadata, &packageMetadata); err != nil {
		t.Fatal(err)
	}
	if packageMetadata.PackageID != hex.EncodeToString(spkSum[:])[:32] || packageMetadata.AppID == "" || packageMetadata.Version == "" {
		t.Fatal("published-artifact-metadata-binding-required")
	}
	appIDText := packageMetadata.AppID
	// The on-chain app_hash is the TREE-HASH over {app.spk, metadata.json}, not
	// sha256(spk) — exactly what apphash.Canonical (and the pearl ceremony) compute.
	appHashHex, err := apphash.Canonical(bytes.NewReader(spk), metadata)
	if err != nil {
		t.Fatal(err)
	}
	appHashBytes, err := hash32FromHex(appHashHex)
	if err != nil {
		t.Fatal(err)
	}

	releaseSum := sha256.Sum256([]byte("release manifest bytes"))
	releaseHashHex := hex.EncodeToString(releaseSum[:])

	masterMint, err := primitives.PubkeyFromBase58(masterMintB58)
	if err != nil {
		t.Fatalf("bad test master mint: %v", err)
	}

	relPDA, _, err := pda.Release(masterMint, appHashBytes, programID)
	if err != nil {
		t.Fatal(err)
	}
	licenseMint, err := primitives.PubkeyFromBase58(cfg.LicenseNFTMint)
	if err != nil {
		t.Fatal(err)
	}
	authzPDA, _, err := pda.StoreOperatorAuthorization(licenseMint, primitives.StoreDomainHash(cfg.Domain), programID)
	if err != nil {
		t.Fatal(err)
	}
	storeAuthority, err := primitives.PubkeyFromBase58(cfg.StoreAuthority)
	if err != nil {
		t.Fatalf("bad test store authority: %v", err)
	}
	listingPDA, _, err := pda.StoreReleaseListing(storeAuthority, appHashBytes, programID)
	if err != nil {
		t.Fatal(err)
	}
	appKey, err := primitives.DecodeSandstormAppID(appIDText)
	if err != nil {
		t.Fatal(err)
	}
	blApp, _, err := deriveBlacklistStatusPDA(verify.BlacklistTypeApp, appKey)
	if err != nil {
		t.Fatal(err)
	}
	blLic, _, err := deriveBlacklistStatusPDA(verify.BlacklistTypeLicense, [32]byte(licenseMint))
	if err != nil {
		t.Fatal(err)
	}
	// A stable per-application app_id, DISTINCT from the per-release app_hash, is
	// what the publish gate reads from the on-chain ReleaseEntry to derive the
	// FoundationAppEntry PDA (B1-05/B2-05). It is SHA-256 of the appId text, as
	// the release ceremony registers it.
	appID := sha256.Sum256([]byte(appIDText))
	foundationPDA, _, err := pda.FoundationApp(appID, programID)
	if err != nil {
		t.Fatal(err)
	}

	rel := ReleaseJSON{
		Schema:             "melusina-release-v1",
		AppHash:            appHashHex,
		ReleaseHash:        releaseHashHex,
		Version:            packageMetadata.Version,
		SignedAtUnix:       1700000000,
		MasterNftMint:      masterMintB58,
		LicenseSquadsVault: cfg.ReleaseSquadsAuthority.Vault,
		ReleaseEntryPda:    relPDA.Base58(),
		AuthorSig:          "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111", // placeholder; chain-verified, not re-checked
		QuorumPolicy:       QuorumPolicy{Threshold: defaultBazaarSquadsThreshold, MemberCount: defaultBazaarSquadsMemberCount, MultisigPda: cfg.ReleaseSquadsAuthority.Multisig},
		ReleaseNonce:       "nonce-abc",
	}
	runtimeContract := runtimeContractForTest(t, spk, metadata, rel)
	runtimeContractSum := sha256.Sum256(runtimeContract)
	rel.RuntimeContractSHA256 = hex.EncodeToString(runtimeContractSum[:])
	rel.RuntimeContractSchema = runtimecontract.Schema

	return publishFixture{
		spk:             spk,
		metadata:        metadata,
		runtimeContract: runtimeContract,
		rel:             rel,
		cfg:             cfg,
		masterMint:      masterMint,
		appID:           appID,
		appHashBytes:    appHashBytes,
		relPDA:          relPDA.Base58(),
		authzPDA:        authzPDA.Base58(),
		listingPDA:      listingPDA.Base58(),
		storeAuthority:  storeAuthority,
		foundationPDA:   foundationPDA.Base58(),
		appIDText:       appIDText,
		appKey:          appKey,
		blAppPDA:        blApp.Base58(),
		blLicPDA:        blLic.Base58(),
		licenseMint:     licenseMint,
	}
}
