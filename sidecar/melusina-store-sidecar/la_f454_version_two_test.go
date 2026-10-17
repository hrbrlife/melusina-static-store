package main

import (
	"strings"
	"testing"
)

func TestLAF454StoreRendererVersionTwoAndLegacyOne(t *testing.T) {
	profile := storeEstateProfileFixture(t)
	input := storeConfigRenderInput{LicenseNFTMint: profile.Anchors.MasterMint,
		RPCURL: "https://rpc.rehearsal.invalid/v1", RPCAttempts: 1,
		ChainID: "solana:rehearsal", OperatorDomain: "operator.rehearsal.invalid",
		KeyVersion: 2}
	config, err := buildStoreConfigRenderCandidate(profile, input)
	if err != nil {
		t.Fatal(err)
	}
	if config.BootIdentity.KeyVersion != 2 || config.BootIdentity.OperatorKeyVersion != 2 {
		t.Fatal("LA_F454_STORE_V2_RENDER_REVERTED")
	}
	input.KeyVersion = 0 // historical input omitted the new field
	legacy, err := buildStoreConfigRenderCandidate(profile, input)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.BootIdentity.KeyVersion != 1 || legacy.BootIdentity.OperatorKeyVersion != 1 {
		t.Fatal("LA_F454_STORE_V1_LEGACY_REJECTED")
	}
}

func TestLAF454VersionTwoRenderInputAndZeroMutation(t *testing.T) {
	_, profilePath, inputPath, outputPath, input := newStoreConfigRenderFixture(t)
	input["keyVersion"] = 2
	writeStoreConfigRenderInput(t, inputPath, input)
	if _, err := renderEstateStoreConfig(estateStoreConfigRenderOptions{profilePath: profilePath, inputPath: inputPath, outputPath: outputPath}); err != nil {
		t.Fatalf("LA_F454_V2_RENDER_REFUSED: %v", err)
	}
	config, err := LoadConfig(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.BootIdentity.KeyVersion != 2 || config.BootIdentity.OperatorKeyVersion != 2 {
		t.Fatal("LA_F454_V2_RENDER_INPUT_REVERTED")
	}
	input["keyVersion"] = 0
	writeStoreConfigRenderInput(t, inputPath, input)
	if _, err := loadStoreConfigRenderInput(inputPath); err == nil || !strings.Contains(err.Error(), "store-config-render-input-invalid:keyVersion") {
		t.Fatalf("LA_F454_ZERO_VERSION_ACCEPTED: %v", err)
	}
}

func TestLAF454VersionTwoFoundationEscrowAndRestore(t *testing.T) {
	escrow, request, _ := foundationProducerFixtureVersion(t, 2)
	if _, err := sealFoundationEscrow(escrow); err != nil {
		t.Fatalf("LA_F454_V2_ESCROW_REFUSED: %v", err)
	}
	if _, err := signFoundationRestoreRequest(request); err != nil {
		t.Fatalf("LA_F454_V2_RESTORE_REFUSED: %v", err)
	}
}
