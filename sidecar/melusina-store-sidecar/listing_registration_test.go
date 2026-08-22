package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
)

type recordingListingRegistrar struct {
	events  *[]string
	intent  listingRegistrationIntent
	receipt listingRegistrationReceipt
	err     error
}

func (r *recordingListingRegistrar) EnsureActive(_ context.Context, intent listingRegistrationIntent) (listingRegistrationReceipt, error) {
	if r.events != nil {
		*r.events = append(*r.events, "listing")
	}
	r.intent = intent
	return r.receipt, r.err
}

func listingPublishFixture(t *testing.T) (*publishService, *identity.Private, publishFixture, []byte) {
	t.Helper()
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "listing-registration-store", cfg.LicenseNFTMint, cfg.Domain)
	cfg.StoreAuthority = op.Public().SignPubkeyB58
	fixture := buildValidFixture(t, cfg, randPubkeyB58(t))
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "listing-registration", "app", fixture.metadata)
	chain := newMockChainReader()
	fixture.pinAccept(chain, operatorSignPub32(t, op))
	svc := newTestService(t, cfg, chain, op)
	publisher := newTestIdentity(t, "listing-registration-publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{publisher.Public().SignPubkeyB58}
	svc.listingRegistrationRequired = true
	release := mustJSON(t, fixture.rel)
	stageEnvelope := signPublishForRoute(t, publisher, op.Public(), fixture.spk, release, "/publish/stage", time.Now().UTC(), 5*time.Minute, "listing-registration-stage")
	stage := doStagePublish(t, svc, jsonPublishBody(t, stageEnvelope, release, fixture.spk, fixture.metadata))
	if stage.Code != http.StatusOK {
		t.Fatalf("stage = %d: %s", stage.Code, stage.Body.String())
	}
	return svc, publisher, fixture, release
}

func TestAppPublishListingFailurePreservesCurrentCatalog(t *testing.T) {
	svc, publisher, fixture, release := listingPublishFixture(t)
	before, err := svc.catalogGenerations.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	beforeIndex, err := readSnapshotFileBounded(before, "apps/index.json", maxAppCatalogJSONBytes)
	if err != nil {
		t.Fatal(err)
	}
	events := []string{}
	svc.afterAppMutation = func(step string) error {
		switch step {
		case "after-generation-commit":
			events = append(events, "generation")
		case "after-rollout-commit", "after-current-switch":
			events = append(events, step)
		}
		return nil
	}
	svc.listingRegistrar = &recordingListingRegistrar{events: &events, err: errors.New("operator listing signer is unavailable")}

	promote := signPublishForRoute(t, publisher, svc.operator.Public(), fixture.spk, release, "/publish", time.Now().UTC(), 5*time.Minute, "listing-registration-promote-fails")
	got := doPublish(t, svc, jsonPublishBody(t, promote, release, fixture.spk, fixture.metadata))
	if got.Code != http.StatusBadGateway || !strings.Contains(got.Body.String(), "check=store_release_listing") {
		t.Fatalf("listing failure = %d: %s", got.Code, got.Body.String())
	}
	after, err := svc.catalogGenerations.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if after.ID != before.ID {
		t.Fatalf("listing failure selected %s, want unchanged %s", after.ID, before.ID)
	}
	afterIndex, err := readSnapshotFileBounded(after, "apps/index.json", maxAppCatalogJSONBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterIndex) != string(beforeIndex) {
		t.Fatal("listing failure changed the served catalog bytes")
	}
	if want := []string{"generation", "listing"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("publish ordering = %v, want %v", events, want)
	}
}

func TestAppPublishRegistersListingBeforeCatalogSwitchAndIncludesProof(t *testing.T) {
	svc, publisher, fixture, release := listingPublishFixture(t)
	before, err := svc.catalogGenerations.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	events := []string{}
	svc.afterAppMutation = func(step string) error {
		switch step {
		case "after-generation-commit":
			events = append(events, "generation")
		case "after-rollout-commit":
			events = append(events, "rollout")
		case "after-current-switch":
			events = append(events, "current")
		}
		return nil
	}
	registrar := &recordingListingRegistrar{events: &events, receipt: listingRegistrationReceipt{
		Listing:               "listing-pda",
		ReleaseEntry:          fixture.relPDA,
		StoreAuthority:        svc.cfg.StoreAuthority,
		OperatorAuthorization: fixture.authzPDA,
		TransactionSignature:  "transaction-signature",
	}}
	svc.listingRegistrar = registrar

	promote := signPublishForRoute(t, publisher, svc.operator.Public(), fixture.spk, release, "/publish", time.Now().UTC(), 5*time.Minute, "listing-registration-promote-succeeds")
	got := doPublish(t, svc, jsonPublishBody(t, promote, release, fixture.spk, fixture.metadata))
	if got.Code != http.StatusOK {
		t.Fatalf("publish = %d: %s", got.Code, got.Body.String())
	}
	after, err := svc.catalogGenerations.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if after.ID == before.ID {
		t.Fatal("successful listing registration did not select its prepared catalog")
	}
	if want := []string{"generation", "listing", "rollout", "current"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("publish ordering = %v, want %v", events, want)
	}
	if registrar.intent.StageID == "" || registrar.intent.AppID != metadataAppID(fixture.metadata) || registrar.intent.AppHash != fixture.rel.AppHash || registrar.intent.MasterNFTMint != fixture.rel.MasterNftMint {
		t.Fatalf("registrar received an inexact release intent: %+v", registrar.intent)
	}
	var receipt Receipt
	if err := json.Unmarshal(got.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Listing == nil || receipt.Listing.Listing != "listing-pda" || receipt.Listing.TransactionSignature != "transaction-signature" {
		t.Fatalf("receipt omitted listing proof: %+v", receipt.Listing)
	}
}

func TestAppPublishListingEnforcementRefusesWithoutRegistrarBeforeSwitch(t *testing.T) {
	svc, publisher, fixture, release := listingPublishFixture(t)
	before, err := svc.catalogGenerations.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	promote := signPublishForRoute(t, publisher, svc.operator.Public(), fixture.spk, release, "/publish", time.Now().UTC(), 5*time.Minute, "listing-registration-no-registrar")
	got := doPublish(t, svc, jsonPublishBody(t, promote, release, fixture.spk, fixture.metadata))
	if got.Code != http.StatusServiceUnavailable || !strings.Contains(got.Body.String(), "no bounded registrar") {
		t.Fatalf("missing registrar = %d: %s", got.Code, got.Body.String())
	}
	after, err := svc.catalogGenerations.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if after.ID != before.ID {
		t.Fatalf("missing registrar selected %s, want unchanged %s", after.ID, before.ID)
	}
}

func TestListingRegistrationStateIsStageBound(t *testing.T) {
	state := listingRegistrationState{
		Schema:                listingRegistrationStateSchema,
		StageID:               strings.Repeat("a", 64),
		StoreAuthority:        randPubkeyB58(t),
		LicenseNFTMint:        randPubkeyB58(t),
		StoreDomainHash:       strings.Repeat("b", 64),
		StoreCertFingerprint:  strings.Repeat("c", 64),
		OperatorAuthorization: randPubkeyB58(t),
		Item: listingBootstrapItem{
			AppID:         "test-app",
			AppHash:       strings.Repeat("d", 64),
			ReleaseEntry:  randPubkeyB58(t),
			FoundationApp: randPubkeyB58(t),
			Listing:       randPubkeyB58(t),
			State:         "active",
		},
	}
	path, err := listingRegistrationStatePath(t.TempDir(), state.StageID)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeListingRegistrationState(path, state); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := readListingRegistrationState(path)
	if err != nil || !exists || !reflect.DeepEqual(loaded, state) {
		t.Fatalf("state round trip = exists=%v state=%+v err=%v", exists, loaded, err)
	}
	mutated := state
	mutated.Item.AppHash = strings.Repeat("e", 64)
	if err := mergeListingRegistrationState(&mutated, loaded); err == nil {
		t.Fatal("state for a different exact release was accepted")
	}
	if filepath.Base(path) != listingRegistrationStatePrefix+state.StageID+".json" {
		t.Fatalf("state path %q is not bound to the stage id", path)
	}
}

func TestMergeListingRegistrationStatePreservesPreparedTransaction(t *testing.T) {
	current := listingRegistrationState{
		Schema:                listingRegistrationStateSchema,
		StageID:               strings.Repeat("a", 64),
		StoreAuthority:        randPubkeyB58(t),
		LicenseNFTMint:        randPubkeyB58(t),
		StoreDomainHash:       strings.Repeat("b", 64),
		StoreCertFingerprint:  strings.Repeat("c", 64),
		OperatorAuthorization: randPubkeyB58(t),
		Item: listingBootstrapItem{
			AppID:         "test-app",
			AppHash:       strings.Repeat("d", 64),
			ReleaseEntry:  randPubkeyB58(t),
			FoundationApp: randPubkeyB58(t),
			Listing:       randPubkeyB58(t),
			State:         "pending",
		},
	}
	existing := current
	existing.Item.State = "prepared"
	existing.Item.Attempts = 2
	existing.Item.TransactionSignature = "5Y1QV1yP7ZL9E8zfrDNn2jvLR1MtCiXfH1fKfDQSoA3P"
	existing.Item.RecentBlockhash = randPubkeyB58(t)
	existing.Item.LastError = "transport interrupted after durable prepare"

	if err := mergeListingRegistrationState(&current, existing); err != nil {
		t.Fatalf("mergeListingRegistrationState: %v", err)
	}
	if current.Item.State != "prepared" || current.Item.Attempts != 2 || current.Item.TransactionSignature != existing.Item.TransactionSignature || current.Item.RecentBlockhash != existing.Item.RecentBlockhash || current.Item.LastError != existing.Item.LastError {
		t.Fatalf("prepared transaction provenance was not preserved: %+v", current.Item)
	}
	if err := validateListingRegistrationState(current); err != nil {
		t.Fatalf("merged state rejected: %v", err)
	}
}

func TestBoundedListingRegistrarAcceptsOnlyTheExactExistingListing(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "bounded-listing-store", cfg.LicenseNFTMint, cfg.Domain)
	cfg.StoreAuthority = op.Public().SignPubkeyB58
	cfg.CatalogMigrationStateDir = t.TempDir()
	if err := os.Chmod(cfg.CatalogMigrationStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(t.TempDir(), "store.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("test certificate")}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.TLS.CertPath = certPath
	fixture := buildValidFixture(t, cfg, randPubkeyB58(t))
	chain := newMockChainReader()
	fixture.pinAccept(chain, operatorSignPub32(t, op))
	fixture.pinServeListingActive(chain)

	registrar := newBoundedListingRegistrar(cfg, chain, op)
	if registrar == nil {
		t.Fatal("bounded registrar was not constructed")
	}
	stageID := strings.Repeat("1", 64)
	receipt, err := registrar.EnsureActive(context.Background(), listingRegistrationIntent{
		StageID: stageID, AppID: metadataAppID(fixture.metadata), AppHash: fixture.rel.AppHash, MasterNFTMint: fixture.rel.MasterNftMint,
	})
	if err != nil {
		t.Fatalf("exact active listing refused: %v", err)
	}
	if receipt.Listing != fixture.listingPDA || receipt.ReleaseEntry != fixture.relPDA || receipt.StoreAuthority != cfg.StoreAuthority || receipt.OperatorAuthorization != fixture.authzPDA || receipt.TransactionSignature != "" {
		t.Fatalf("exact listing receipt = %+v", receipt)
	}
	statePath, err := listingRegistrationStatePath(cfg.CatalogMigrationStateDir, stageID)
	if err != nil {
		t.Fatal(err)
	}
	state, exists, err := readListingRegistrationState(statePath)
	if err != nil || !exists || state.Item.State != "active" {
		t.Fatalf("exact active listing was not durably recorded: exists=%v state=%+v err=%v", exists, state, err)
	}

	wrong := chain.storeListing[fixture.listingPDA]
	wrong.appHash = [32]byte{0xff}
	chain.storeListing[fixture.listingPDA] = wrong
	_, err = registrar.EnsureActive(context.Background(), listingRegistrationIntent{
		StageID: stageID, AppID: metadataAppID(fixture.metadata), AppHash: fixture.rel.AppHash, MasterNFTMint: fixture.rel.MasterNftMint,
	})
	if err == nil || !strings.Contains(err.Error(), "exact active target projection") {
		t.Fatalf("mismatched listing was accepted: %v", err)
	}
}
