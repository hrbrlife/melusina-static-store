package main

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func listingTestPubkey(t *testing.T) pda.Pubkey {
	t.Helper()
	value, err := primitives.PubkeyFromBase58(randPubkeyB58(t))
	if err != nil {
		t.Fatalf("test pubkey: %v", err)
	}
	return value
}

func listingTestState(t *testing.T, itemState string) listingBootstrapState {
	t.Helper()
	return listingBootstrapState{
		Schema:               listingBootstrapStateSchema,
		State:                "registering",
		SnapshotID:           "generation-test",
		IndexSHA256:          strings.Repeat("a", 64),
		ExpectedAppCount:     1,
		StoreAuthority:       listingTestPubkey(t).Base58(),
		LicenseNFTMint:       listingTestPubkey(t).Base58(),
		ProgramID:            listingTestPubkey(t).Base58(),
		StoreDomainHash:      strings.Repeat("b", 64),
		StoreCertFingerprint: strings.Repeat("c", 64),
		Items: []listingBootstrapItem{{
			AppID:         "listing-test",
			PackageID:     strings.Repeat("e", 32),
			AppHash:       strings.Repeat("d", 64),
			ReleaseEntry:  listingTestPubkey(t).Base58(),
			FoundationApp: listingTestPubkey(t).Base58(),
			Listing:       listingTestPubkey(t).Base58(),
			State:         itemState,
		}},
	}
}

func TestMergeListingBootstrapStatePreservesPreparedTransaction(t *testing.T) {
	current := listingTestState(t, "pending")
	existing := current
	existing.Items[0].State = "prepared"
	existing.Items[0].Attempts = 2
	existing.Items[0].TransactionSignature = "4Y1QV1yP7ZL9E8zfrDNn2jvLR1MtCiXfH1fKfDQSoA3P"
	existing.Items[0].RecentBlockhash = listingTestPubkey(t).Base58()
	existing.Items[0].LastError = "transport interrupted after durable prepare"

	if err := mergeListingBootstrapState(&current, existing); err != nil {
		t.Fatalf("mergeListingBootstrapState: %v", err)
	}
	got := current.Items[0]
	if got.State != "prepared" || got.Attempts != 2 || got.TransactionSignature != existing.Items[0].TransactionSignature || got.RecentBlockhash != existing.Items[0].RecentBlockhash || got.LastError != existing.Items[0].LastError {
		t.Fatalf("prepared transaction provenance was not preserved: %+v", got)
	}
	if err := validateListingBootstrapState(current); err != nil {
		t.Fatalf("merged state rejected: %v", err)
	}
}

func TestValidateListingBootstrapStateRejectsIncompleteTerminalState(t *testing.T) {
	state := listingTestState(t, "pending")
	state.State = "registered"
	if err := validateListingBootstrapState(state); err == nil || !strings.Contains(err.Error(), "non-active") {
		t.Fatalf("registered state with pending listing accepted: %v", err)
	}

	state.Items[0].State = "active"
	state.State = "activated"
	if err := validateListingBootstrapState(state); err == nil || !strings.Contains(err.Error(), "activation hashes") {
		t.Fatalf("activated state without config evidence accepted: %v", err)
	}
}

func TestBuildRegisterStoreReleaseListingTransactionBindsProvidedAuthorization(t *testing.T) {
	operator := newTestIdentity(t, "store", randPubkeyB58(t), "store.example.org")
	storeAuthority := pda.Pubkey(operatorSignPub32(t, operator))
	listing := listingTestPubkey(t)
	release := listingTestPubkey(t)
	authorization := listingTestPubkey(t)
	foundation := listingTestPubkey(t)
	licenseMint := listingTestPubkey(t)
	var appHash, domainHash, certFingerprint, blockhash [32]byte
	for index := range appHash {
		appHash[index] = byte(index + 1)
		domainHash[index] = byte(index + 2)
		certFingerprint[index] = byte(index + 3)
		blockhash[index] = byte(index + 4)
	}

	wire, signature, err := buildRegisterStoreReleaseListingTransaction(operator, storeAuthority, listing, release, authorization, foundation, licenseMint, appHash, domainHash, certFingerprint, blockhash)
	if err != nil {
		t.Fatalf("build transaction: %v", err)
	}
	if len(wire) < 65 || wire[0] != 1 || signature == "" {
		t.Fatalf("unexpected transaction envelope: len=%d signature=%q", len(wire), signature)
	}
	message := wire[65:]
	if !operator.Public().Verify(message, wire[1:65]) {
		t.Fatal("transaction is not signed by the boot-bound operator")
	}
	if len(message) < 4 || message[0] != 1 || message[1] != 0 || message[2] != 5 || message[3] != 7 {
		t.Fatalf("unexpected legacy message header: %x", message[:4])
	}
	wantAccounts := []pda.Pubkey{storeAuthority, listing, release, authorization, foundation}
	for index, want := range wantAccounts {
		offset := 4 + index*32
		if !bytes.Equal(message[offset:offset+32], want[:]) {
			t.Fatalf("account %d did not bind the expected key", index)
		}
	}

	// Header + seven account keys + recent blockhash + one instruction. The
	// account-index order is the exact Anchor RegisterStoreReleaseListing order.
	offset := 4 + 7*32 + 32
	if message[offset] != 1 || message[offset+1] != 6 || message[offset+2] != 6 {
		t.Fatalf("unexpected instruction layout at %d: %x", offset, message[offset:offset+3])
	}
	if got, want := message[offset+3:offset+9], []byte{1, 2, 3, 4, 0, 5}; !bytes.Equal(got, want) {
		t.Fatalf("instruction account order = %v, want %v", got, want)
	}
	dataOffset := offset + 11 // program + account-count + six indices + shortvec(136)
	if len(message) < dataOffset+8 {
		t.Fatal("transaction lacks instruction data")
	}
	discriminator := sha256.Sum256([]byte("global:register_store_release_listing"))
	if !bytes.Equal(message[dataOffset:dataOffset+8], discriminator[:8]) {
		t.Fatal("transaction has the wrong Anchor instruction discriminator")
	}
}
