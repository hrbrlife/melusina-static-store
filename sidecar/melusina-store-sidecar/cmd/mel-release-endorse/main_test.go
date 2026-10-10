package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease/releasetest"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry/releaseentrytest"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// This test runs the command's real profile verifier, RPC reader, account
// decoder, threshold admission and output writer against a local RPC endpoint.
// The RPC endpoint supplies transport responses only; expected values come
// from the independently signed estate profile and ReleaseEntry fixture.
func TestEndorseProductionPathBindsSignedEstateAndFinalizedEntry(t *testing.T) {
	primary := releasetest.TrustedPublisher()
	additional := releasetest.VectorKey("rehearsal/publisher-2")
	profile := releasetest.LoadProfileVector(t, "../../testdata/estate-profile-vectors.json", releasetest.NewEstateVector)
	profile = releasetest.WithPublishers(t, profile, 2, primary, additional)
	profilePath := releasetest.Write(t, profile)

	master, err := primitives.PubkeyFromBase58(profile.Profile.Anchors.MasterMint)
	if err != nil {
		t.Fatal(err)
	}
	var programID, custodianID string
	for _, program := range profile.Profile.Programs {
		if program.Role == "license-registry" {
			programID = program.ProgramID
		}
	}
	for _, role := range profile.Profile.Roles {
		if role.Role == "store-release" {
			custodianID = role.Vault
		}
	}
	program, err := primitives.PubkeyFromBase58(programID)
	if err != nil {
		t.Fatal(err)
	}
	custodian, err := primitives.PubkeyFromBase58(custodianID)
	if err != nil {
		t.Fatal(err)
	}
	appHash := sha256.Sum256([]byte("endorse-production-path-app"))
	appID := sha256.Sum256([]byte("endorse-production-path-id"))
	releaseHash := sha256.Sum256([]byte("endorse-production-path-release"))
	entry := releaseentrytest.Active([32]byte(master), [32]byte(custodian), appHash, appID, releaseHash, "1.0.0", primary)
	entryBytes := releaseentrytest.Encode(entry)
	pda, _, err := primitives.DeriveReleaseV2(master, primitives.Pubkey(appHash), program)
	if err != nil {
		t.Fatal(err)
	}

	genesis := profile.Profile.Network.GenesisHash
	var genesisReads, accountReads int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/" {
			http.Error(w, "unexpected RPC route", http.StatusBadRequest)
			return
		}
		var call struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&call) != nil {
			http.Error(w, "invalid RPC request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch call.Method {
		case "getGenesisHash":
			genesisReads++
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": genesis})
		case "getAccountInfo":
			accountReads++
			if len(call.Params) != 2 || string(call.Params[0]) != `"`+pda.Base58()+`"` || !strings.Contains(string(call.Params[1]), `"commitment":"finalized"`) {
				http.Error(w, "account lookup not finalized at the derived PDA", http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"value": map[string]any{
				"owner": programID, "data": []string{base64.StdEncoding.EncodeToString(entryBytes), "base64"}, "executable": false,
			}}})
		default:
			http.Error(w, "unexpected RPC method", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "publisher-keypair.json")
	keyNumbers := make([]int, len(additional))
	for i, value := range additional {
		keyNumbers[i] = int(value)
	}
	keyJSON, err := json.Marshal(keyNumbers)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyJSON, 0600); err != nil {
		t.Fatal(err)
	}

	invoke := func(out string) error {
		t.Helper()
		previousArgs, previousFlags := os.Args, flag.CommandLine
		defer func() { os.Args, flag.CommandLine = previousArgs, previousFlags }()
		flag.CommandLine = flag.NewFlagSet("mel-release-endorse-test", flag.ContinueOnError)
		flag.CommandLine.SetOutput(io.Discard)
		os.Args = []string{"mel-release-endorse", "--estate-profile", profilePath, "--profile-sha256", profile.SHA256,
			"--rpc-url", server.URL, "--release-entry-pda", pda.Base58(), "--signer-keypair", keyPath, "--out", out}
		return run()
	}

	output := filepath.Join(dir, "endorsement.json")
	if err := invoke(output); err != nil {
		t.Fatalf("ENDORSE_PRODUCTION_PATH_POSITIVE: %v", err)
	}
	if genesisReads != 1 || accountReads != 1 {
		t.Fatalf("ENDORSE_PRODUCTION_PATH_RPC_CALLS: genesis=%d account=%d", genesisReads, accountReads)
	}
	var document struct {
		Schema            string `json:"schema"`
		ReleaseEntryPDA   string `json:"releaseEntryPda"`
		SignedPayloadHash string `json:"signedPayloadHash"`
		Signatures        []struct {
			PublisherEd25519PublicKey string `json:"publisherEd25519PublicKey"`
			Signature                 string `json:"signature"`
		} `json:"signatures"`
	}
	raw, err := os.ReadFile(output)
	if err != nil || json.Unmarshal(raw, &document) != nil || document.Schema != "melusina-app-release-endorsements-v1" ||
		document.ReleaseEntryPDA != pda.Base58() || document.SignedPayloadHash != hex.EncodeToString(entry.SignedPayloadHash[:]) || len(document.Signatures) != 1 {
		t.Fatalf("ENDORSE_PRODUCTION_PATH_OUTPUT: %v", err)
	}
	public, err := hex.DecodeString(document.Signatures[0].PublisherEd25519PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		t.Fatalf("ENDORSE_PRODUCTION_PATH_PUBLIC_KEY: %v", err)
	}
	signature, err := hex.DecodeString(document.Signatures[0].Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		t.Fatalf("ENDORSE_PRODUCTION_PATH_SIGNATURE: %v", err)
	}
	var endorsement releaseentry.PublisherSignature
	copy(endorsement.PublicKey[:], public)
	copy(endorsement.Signature[:], signature)
	keys := [][32]byte{}
	for _, encoded := range profile.Profile.ReleaseTrust.PublisherKeys {
		decoded, err := hex.DecodeString(encoded)
		if err != nil || len(decoded) != 32 {
			t.Fatal("signed release trust has invalid key")
		}
		keys = append(keys, [32]byte(decoded))
	}
	trust, err := releaseentry.NewTrust([32]byte(master), [32]byte(custodian), keys, profile.Profile.ReleaseTrust.Threshold)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.AdmitWithSignatures(entry, releaseentry.Expectation{AppHash: appHash, AppID: appID, ReleaseHash: releaseHash, Version: "1.0.0"}, []releaseentry.PublisherSignature{endorsement}); err != nil {
		t.Fatalf("ENDORSE_PRODUCTION_PATH_SIGNATURE_ADMISSION: %v", err)
	}
	keyLink := filepath.Join(dir, "publisher-key-link")
	if err := os.Symlink(keyPath, keyLink); err != nil {
		t.Fatal(err)
	}
	if _, err := keypair(keyLink); err == nil || !strings.Contains(err.Error(), "ENDORSE_SIGNER_KEY_MODE_REQUIRED") {
		t.Fatalf("ENDORSE_SIGNER_KEY_SYMLINK_MUTATION_CONTROL: %v", err)
	}

	genesis = "another-genesis"
	refusedOutput := filepath.Join(dir, "wrong-genesis.json")
	if err := invoke(refusedOutput); err == nil || !strings.Contains(err.Error(), "ENDORSE_SIGNED_GENESIS_MISMATCH") {
		t.Fatalf("ENDORSE_SIGNED_GENESIS_MUTATION_CONTROL: %v", err)
	}
	if _, err := os.Lstat(refusedOutput); !os.IsNotExist(err) {
		t.Fatalf("ENDORSE_SIGNED_GENESIS_CREATED_OUTPUT: %v", err)
	}
}
