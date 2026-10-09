// mel-release-endorse produces a detached, profile-pinned app release signature
// after reading the finalized ReleaseEntry from the estate's own chain.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

type rpcResult struct {
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

func callRPC(client *http.Client, origin, method string, params any, target any) error {
	request, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin, bytes.NewReader(request))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ENDORSE_RPC_HTTP_STATUS:%d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var result rpcResult
	if json.Unmarshal(raw, &result) != nil || len(result.Error) != 0 && string(result.Error) != "null" || len(result.Result) == 0 {
		return errors.New("ENDORSE_RPC_RESPONSE_INVALID")
	}
	if err := json.Unmarshal(result.Result, target); err != nil {
		return fmt.Errorf("ENDORSE_RPC_RESPONSE_INVALID:%w", err)
	}
	return nil
}

func keypair(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("ENDORSE_SIGNER_KEY_MODE_REQUIRED")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var numbers []int
	if err := json.Unmarshal(raw, &numbers); err != nil || len(numbers) != 64 {
		return nil, errors.New("ENDORSE_SIGNER_KEYPAIR_INVALID")
	}
	seed := make([]byte, 32)
	for i, value := range numbers {
		if value < 0 || value > 255 {
			return nil, errors.New("ENDORSE_SIGNER_KEYPAIR_INVALID")
		}
		if i < 32 {
			seed[i] = byte(value)
		}
	}
	key := ed25519.NewKeyFromSeed(seed)
	for i := range seed {
		seed[i] = 0
	}
	for i := 32; i < 64; i++ {
		if numbers[i] != int(key[i]) {
			return nil, errors.New("ENDORSE_SIGNER_KEYPAIR_INVALID")
		}
	}
	for i := range numbers {
		numbers[i] = 0
	}
	return key, nil
}

func run() error {
	profilePath := flag.String("estate-profile", "", "owner-signed EstateProfileV1 file")
	profilePin := flag.String("profile-sha256", "", "reviewed profile digest")
	rpcURL := flag.String("rpc-url", "", "profile-pinned chain RPC")
	entryPDA := flag.String("release-entry-pda", "", "finalized app ReleaseEntry PDA")
	signerPath := flag.String("signer-keypair", "", "0600 Solana Ed25519 keypair file")
	outputPath := flag.String("out", "", "new detached endorsement JSON file")
	flag.Parse()
	for _, path := range []string{*profilePath, *signerPath, *outputPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("ENDORSE_ABSOLUTE_CLEAN_PATH_REQUIRED")
		}
	}
	if len(*profilePin) != 64 || strings.ToLower(*profilePin) != *profilePin {
		return errors.New("ENDORSE_PROFILE_PIN_REQUIRED")
	}
	parsed, err := url.Parse(*rpcURL)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Fragment != "" || parsed.RawQuery != "" ||
		!(parsed.Scheme == "https" || parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost")) {
		return errors.New("ENDORSE_RPC_TRANSPORT_INVALID")
	}
	raw, err := os.ReadFile(*profilePath)
	if err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > 1<<20 {
		return errors.New("ENDORSE_PROFILE_BYTES_INVALID")
	}
	profile, err := estateprofile.DecodeProfile(raw)
	if err != nil {
		return err
	}
	digest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		return err
	}
	if digest != *profilePin {
		return errors.New("ENDORSE_SIGNED_PROFILE_PIN_MISMATCH")
	}
	programID := ""
	for _, program := range profile.Programs {
		if program.Role == "license-registry" {
			programID = program.ProgramID
		}
	}
	if programID == "" {
		return errors.New("ENDORSE_REGISTRY_PROGRAM_REQUIRED")
	}
	client := &http.Client{Timeout: 20 * time.Second}
	var genesis string
	if err := callRPC(client, *rpcURL, "getGenesisHash", []any{}, &genesis); err != nil {
		return err
	}
	if genesis != profile.Network.GenesisHash {
		return errors.New("ENDORSE_SIGNED_GENESIS_MISMATCH")
	}
	var account struct {
		Value *struct {
			Owner      string   `json:"owner"`
			Data       []string `json:"data"`
			Executable bool     `json:"executable"`
		} `json:"value"`
	}
	if err := callRPC(client, *rpcURL, "getAccountInfo", []any{*entryPDA, map[string]any{"encoding": "base64", "commitment": "finalized"}}, &account); err != nil {
		return err
	}
	if account.Value == nil || account.Value.Owner != programID || account.Value.Executable || len(account.Value.Data) != 2 || account.Value.Data[1] != "base64" {
		return errors.New("ENDORSE_FINALIZED_RELEASE_ENTRY_REQUIRED")
	}
	entryBytes, err := base64.StdEncoding.Strict().DecodeString(account.Value.Data[0])
	if err != nil {
		return errors.New("ENDORSE_RELEASE_ENTRY_BYTES_INVALID")
	}
	entry, err := releaseentry.Decode(entryBytes)
	if err != nil {
		return err
	}
	master, err := primitives.PubkeyFromBase58(profile.Anchors.MasterMint)
	if err != nil {
		return err
	}
	program, err := primitives.PubkeyFromBase58(programID)
	if err != nil {
		return err
	}
	pda, _, err := primitives.DeriveReleaseV2(master, primitives.Pubkey(entry.AppHash), program)
	if err != nil || pda.Base58() != *entryPDA {
		return errors.New("ENDORSE_RELEASE_ENTRY_PDA_MISMATCH")
	}
	var custodian primitives.Pubkey
	for _, role := range profile.Roles {
		if role.Role == "store-release" {
			custodian, err = primitives.PubkeyFromBase58(role.Vault)
			if err != nil {
				return err
			}
			break
		}
	}
	if custodian == (primitives.Pubkey{}) {
		return errors.New("ENDORSE_RELEASE_CUSTODIAN_REQUIRED")
	}
	keys := make([][32]byte, 0, len(profile.ReleaseTrust.PublisherKeys))
	for _, value := range profile.ReleaseTrust.PublisherKeys {
		key, err := hex.DecodeString(value)
		if err != nil || len(key) != 32 {
			return errors.New("ENDORSE_PROFILE_PUBLISHER_INVALID")
		}
		keys = append(keys, [32]byte(key))
	}
	trust, err := releaseentry.NewTrust([32]byte(master), [32]byte(custodian), keys, profile.ReleaseTrust.Threshold)
	if err != nil {
		return err
	}
	signer, err := keypair(*signerPath)
	if err != nil {
		return err
	}
	var public [32]byte
	copy(public[:], signer.Public().(ed25519.PublicKey))
	endorsement := releaseentry.PublisherSignature{PublicKey: public}
	copy(endorsement.Signature[:], ed25519.Sign(signer, entry.SignedPayloadHash[:]))
	for i := range signer {
		signer[i] = 0
	}
	want := releaseentry.Expectation{AppHash: entry.AppHash, AppID: entry.AppID, ReleaseHash: entry.ReleaseHash, Version: entry.Version}
	if err := trust.AdmitWithSignatures(entry, want, []releaseentry.PublisherSignature{endorsement}); err != nil {
		return err
	}
	document := struct {
		Schema            string `json:"schema"`
		ReleaseEntryPDA   string `json:"releaseEntryPda"`
		SignedPayloadHash string `json:"signedPayloadHash"`
		Signatures        []struct {
			PublisherEd25519PublicKey string `json:"publisherEd25519PublicKey"`
			Signature                 string `json:"signature"`
		} `json:"signatures"`
	}{Schema: "melusina-app-release-endorsements-v1", ReleaseEntryPDA: *entryPDA, SignedPayloadHash: hex.EncodeToString(entry.SignedPayloadHash[:])}
	document.Signatures = append(document.Signatures, struct {
		PublisherEd25519PublicKey string `json:"publisherEd25519PublicKey"`
		Signature                 string `json:"signature"`
	}{hex.EncodeToString(endorsement.PublicKey[:]), hex.EncodeToString(endorsement.Signature[:])})
	bytes, err := json.Marshal(document)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = out.Write(append(bytes, '\n')); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	fmt.Printf("APP_RELEASE_ENDORSEMENT_READY %s %s\n", *entryPDA, hex.EncodeToString(public[:]))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
