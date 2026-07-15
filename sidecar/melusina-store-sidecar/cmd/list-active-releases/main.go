// Command list-active-releases enumerates EVERY Active on-chain ReleaseEntry
// for a given app_id — the same getProgramAccounts(memcmp app_id) query
// store_rpc_reader.go's FetchActiveReleaseEntriesByAppID runs — so a revoke
// pass can retire ALL stale entries, not just the one a 409 happened to name.
// verifyReleaseVersionForward (release_version.go) rejects a publish while
// ANY other Active entry exists for the same app_id, so a single missed
// leftover (e.g. an old 0.1.44 nobody remembers) would 409 all over again.
//
// Usage:
//
//	list-active-releases -rpc-url <url> -known-pda <any-known-ReleaseEntry-PDA-for-this-app>
//
// Prints one JSON line per Active entry: {pda, version, appHash}. Read-only —
// makes zero on-chain writes.
package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"bytes"
	"io"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	defaultLicenseProgramID = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"
	releaseEntryAppIDOffset = verify.AccountDiscriminatorLen + 32 + 32
)

type activeEntry struct {
	PDA     string `json:"pda"`
	Version string `json:"version"`
	AppHash string `json:"appHash"`
}

func main() {
	rpcURL := flag.String("rpc-url", "", "Solana JSON-RPC endpoint (required)")
	knownPDA := flag.String("known-pda", "", "any known ReleaseEntry PDA for this app (base58; required — used to read app_id)")
	programIDFlag := flag.String("program-id", defaultLicenseProgramID, "license-registry program id")
	flag.Parse()
	if *rpcURL == "" || *knownPDA == "" {
		fmt.Fprintln(os.Stderr, "usage: list-active-releases -rpc-url <url> -known-pda <pda>")
		os.Exit(2)
	}
	if err := run(*rpcURL, *knownPDA, *programIDFlag); err != nil {
		fmt.Fprintf(os.Stderr, "list-active-releases: %v\n", err)
		os.Exit(1)
	}
}

func run(rpcURL, knownPDA, programIDB58 string) error {
	programID, err := primitives.PubkeyFromBase58(programIDB58)
	if err != nil {
		return fmt.Errorf("bad -program-id: %w", err)
	}
	cr := verify.NewRPCClient(rpcURL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	data, err := cr.GetAccountInfo(ctx, knownPDA)
	if err != nil {
		return fmt.Errorf("fetch known PDA %s: %w", knownPDA, err)
	}
	if data == nil {
		return fmt.Errorf("known PDA %s not found on-chain", knownPDA)
	}
	appID, err := verify.ReadReleaseEntryAppID(data)
	if err != nil {
		return fmt.Errorf("decode app_id from %s: %w", knownPDA, err)
	}
	fmt.Fprintf(os.Stderr, "app_id (base58 of raw bytes): %s\n", primitives.EncodeBase58(appID[:]))

	accounts, err := getProgramAccountsByAppID(ctx, rpcURL, programID.Base58(), appID)
	if err != nil {
		return fmt.Errorf("getProgramAccounts: %w", err)
	}
	entries, err := activeEntries(accounts, appID)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	for _, entry := range entries {
		if err := enc.Encode(entry); err != nil {
			return fmt.Errorf("write active entry: %w", err)
		}
	}
	fmt.Fprintf(os.Stderr, "%d Active ReleaseEntry account(s) found for this app_id\n", len(entries))
	return nil
}

// activeEntries refuses an incomplete RPC result. A caller uses this list to
// decide irreversible revocations, so silently skipping an undecodable account
// would turn a partial chain view into an unsafe "complete" allowlist check.
func activeEntries(accounts []programAccount, appID [32]byte) ([]activeEntry, error) {
	entries := make([]activeEntry, 0, len(accounts))
	for _, acct := range accounts {
		meta, err := readReleaseEntryMinimal(acct.data)
		if err != nil {
			return nil, fmt.Errorf("decode ReleaseEntry %s: %w", acct.pubkey, err)
		}
		if meta.appID != appID || meta.status != verify.AttestationStatusActive {
			continue
		}
		entries = append(entries, activeEntry{PDA: acct.pubkey, Version: meta.version, AppHash: fmt.Sprintf("%x", meta.appHash)})
	}
	return entries, nil
}

type programAccount struct {
	pubkey string
	data   []byte
}

type storeRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type storeRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcProgramAccount struct {
	Pubkey  string `json:"pubkey"`
	Account struct {
		Data []string `json:"data"`
	} `json:"account"`
}

type programAccountsResponse struct {
	// A pointer distinguishes an explicit empty result (a complete, valid chain
	// view) from omitted/null result, which must never authorize revocations.
	Result *[]rpcProgramAccount `json:"result"`
	Error  *storeRPCError       `json:"error,omitempty"`
}

func getProgramAccountsByAppID(ctx context.Context, rpcURL, programIDB58 string, appID [32]byte) ([]programAccount, error) {
	req := storeRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "getProgramAccounts",
		Params: []any{
			programIDB58,
			map[string]any{
				"encoding":   "base64",
				"commitment": "confirmed",
				"filters": []any{
					map[string]any{
						"memcmp": map[string]any{
							"offset": releaseEntryAppIDOffset,
							"bytes":  primitives.EncodeBase58(appID[:]),
						},
					},
				},
			},
		},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var parsed programAccountsResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode response: %w (body=%s)", err, string(raw))
	}
	if parsed.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", parsed.Error.Code, parsed.Error.Message)
	}
	if parsed.Result == nil {
		return nil, errors.New("RPC response omitted or null result")
	}
	return decodeProgramAccounts(*parsed.Result)
}

// decodeProgramAccounts refuses malformed RPC account records. Callers use the
// resulting set as the complete Active-entry view before an irreversible
// revoke, so dropping a record would turn a partial response into a false
// allowlist match.
func decodeProgramAccounts(records []rpcProgramAccount) ([]programAccount, error) {
	out := make([]programAccount, 0, len(records))
	for _, r := range records {
		if r.Pubkey == "" {
			return nil, errors.New("RPC account record has empty pubkey")
		}
		if len(r.Account.Data) != 2 || r.Account.Data[0] == "" || r.Account.Data[1] != "base64" {
			return nil, fmt.Errorf("RPC account %s has missing or malformed base64 data", r.Pubkey)
		}
		decoded, err := decodeBase64(r.Account.Data[0])
		if err != nil {
			return nil, fmt.Errorf("decode RPC account %s base64 data: %w", r.Pubkey, err)
		}
		out = append(out, programAccount{pubkey: r.Pubkey, data: decoded})
	}
	return out, nil
}

type releaseEntryMinimal struct {
	appHash [32]byte
	appID   [32]byte
	version string
	status  verify.AttestationStatus
}

// readReleaseEntryMinimal mirrors store_rpc_reader.go's readReleaseEntryMeta —
// same release_v2 field layout, trimmed to just the fields this ops tool needs
// (appHash/appID/version/status). Kept deliberately self-contained (not
// imported from package main, which is a separate, non-library `main`) rather
// than refactored into a shared internal package, since this is a narrow,
// read-only, one-off enumeration tool for the revoke-then-serve unblock, not
// a new runtime dependency of the server.
func readReleaseEntryMinimal(data []byte) (releaseEntryMinimal, error) {
	var meta releaseEntryMinimal
	offset := verify.AccountDiscriminatorLen
	offset += 32 // master_nft_mint
	if offset+32 > len(data) {
		return meta, errors.New("buffer too short: app_hash")
	}
	copy(meta.appHash[:], data[offset:offset+32])
	offset += 32
	if offset+32 > len(data) {
		return meta, errors.New("buffer too short: app_id")
	}
	copy(meta.appID[:], data[offset:offset+32])
	offset += 32
	offset += 32 // release_hash
	if offset+4 > len(data) {
		return meta, errors.New("buffer too short: version len")
	}
	n := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4
	if n < 0 || offset+n > len(data) {
		return meta, errors.New("buffer too short: version bytes")
	}
	meta.version = string(data[offset : offset+n])
	offset += n
	for _, skip := range []int{32, 32, 64, 32, 32} { // vault, pubkey, sig, payload_hash, registered_by
		offset += skip
	}
	offset += 8 // registered_at
	status, err := verify.ReadAttestationStatusByte(data, offset)
	if err != nil {
		return meta, err
	}
	meta.status = status
	return meta, nil
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
