// Command list-active-releases enumerates EVERY Active on-chain ReleaseEntry
// for a given app_id — the same getProgramAccounts(memcmp app_id) query
// store_rpc_reader.go's FetchActiveReleaseEntriesByAppID runs — so the no-gap
// supersede orchestrator (cmd/publish-supersede) can retire ALL stale entries
// as its FINAL step, not just the one a caller happened to name.
//
// NOTE (card 0055): the app publish gate (release_version.go
// verifyReleaseVersionForward) does NOT require zero other Active entries. It
// permits a bounded 2-Active rollout window and rejects only a submitted
// version that is not strictly greater than some other Active version
// (errSupersedeRequired is enforced on the installer path, not apps). Stale
// entries are therefore retired AFTER the new release is Active AND served
// (promote-first, revoke-last), so an app is never left with zero Active
// releases. An earlier version of this comment wrongly claimed the gate
// "rejects a publish while ANY other Active entry exists" — that false belief
// is exactly what drove the buggy revoke-first ordering.
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
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"bytes"
	"io"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	legacyLicenseProgramID  = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"
	releaseEntryAppIDOffset = verify.AccountDiscriminatorLen + 32 + 32
)

type activeEntry struct {
	PDA     string `json:"pda"`
	Version string `json:"version"`
	AppHash string `json:"appHash"`
}

func main() {
	rpcURL := flag.String("rpc-url", "", "Solana JSON-RPC endpoint (required)")
	knownPDA := flag.String("known-pda", "", "any known ReleaseEntry PDA for this app (use for republish)")
	appIDText := flag.String("app-id", "", "canonical ASCII appId; sha256(appId) is queried (use for zero-state first publish)")
	programIDFlag := flag.String("program-id", "", "fresh license-registry program id (required; no default)")
	genesisHash := flag.String("cluster-genesis-hash", "", "exact getGenesisHash result (required)")
	flag.Parse()
	if *rpcURL == "" || *programIDFlag == "" || *genesisHash == "" || ((*knownPDA == "") == (*appIDText == "")) {
		fmt.Fprintln(os.Stderr, "usage: list-active-releases -rpc-url <url> -program-id <fresh-program> -cluster-genesis-hash <hash> (-known-pda <pda> | -app-id <ascii-app-id>)")
		os.Exit(2)
	}
	if err := run(*rpcURL, *knownPDA, *appIDText, *programIDFlag, *genesisHash); err != nil {
		fmt.Fprintf(os.Stderr, "list-active-releases: %v\n", err)
		os.Exit(1)
	}
}

func run(rpcURL, knownPDA, appIDText, programIDB58, expectedGenesis string) error {
	if programIDB58 == legacyLicenseProgramID {
		return errors.New("legacy program id is refused")
	}
	programID, err := primitives.PubkeyFromBase58(programIDB58)
	if err != nil {
		return fmt.Errorf("bad -program-id: %w", err)
	}
	cr := verify.NewRPCClient(rpcURL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := verifyGenesisHash(ctx, rpcURL, expectedGenesis); err != nil {
		return err
	}

	var appID [32]byte
	if strings.TrimSpace(appIDText) != "" {
		if strings.TrimSpace(appIDText) != appIDText || len(appIDText) > 256 {
			return errors.New("-app-id must be canonical non-whitespace ASCII text <=256 bytes")
		}
		for _, b := range []byte(appIDText) {
			if b < 0x21 || b > 0x7e {
				return errors.New("-app-id must contain printable ASCII without spaces")
			}
		}
		appID = sha256.Sum256([]byte(appIDText))
	} else {
		data, err := cr.GetAccountInfo(ctx, knownPDA)
		if err != nil {
			return fmt.Errorf("fetch known PDA %s: %w", knownPDA, err)
		}
		if data == nil {
			return fmt.Errorf("known PDA %s not found on-chain", knownPDA)
		}
		appID, err = verify.ReadReleaseEntryAppID(data)
		if err != nil {
			return fmt.Errorf("decode app_id from %s: %w", knownPDA, err)
		}
	}
	fmt.Fprintf(os.Stderr, "app_id (base58 of raw bytes): %s\n", primitives.EncodeBase58(appID[:]))

	accounts, err := getProgramAccountsByAppID(ctx, rpcURL, programID.Base58(), appID)
	if err != nil {
		return fmt.Errorf("getProgramAccounts: %w", err)
	}
	enc := json.NewEncoder(os.Stdout)
	found := 0
	for _, acct := range accounts {
		meta, err := readReleaseEntryMinimal(acct.data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: decode error: %v\n", acct.pubkey, err)
			continue
		}
		if meta.appID != appID {
			continue
		}
		if meta.status != verify.AttestationStatusActive {
			continue
		}
		found++
		_ = enc.Encode(activeEntry{PDA: acct.pubkey, Version: meta.version, AppHash: fmt.Sprintf("%x", meta.appHash)})
	}
	fmt.Fprintf(os.Stderr, "%d Active ReleaseEntry account(s) found for this app_id\n", found)
	return nil
}

func verifyGenesisHash(ctx context.Context, rpcURL, expected string) error {
	if _, err := primitives.PubkeyFromBase58(strings.TrimSpace(expected)); err != nil {
		return fmt.Errorf("bad -cluster-genesis-hash: %w", err)
	}
	req := storeRPCRequest{JSONRPC: "2.0", ID: 1, Method: "getGenesisHash"}
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil {
		return err
	}
	var parsed struct {
		Result string         `json:"result"`
		Error  *storeRPCError `json:"error,omitempty"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return err
	}
	if parsed.Error != nil {
		return fmt.Errorf("getGenesisHash RPC error %d: %s", parsed.Error.Code, parsed.Error.Message)
	}
	if strings.TrimSpace(parsed.Result) != strings.TrimSpace(expected) {
		return fmt.Errorf("cluster genesis mismatch: RPC=%q expected=%q", parsed.Result, expected)
	}
	return nil
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

type programAccountsResponse struct {
	Result []struct {
		Pubkey  string `json:"pubkey"`
		Account struct {
			Data []string `json:"data"`
		} `json:"account"`
	} `json:"result"`
	Error *storeRPCError `json:"error,omitempty"`
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
	out := make([]programAccount, 0, len(parsed.Result))
	for _, r := range parsed.Result {
		if len(r.Account.Data) == 0 {
			continue
		}
		decoded, err := decodeBase64(r.Account.Data[0])
		if err != nil {
			continue
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
