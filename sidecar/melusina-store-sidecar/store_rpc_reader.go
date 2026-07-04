package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const releaseEntryAppIDOffset = verify.AccountDiscriminatorLen + 32 + 32

type storeRPCReader struct {
	*verify.RPCClient
}

func newStoreRPCReader(endpoint string) *storeRPCReader {
	return &storeRPCReader{RPCClient: verify.NewRPCClient(endpoint)}
}

func (c *storeRPCReader) FetchReleaseEntryMeta(ctx context.Context, addr string) (releaseEntryMeta, error) {
	data, err := c.GetAccountInfo(ctx, addr)
	if err != nil {
		return releaseEntryMeta{}, err
	}
	if data == nil {
		return releaseEntryMeta{}, verify.ErrPDANotFound
	}
	meta, err := readReleaseEntryMeta(data)
	if err != nil {
		return releaseEntryMeta{}, err
	}
	meta.PDA = addr
	return meta, nil
}

func (c *storeRPCReader) FetchInstallerReleaseEntryMeta(ctx context.Context, addr string) (installerReleaseMeta, error) {
	data, err := c.GetAccountInfo(ctx, addr)
	if err != nil {
		return installerReleaseMeta{}, err
	}
	if data == nil {
		return installerReleaseMeta{}, verify.ErrPDANotFound
	}
	meta, err := readInstallerReleaseEntryMeta(data)
	if err != nil {
		return installerReleaseMeta{}, err
	}
	meta.PDA = addr
	return meta, nil
}

func (c *storeRPCReader) FetchActiveReleaseEntriesByAppID(ctx context.Context, appID [32]byte) ([]releaseEntryMeta, error) {
	accounts, err := c.getProgramAccountsByAppID(ctx, appID)
	if err != nil {
		return nil, err
	}
	out := make([]releaseEntryMeta, 0, len(accounts))
	for _, acct := range accounts {
		meta, err := readReleaseEntryMeta(acct.Data)
		if err != nil {
			return nil, fmt.Errorf("decode release entry %s: %w", acct.Pubkey, err)
		}
		if meta.AppID != appID {
			continue
		}
		if meta.Status == verify.AttestationStatusActive {
			meta.PDA = acct.Pubkey
			out = append(out, meta)
		}
	}
	return out, nil
}

type programAccount struct {
	Pubkey string
	Data   []byte
}

func (c *storeRPCReader) getProgramAccountsByAppID(ctx context.Context, appID [32]byte) ([]programAccount, error) {
	req := storeRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "getProgramAccounts",
		Params: []any{
			programID.Base58(),
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
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", verify.ErrRPCUnreachable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%w: HTTP %d: %s", verify.ErrRPCUnreachable, resp.StatusCode, string(raw))
	}
	var parsed storeProgramAccountsResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode getProgramAccounts response: %w", err)
	}
	if parsed.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", parsed.Error.Code, parsed.Error.Message)
	}
	out := make([]programAccount, 0, len(parsed.Result))
	for _, item := range parsed.Result {
		if len(item.Account.Data) < 2 || item.Account.Data[1] != "base64" {
			return nil, errors.New("unexpected getProgramAccounts data shape")
		}
		decoded, err := base64.StdEncoding.DecodeString(item.Account.Data[0])
		if err != nil {
			return nil, fmt.Errorf("base64 decode %s: %w", item.Pubkey, err)
		}
		out = append(out, programAccount{Pubkey: item.Pubkey, Data: decoded})
	}
	return out, nil
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

type storeProgramAccountsResponse struct {
	Result []struct {
		Pubkey  string `json:"pubkey"`
		Account struct {
			Data []string `json:"data"`
		} `json:"account"`
	} `json:"result"`
	Error *storeRPCError `json:"error,omitempty"`
}

func readReleaseEntryMeta(data []byte) (releaseEntryMeta, error) {
	var meta releaseEntryMeta
	offset := verify.AccountDiscriminatorLen
	var err error
	if offset, err = skipFixed(data, offset, 32, "release_v2", "master_nft_mint"); err != nil {
		return meta, err
	}
	if offset, err = copyFixed(data, offset, meta.AppHash[:], "release_v2", "app_hash"); err != nil {
		return meta, err
	}
	if offset, err = copyFixed(data, offset, meta.AppID[:], "release_v2", "app_id"); err != nil {
		return meta, err
	}
	if offset, err = skipFixed(data, offset, 32, "release_v2", "release_hash"); err != nil {
		return meta, err
	}
	version, next, err := readBorshStringLocal(data, offset)
	if err != nil {
		return meta, fmt.Errorf("release_v2: version: %w", err)
	}
	meta.Version = version
	offset = next
	for _, step := range []struct {
		name string
		n    int
	}{
		{"publisher_squads_vault", 32},
		{"publisher_ed25519_pubkey", 32},
		{"signature", 64},
		{"signed_payload_hash", 32},
		{"registered_by", 32},
	} {
		if offset, err = skipFixed(data, offset, step.n, "release_v2", step.name); err != nil {
			return meta, err
		}
	}
	// registered_at is the on-chain-WITNESSED attestation time (i64 unix, set by the
	// license program's Clock at register). It is the tamper-proof anchor the publish
	// gate uses to bound the publisher-supplied RELEASE.json signedAtUnix (store
	// hygiene check a); the reader now surfaces it instead of skipping it.
	registeredAt, next, err := readInt64LE(data, offset, "release_v2", "registered_at")
	if err != nil {
		return meta, err
	}
	meta.RegisteredAt = registeredAt
	offset = next
	status, err := verify.ReadAttestationStatusByte(data, offset)
	if err != nil {
		return meta, err
	}
	meta.Status = status
	return meta, nil
}

func readInstallerReleaseEntryMeta(data []byte) (installerReleaseMeta, error) {
	var meta installerReleaseMeta
	offset := verify.AccountDiscriminatorLen
	var err error
	if offset, err = skipFixed(data, offset, 32, "installer_release", "master_nft_mint"); err != nil {
		return meta, err
	}
	if offset, err = copyFixed(data, offset, meta.InstallerHash[:], "installer_release", "installer_hash"); err != nil {
		return meta, err
	}
	version, next, err := readBorshStringLocal(data, offset)
	if err != nil {
		return meta, fmt.Errorf("installer_release: version: %w", err)
	}
	meta.Version = version
	offset = next
	for _, step := range []struct {
		name string
		n    int
	}{
		{"publisher_squads_vault", 32},
		{"registered_by", 32},
		{"registered_at", 8},
	} {
		if offset, err = skipFixed(data, offset, step.n, "installer_release", step.name); err != nil {
			return meta, err
		}
	}
	status, err := verify.ReadAttestationStatusByte(data, offset)
	if err != nil {
		return meta, err
	}
	meta.Status = status
	return meta, nil
}

func skipFixed(data []byte, offset, n int, account, field string) (int, error) {
	if offset+n > len(data) {
		return -1, fmt.Errorf("%s: %s: buffer too short", account, field)
	}
	return offset + n, nil
}

func copyFixed(data []byte, offset int, dst []byte, account, field string) (int, error) {
	if offset+len(dst) > len(data) {
		return -1, fmt.Errorf("%s: %s: buffer too short", account, field)
	}
	copy(dst, data[offset:offset+len(dst)])
	return offset + len(dst), nil
}

// readInt64LE reads a fixed 8-byte little-endian i64 (Borsh/Anchor encoding, e.g.
// an on-chain Clock unix timestamp) at offset, returning the value and the next
// offset. It fails closed when the buffer is too short.
func readInt64LE(data []byte, offset int, account, field string) (int64, int, error) {
	if offset+8 > len(data) {
		return 0, -1, fmt.Errorf("%s: %s: buffer too short", account, field)
	}
	return int64(binary.LittleEndian.Uint64(data[offset : offset+8])), offset + 8, nil
}

func readBorshStringLocal(data []byte, offset int) (string, int, error) {
	if offset+4 > len(data) {
		return "", offset, errors.New("buffer too short for length")
	}
	n := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4
	if n < 0 || offset+n > len(data) {
		return "", offset, errors.New("buffer too short for string bytes")
	}
	return string(data[offset : offset+n]), offset + n, nil
}
