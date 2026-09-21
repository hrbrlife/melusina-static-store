package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// genesisHashReader is intentionally narrower than chainReader. The serving
// path does not need getGenesisHash, while an estate-enroll ceremony does. A
// separate interface keeps existing chainReader fakes valid and makes the new
// trust-root read explicit at its only caller.
type genesisHashReader interface {
	FetchGenesisHash(context.Context) (string, error)
}

// configuredGenesisHashReader additionally proves every explicitly trusted
// endpoint belongs to the same cluster. A normal failover read cannot make
// that assertion because it stops after the first reachable endpoint.
type configuredGenesisHashReader interface {
	FetchConfiguredGenesisHashes(context.Context) ([]string, error)
}

var _ genesisHashReader = (*storeRPCReader)(nil)
var _ genesisHashReader = (*rpcFailoverChainReader)(nil)
var _ configuredGenesisHashReader = (*rpcFailoverChainReader)(nil)

// FetchGenesisHash reads the cluster's immutable identity. A syntactically
// valid JSON-RPC reply is still checked as a canonical 32-byte base58 value so
// a malformed endpoint answer cannot reach an estate-enrollment comparison.
func (c *storeRPCReader) FetchGenesisHash(ctx context.Context) (string, error) {
	req := storeRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "getGenesisHash",
		Params:  []any{},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("%w: %v", verify.ErrRPCUnreachable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return "", fmt.Errorf("%w: HTTP %d: %s", verify.ErrRPCUnreachable, resp.StatusCode, string(raw))
	}
	var parsed storeGenesisHashResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("decode getGenesisHash response: %w", err)
	}
	if parsed.Error != nil {
		return "", fmt.Errorf("rpc error %d: %s", parsed.Error.Code, parsed.Error.Message)
	}
	genesis, err := primitives.PubkeyFromBase58(parsed.Result)
	if err != nil || genesis.Base58() != parsed.Result {
		return "", errors.New("invalid getGenesisHash result")
	}
	return genesis.Base58(), nil
}

// FetchGenesisHash applies the same retry and trusted-fallback rules as every
// other Store chain read. Only transport failures advance to another endpoint;
// a malformed or definitive response remains a refusal from the endpoint that
// supplied it.
func (c *rpcFailoverChainReader) FetchGenesisHash(ctx context.Context) (genesis string, err error) {
	err = c.call(ctx, func(ctx context.Context, reader chainReader) error {
		genesisReader, ok := reader.(genesisHashReader)
		if !ok {
			return errors.New("configured chain reader does not support getGenesisHash")
		}
		genesis, err = genesisReader.FetchGenesisHash(ctx)
		return err
	})
	return genesis, err
}

// FetchConfiguredGenesisHashes checks each configured endpoint independently.
// It retries a transport failure on that endpoint, but never uses another
// endpoint as evidence for it: a fallback that later becomes active must have
// demonstrated the same immutable cluster identity at enrollment/startup.
func (c *rpcFailoverChainReader) FetchConfiguredGenesisHashes(ctx context.Context) ([]string, error) {
	if len(c.readers) == 0 {
		return nil, errors.New("no configured RPC endpoint supports getGenesisHash")
	}
	hashes := make([]string, 0, len(c.readers))
	for index, reader := range c.readers {
		genesisReader, ok := reader.(genesisHashReader)
		if !ok {
			return nil, fmt.Errorf("configured RPC endpoint %d does not support getGenesisHash", index+1)
		}
		var genesis string
		var err error
		for attempt := 0; attempt < c.attempts; attempt++ {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			genesis, err = genesisReader.FetchGenesisHash(ctx)
			if err == nil {
				break
			}
			if !errors.Is(err, verify.ErrRPCUnreachable) {
				return nil, fmt.Errorf("configured RPC endpoint %d getGenesisHash: %w", index+1, err)
			}
			if attempt+1 < c.attempts {
				if err := waitForRPCRetry(ctx, c.delay); err != nil {
					return nil, err
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("configured RPC endpoint %d getGenesisHash: %w", index+1, err)
		}
		hashes = append(hashes, genesis)
	}
	return hashes, nil
}

type storeGenesisHashResponse struct {
	Result string         `json:"result"`
	Error  *storeRPCError `json:"error,omitempty"`
}
