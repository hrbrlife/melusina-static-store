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

var _ genesisHashReader = (*storeRPCReader)(nil)
var _ genesisHashReader = (*rpcFailoverChainReader)(nil)

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

type storeGenesisHashResponse struct {
	Result string         `json:"result"`
	Error  *storeRPCError `json:"error,omitempty"`
}
