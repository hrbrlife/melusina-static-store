package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

// getMultipleAccountsLimit is the JSON-RPC server-side cap on addresses per
// getMultipleAccounts call. Requests are chunked to stay under it rather than
// relying on any one provider being lenient.
const getMultipleAccountsLimit = 100

// accountValue is one account slot in a batch answer. present distinguishes
// "the RPC answered, and this account does not exist" — which is a DEFINITIVE
// chain answer that must stay fail-closed — from a transport failure, which is
// retryable. Collapsing those two is how a batch read could silently turn a
// missing PDA into a served app, so they are kept distinct at every layer.
type accountValue struct {
	data    []byte
	present bool
}

type multiAccountReader interface {
	fetchMultipleAccounts(ctx context.Context, addrs []string) ([]accountValue, error)
}

var _ multiAccountReader = (*storeRPCReader)(nil)
var _ multiAccountReader = (*rpcFailoverChainReader)(nil)

type storeMultipleAccountsResponse struct {
	Result *struct {
		Value []*struct {
			Data []string `json:"data"`
		} `json:"value"`
	} `json:"result"`
	Error *storeRPCError `json:"error"`
}

// fetchMultipleAccounts reads many accounts in one round trip, returning one
// slot PER REQUESTED ADDRESS, in order. Error classification is deliberately
// identical to getProgramAccountsByAppID and verify.GetAccountInfo: a transport
// error or any HTTP status >= 400 is wrapped ErrRPCUnreachable (retryable, and
// what makes rpc_fallback_urls engage), while a JSON-RPC error or a malformed
// body is returned as-is and is NOT retried.
func (c *storeRPCReader) fetchMultipleAccounts(ctx context.Context, addrs []string) ([]accountValue, error) {
	out := make([]accountValue, 0, len(addrs))
	for start := 0; start < len(addrs); start += getMultipleAccountsLimit {
		end := start + getMultipleAccountsLimit
		if end > len(addrs) {
			end = len(addrs)
		}
		chunk, err := c.fetchAccountChunk(ctx, addrs[start:end])
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
	}
	return out, nil
}

func (c *storeRPCReader) fetchAccountChunk(ctx context.Context, addrs []string) ([]accountValue, error) {
	req := storeRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "getMultipleAccounts",
		Params: []any{
			addrs,
			map[string]any{"encoding": "base64", "commitment": "confirmed"},
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
	var parsed storeMultipleAccountsResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode getMultipleAccounts response: %w", err)
	}
	if parsed.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", parsed.Error.Code, parsed.Error.Message)
	}
	if parsed.Result == nil {
		return nil, errors.New("getMultipleAccounts response has no result")
	}
	// Positional mapping is the whole contract of this call: slot i IS address i.
	// A length disagreement means the answer cannot be attributed to the requested
	// addresses, so it is refused rather than mis-associated.
	if len(parsed.Result.Value) != len(addrs) {
		return nil, fmt.Errorf("getMultipleAccounts returned %d slots for %d addresses", len(parsed.Result.Value), len(addrs))
	}
	out := make([]accountValue, len(addrs))
	for i, item := range parsed.Result.Value {
		if item == nil {
			out[i] = accountValue{present: false} // definitive: account does not exist
			continue
		}
		if len(item.Data) < 2 || item.Data[1] != "base64" {
			return nil, errors.New("unexpected getMultipleAccounts data shape")
		}
		decoded, err := base64.StdEncoding.DecodeString(item.Data[0])
		if err != nil {
			return nil, fmt.Errorf("base64 decode %s: %w", addrs[i], err)
		}
		out[i] = accountValue{data: decoded, present: true}
	}
	return out, nil
}

// fetchMultipleAccounts mirrors fetchRawAccount's failover loop exactly: advance
// to the next configured endpoint ONLY on ErrRPCUnreachable, honour ctx first,
// pace with the same delay, and end with the same bounded-failure wrap.
// Diverging here would silently change which failures reach the fallback.
func (c *rpcFailoverChainReader) fetchMultipleAccounts(ctx context.Context, addrs []string) ([]accountValue, error) {
	if len(c.multiReaders) != len(c.readers) || len(c.multiReaders) == 0 {
		return nil, errors.New("chain reader does not support batched account reads")
	}
	var transientFailures int
	for readerIndex, reader := range c.multiReaders {
		for attempt := 0; attempt < c.attempts; attempt++ {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			values, err := reader.fetchMultipleAccounts(ctx, addrs)
			if err == nil {
				return values, nil
			}
			if !errors.Is(err, verify.ErrRPCUnreachable) {
				return nil, err
			}
			transientFailures++
			if attempt+1 < c.attempts || readerIndex+1 < len(c.multiReaders) {
				if err := waitForRPCRetry(ctx, c.delay); err != nil {
					return nil, err
				}
			}
		}
	}
	return nil, fmt.Errorf("%w: all configured RPC attempts failed (%d transport failure(s))", verify.ErrRPCUnreachable, transientFailures)
}
