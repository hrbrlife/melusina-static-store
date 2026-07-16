package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const maxRPCGenesisResponse = 16 << 10

// verifyRPCGenesis binds a write-capable process to the exact cluster named by
// its deployment genesis. It runs before any catalog state is created or read.
func verifyRPCGenesis(ctx context.Context, rpcURL, expected string) error {
	expected = strings.TrimSpace(expected)
	if strings.TrimSpace(rpcURL) == "" || expected == "" {
		return errors.New("rpc_url and cluster_genesis_hash are required")
	}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"getGenesisHash"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("getGenesisHash request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("getGenesisHash HTTP status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRPCGenesisResponse+1))
	if err != nil {
		return err
	}
	if len(raw) > maxRPCGenesisResponse {
		return errors.New("getGenesisHash response exceeds bound")
	}
	var out struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  string `json:"result"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return fmt.Errorf("decode getGenesisHash: %w", err)
	}
	if out.Error != nil {
		return fmt.Errorf("getGenesisHash RPC error %d: %s", out.Error.Code, out.Error.Message)
	}
	if strings.TrimSpace(out.Result) != expected {
		return fmt.Errorf("cluster genesis mismatch: RPC=%q deployment=%q", strings.TrimSpace(out.Result), expected)
	}
	return nil
}
