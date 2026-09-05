package main

// The host-apply proof needs a small, purpose-specific finalized-RPC surface.
// It deliberately does not widen chainReader: normal Store publish/serve paths
// must not gain an arbitrary transaction-history capability merely because the
// narrowly scoped Fineract migration needs to verify one Squads execution.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

const maxHostApplyRPCResponseBytes = 4 << 20

// hostApplySquadsProofReader is intentionally available only to the host-apply
// proof verifier. The account cohort is obtained at finalized commitment with a
// minContextSlot anchored to the finalized execution transaction, so a proposal
// cannot be paired with unrelated account bytes from an earlier RPC view.
type hostApplySquadsProofReader interface {
	fetchFinalizedHostApplyTransaction(ctx context.Context, signature string) (hostApplyFinalizedTransaction, error)
	fetchFinalizedHostApplyAccounts(ctx context.Context, addresses []string, minContextSlot uint64) (hostApplyFinalizedAccountCohort, error)
}

type hostApplyFinalizedAccount struct {
	Address string
	Owner   string
	Data    []byte
}

type hostApplyFinalizedAccountCohort struct {
	ContextSlot uint64
	Accounts    []hostApplyFinalizedAccount
}

type hostApplyTxHeader struct {
	NumRequiredSignatures       uint8 `json:"numRequiredSignatures"`
	NumReadonlySignedAccounts   uint8 `json:"numReadonlySignedAccounts"`
	NumReadonlyUnsignedAccounts uint8 `json:"numReadonlyUnsignedAccounts"`
}

type hostApplyCompiledInstruction struct {
	ProgramIDIndex uint8   `json:"programIdIndex"`
	Accounts       []uint8 `json:"accounts"`
	Data           string  `json:"data"`
}

type hostApplyInnerInstructionSet struct {
	Index        int                            `json:"index"`
	Instructions []hostApplyCompiledInstruction `json:"instructions"`
}

// hostApplyFinalizedTransaction contains only the exact transcript fields that
// the proof verifier consumes. It is deliberately decoded from RPC's `json`
// form rather than trusting a caller-supplied transaction description.
type hostApplyFinalizedTransaction struct {
	Signature           string
	Signatures          []string
	Slot                uint64
	Failed              bool
	Header              hostApplyTxHeader
	AccountKeys         []string
	Instructions        []hostApplyCompiledInstruction
	InnerInstructions   []hostApplyInnerInstructionSet
	AddressTableLookups int
}

func hostApplyRPCPost(ctx context.Context, endpoint string, client *http.Client, method string, params any, out any) error {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", verify.ErrRPCUnreachable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxHostApplyRPCResponseBytes+1))
	if err != nil {
		return fmt.Errorf("%w: read %s response: %v", verify.ErrRPCUnreachable, method, err)
	}
	if len(raw) > maxHostApplyRPCResponseBytes {
		return fmt.Errorf("%s response exceeds bounded limit", method)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("%w: %s HTTP %d: %s", verify.ErrRPCUnreachable, method, resp.StatusCode, string(raw))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode %s response: %w", method, err)
	}
	return nil
}

func (c *storeRPCReader) fetchFinalizedHostApplyTransaction(ctx context.Context, signature string) (hostApplyFinalizedTransaction, error) {
	var zero hostApplyFinalizedTransaction
	var response struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
		Result *struct {
			Slot uint64 `json:"slot"`
			Meta *struct {
				Err               json.RawMessage                `json:"err"`
				InnerInstructions []hostApplyInnerInstructionSet `json:"innerInstructions"`
			} `json:"meta"`
			Transaction *struct {
				Signatures []string `json:"signatures"`
				Message    *struct {
					Header              hostApplyTxHeader              `json:"header"`
					AccountKeys         []hostApplyRPCAccountKey       `json:"accountKeys"`
					Instructions        []hostApplyCompiledInstruction `json:"instructions"`
					AddressTableLookups []json.RawMessage              `json:"addressTableLookups"`
				} `json:"message"`
			} `json:"transaction"`
		} `json:"result"`
	}
	if err := hostApplyRPCPost(ctx, c.RPCClient.Endpoint, c.RPCClient.HTTPClient, "getTransaction", []any{
		signature, map[string]any{"encoding": "json", "commitment": "finalized", "maxSupportedTransactionVersion": 0},
	}, &response); err != nil {
		return zero, err
	}
	if response.Error != nil {
		return zero, fmt.Errorf("getTransaction RPC error: %s", response.Error.Message)
	}
	if response.Result == nil || response.Result.Meta == nil || response.Result.Transaction == nil || response.Result.Transaction.Message == nil {
		return zero, errors.New("finalized Squads execution transaction is unavailable")
	}
	message := response.Result.Transaction.Message
	out := hostApplyFinalizedTransaction{
		Signature:           signature,
		Signatures:          append([]string(nil), response.Result.Transaction.Signatures...),
		Slot:                response.Result.Slot,
		Header:              message.Header,
		Instructions:        append([]hostApplyCompiledInstruction(nil), message.Instructions...),
		InnerInstructions:   append([]hostApplyInnerInstructionSet(nil), response.Result.Meta.InnerInstructions...),
		AddressTableLookups: len(message.AddressTableLookups),
	}
	if len(response.Result.Meta.Err) != 0 && string(response.Result.Meta.Err) != "null" {
		out.Failed = true
	}
	out.AccountKeys = make([]string, len(message.AccountKeys))
	for i, key := range message.AccountKeys {
		if strings.TrimSpace(key.Pubkey) == "" {
			return zero, fmt.Errorf("getTransaction accountKeys[%d] has no pubkey", i)
		}
		out.AccountKeys[i] = key.Pubkey
	}
	return out, nil
}

// hostApplyRPCAccountKey accepts the documented JSON account-key object. A
// string-only key list is intentionally refused: it is a different RPC shape
// whose signer/writable transcript cannot be independently inspected.
type hostApplyRPCAccountKey struct {
	Pubkey string `json:"pubkey"`
}

func (c *storeRPCReader) fetchFinalizedHostApplyAccounts(ctx context.Context, addresses []string, minContextSlot uint64) (hostApplyFinalizedAccountCohort, error) {
	var zero hostApplyFinalizedAccountCohort
	if len(addresses) == 0 || len(addresses) > 8 {
		return zero, errors.New("invalid finalized Squads account cohort size")
	}
	for _, address := range addresses {
		if strings.TrimSpace(address) == "" {
			return zero, errors.New("finalized Squads account cohort contains an empty address")
		}
	}
	var response struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
		Result *struct {
			Context struct {
				Slot uint64 `json:"slot"`
			} `json:"context"`
			Value []*struct {
				Data  [2]string `json:"data"`
				Owner string    `json:"owner"`
			} `json:"value"`
		} `json:"result"`
	}
	config := map[string]any{"encoding": "base64", "commitment": "finalized", "minContextSlot": minContextSlot}
	if err := hostApplyRPCPost(ctx, c.RPCClient.Endpoint, c.RPCClient.HTTPClient, "getMultipleAccounts", []any{addresses, config}, &response); err != nil {
		return zero, err
	}
	if response.Error != nil {
		return zero, fmt.Errorf("getMultipleAccounts RPC error: %s", response.Error.Message)
	}
	if response.Result == nil || response.Result.Context.Slot < minContextSlot || len(response.Result.Value) != len(addresses) {
		return zero, errors.New("finalized Squads account cohort is absent or predates execution")
	}
	out := hostApplyFinalizedAccountCohort{ContextSlot: response.Result.Context.Slot, Accounts: make([]hostApplyFinalizedAccount, len(addresses))}
	for i, value := range response.Result.Value {
		if value == nil || value.Data[1] != "base64" || strings.TrimSpace(value.Owner) == "" {
			return zero, fmt.Errorf("finalized Squads account %d is absent or malformed", i)
		}
		data, err := base64.StdEncoding.DecodeString(value.Data[0])
		if err != nil {
			return zero, fmt.Errorf("decode finalized Squads account %d: %w", i, err)
		}
		out.Accounts[i] = hostApplyFinalizedAccount{Address: addresses[i], Owner: value.Owner, Data: data}
	}
	return out, nil
}

// The failover wrapper retries this specialized surface only on transport
// failures, preserving the established Store rule that a valid rejection from
// an endpoint is never "healed" by asking another endpoint for a different
// answer.
func (c *rpcFailoverChainReader) fetchFinalizedHostApplyTransaction(ctx context.Context, signature string) (hostApplyFinalizedTransaction, error) {
	var zero hostApplyFinalizedTransaction
	if len(c.readers) == 0 {
		return zero, errors.New("chain reader has no configured endpoints")
	}
	var transientFailures int
	for readerIndex, reader := range c.readers {
		proofReader, ok := reader.(hostApplySquadsProofReader)
		if !ok {
			return zero, errors.New("configured chain reader lacks finalized Squads proof support")
		}
		for attempt := 0; attempt < c.attempts; attempt++ {
			if err := ctx.Err(); err != nil {
				return zero, err
			}
			out, err := proofReader.fetchFinalizedHostApplyTransaction(ctx, signature)
			if err == nil {
				return out, nil
			}
			if !errors.Is(err, verify.ErrRPCUnreachable) {
				return zero, err
			}
			transientFailures++
			if attempt+1 < c.attempts || readerIndex+1 < len(c.readers) {
				if err := waitForRPCRetry(ctx, c.delay); err != nil {
					return zero, err
				}
			}
		}
	}
	return zero, fmt.Errorf("%w: all configured RPC attempts failed (%d transport failure(s))", verify.ErrRPCUnreachable, transientFailures)
}

func (c *rpcFailoverChainReader) fetchFinalizedHostApplyAccounts(ctx context.Context, addresses []string, minContextSlot uint64) (hostApplyFinalizedAccountCohort, error) {
	var zero hostApplyFinalizedAccountCohort
	if len(c.readers) == 0 {
		return zero, errors.New("chain reader has no configured endpoints")
	}
	var transientFailures int
	for readerIndex, reader := range c.readers {
		proofReader, ok := reader.(hostApplySquadsProofReader)
		if !ok {
			return zero, errors.New("configured chain reader lacks finalized Squads proof support")
		}
		for attempt := 0; attempt < c.attempts; attempt++ {
			if err := ctx.Err(); err != nil {
				return zero, err
			}
			out, err := proofReader.fetchFinalizedHostApplyAccounts(ctx, addresses, minContextSlot)
			if err == nil {
				return out, nil
			}
			if !errors.Is(err, verify.ErrRPCUnreachable) {
				return zero, err
			}
			transientFailures++
			if attempt+1 < c.attempts || readerIndex+1 < len(c.readers) {
				if err := waitForRPCRetry(ctx, c.delay); err != nil {
					return zero, err
				}
			}
		}
	}
	return zero, fmt.Errorf("%w: all configured RPC attempts failed (%d transport failure(s))", verify.ErrRPCUnreachable, transientFailures)
}

var _ hostApplySquadsProofReader = (*storeRPCReader)(nil)
var _ hostApplySquadsProofReader = (*rpcFailoverChainReader)(nil)
