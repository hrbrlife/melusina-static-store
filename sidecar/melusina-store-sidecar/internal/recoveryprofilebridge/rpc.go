package recoveryprofilebridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

type FinalizedReadback struct {
	Slot uint64
	Core RawAccount
	RawReadback
}

// FetchFinalizedReadback takes one finalized getMultipleAccounts snapshot.
// The five positions are fixed by the signed bridge, never by a caller's
// decoded account claims. A partially missing answer refuses as chain drift.
func FetchFinalizedReadback(ctx context.Context, endpoint string, b Signed, client *http.Client) (FinalizedReadback, error) {
	var zero FinalizedReadback
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		!(parsed.Scheme == "https" || parsed.Scheme == "http" &&
			(parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1")) {
		return zero, ErrChainDrift
	}
	master, err := primitives.PubkeyFromBase58(b.Statement.MasterMint)
	if err != nil {
		return zero, ErrMalformed
	}
	program, err := primitives.PubkeyFromBase58(b.Statement.RegistryProgram)
	if err != nil {
		return zero, ErrMalformed
	}
	trust, _, err := primitives.FindProgramAddress([][]byte{[]byte("installer_release_trust"), master[:]}, program, nil)
	if err != nil {
		return zero, ErrMalformed
	}
	if len(b.Statement.Members) != 3 {
		return zero, ErrMember
	}
	addresses := []string{b.Statement.CoreMultisig, trust.Base58()}
	for _, member := range b.Statement.Members {
		addresses = append(addresses, member.EntryPDA)
	}
	request, err := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Method  string `json:"method"`
		Params  []any  `json:"params"`
	}{"2.0", 1, "getMultipleAccounts", []any{addresses, map[string]any{"encoding": "base64", "commitment": "finalized"}}})
	if err != nil {
		return zero, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(request))
	if err != nil {
		return zero, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	if err := requireRecoveryGenesis(ctx, endpoint, b.Statement.Genesis, client); err != nil {
		return zero, err
	}
	response, err := client.Do(httpRequest)
	if err != nil {
		return zero, fmt.Errorf("%w: %v", ErrChainDrift, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return zero, ErrChainDrift
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(raw) > 1<<20 {
		return zero, ErrChainDrift
	}
	var answer struct {
		Result *struct {
			Context struct {
				Slot uint64 `json:"slot"`
			} `json:"context"`
			Value []*struct {
				Owner string   `json:"owner"`
				Data  []string `json:"data"`
			} `json:"value"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &answer) != nil || answer.Result == nil || answer.Result.Context.Slot == 0 ||
		(len(answer.Error) > 0 && !bytes.Equal(bytes.TrimSpace(answer.Error), []byte("null"))) ||
		len(answer.Result.Value) != len(addresses) {
		return zero, ErrChainDrift
	}
	readback := FinalizedReadback{Slot: answer.Result.Context.Slot, RawReadback: RawReadback{Entries: map[string]RawAccount{}}}
	for i, value := range answer.Result.Value {
		if value == nil || len(value.Data) != 2 || value.Data[1] != "base64" || strings.TrimSpace(value.Owner) == "" {
			return zero, ErrChainDrift
		}
		body, err := base64.StdEncoding.DecodeString(value.Data[0])
		if err != nil || len(body) == 0 || len(body) > 1<<20 {
			return zero, ErrChainDrift
		}
		account := RawAccount{Address: addresses[i], Owner: value.Owner, Data: body}
		switch i {
		case 0:
			readback.Core = account
		case 1:
			readback.Trust = account
		default:
			readback.Entries[b.Statement.Members[i-2].Role] = account
		}
	}
	return readback, nil
}

func requireRecoveryGenesis(ctx context.Context, endpoint, expected string, client *http.Client) error {
	request := []byte(`{"jsonrpc":"2.0","id":1,"method":"getGenesisHash","params":[]}`)
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(request))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := client.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("%w: genesis RPC: %v", ErrChainDrift, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ErrChainDrift
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(raw) > 4096 {
		return ErrChainDrift
	}
	var answer struct {
		Result string          `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &answer) != nil || answer.Result != expected ||
		(len(answer.Error) > 0 && !bytes.Equal(bytes.TrimSpace(answer.Error), []byte("null"))) {
		return ErrChainDrift
	}
	return nil
}

// VerifyFinalizedReadback replaces the council claim with the decoded live
// Squads account before checking the trust and three exact Active entries.
func VerifyFinalizedReadback(b Signed, oldRaw, successorRaw []byte, observed Observation, readback FinalizedReadback) (string, error) {
	if readback.Slot == 0 {
		return "", ErrChainDrift
	}
	profile, err := estateprofile.DecodeProfile(oldRaw)
	if err != nil {
		return "", ErrProfile
	}
	members, threshold, err := VerifyCouncilRaw(profile, b.Statement, readback.Core)
	if err != nil {
		return "", err
	}
	observed.CoreMembers, observed.CoreThreshold = members, threshold
	return VerifyRawReadback(b, oldRaw, successorRaw, observed, readback.RawReadback)
}
