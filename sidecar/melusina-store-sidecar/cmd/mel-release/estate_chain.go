package main

// Chain binding. The chain a release reads and writes is the network of the
// owner-signed estate profile mel-release is bound to (network.genesisHash;
// network.label is display only). MEL_RELEASE_RPC_URL is transport, never
// identity: before any provider-backed subcommand hands it to the governed
// provider, it must serve that genesis. Nothing here compiles a cluster,
// genesis or endpoint, so a rehearsal estate on its own validator and the M2
// devnet estate run the same CLI under their own signed profiles.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Refusal names. Each refusal error starts with its name.
const (
	refusalEstateRPCAbsent     = "estate-rpc-endpoint-absent"
	refusalEstateRPCInvalid    = "estate-rpc-endpoint-invalid"
	refusalEstateGenesisAbsent = "estate-profile-genesis-absent"
	refusalRPCGenesisDiffers   = "rpc-genesis-differs-from-estate-profile"
	maxGenesisResponseBytes    = 64 << 10
)

// rpcGenesisClient never follows a redirect: the endpoint that answers is the
// endpoint the provider will use.
var rpcGenesisClient = &http.Client{
	Timeout: 20 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("estate RPC redirect refused")
	},
}

// subcommandReadsChain reports whether a subcommand reaches the provider and
// therefore the chain. manifest renders a local document only.
func subcommandReadsChain(sub string) bool {
	switch sub {
	case "manifest", "-h", "--help", "help":
		return false
	}
	return true
}

// requireEstateRPCGenesis refuses, by name, an absent or unusable RPC endpoint
// and one that serves any genesis other than the signed profile's. The URL is
// never echoed: an operator's endpoint may carry a provider credential.
func requireEstateRPCGenesis(ctx context.Context, rpcURL string, estate estateBinding, client *http.Client) error {
	if estate.GenesisHash == "" {
		return fmt.Errorf("%s: no owner-signed estate genesis is bound", refusalEstateGenesisAbsent)
	}
	rpcURL = strings.TrimSpace(rpcURL)
	if rpcURL == "" {
		return fmt.Errorf("%s: the estate RPC has no default; name the endpoint that serves the signed profile's genesis", refusalEstateRPCAbsent)
	}
	parsed, err := url.Parse(rpcURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("%s: the estate RPC must be an https endpoint without userinfo or fragment", refusalEstateRPCInvalid)
	}
	if client == nil {
		client = rpcGenesisClient
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"getGenesisHash"}`)))
	if err != nil {
		return fmt.Errorf("%s: %v", refusalEstateRPCInvalid, err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("estate RPC genesis is unreadable: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("estate RPC genesis is unreadable: HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxGenesisResponseBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxGenesisResponseBytes {
		return errors.New("estate RPC genesis response has an invalid size")
	}
	var decoded struct {
		Result string           `json:"result"`
		Error  *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded.Error != nil || decoded.Result == "" {
		return errors.New("estate RPC returned no genesis hash")
	}
	if decoded.Result != estate.GenesisHash {
		return fmt.Errorf("%s: the RPC serves genesis %s; the signed estate profile names %s", refusalRPCGenesisDiffers, decoded.Result, estate.GenesisHash)
	}
	return nil
}
