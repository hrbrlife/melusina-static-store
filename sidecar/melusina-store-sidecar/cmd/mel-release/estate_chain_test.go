package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

// genesisRPC answers getGenesisHash with genesis and counts every call.
func genesisRPC(t *testing.T, genesis string) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var methods []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		mu.Lock()
		methods = append(methods, request.Method)
		mu.Unlock()
		if request.Method != "getGenesisHash" {
			http.Error(w, "unexpected method", http.StatusTeapot)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": genesis})
	}))
	t.Cleanup(server.Close)
	return server, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), methods...) }
}

func vectorBinding(t *testing.T, name string) estateBinding {
	t.Helper()
	raw, digest := estateVector(t, name)
	var profile estateprofile.EstateProfileV1
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	binding, err := estateBindingOf(profile, digest)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestEstateBindingCarriesTheSignedNetwork(t *testing.T) {
	raw, _ := estateVector(t, newEstateVector)
	var tree struct {
		Network struct {
			Label       string `json:"label"`
			GenesisHash string `json:"genesisHash"`
		} `json:"network"`
	}
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatal(err)
	}
	binding := vectorBinding(t, newEstateVector)
	if binding.GenesisHash == "" || binding.GenesisHash != tree.Network.GenesisHash || binding.Cluster != tree.Network.Label {
		t.Fatalf("binding network %q/%q is not the signed profile's %q/%q", binding.Cluster, binding.GenesisHash, tree.Network.Label, tree.Network.GenesisHash)
	}
}

func TestEstateRPCServingTheSignedGenesisIsAccepted(t *testing.T) {
	binding := vectorBinding(t, newEstateVector)
	server, methods := genesisRPC(t, binding.GenesisHash)
	if err := requireEstateRPCGenesis(context.Background(), server.URL, binding, server.Client()); err != nil {
		t.Fatalf("RPC serving the signed genesis refused: %v", err)
	}
	if got := methods(); len(got) != 1 || got[0] != "getGenesisHash" {
		t.Fatalf("unexpected RPC traffic: %v", got)
	}
}

func TestEstateRPCServingAnotherGenesisIsRefusedByName(t *testing.T) {
	binding := vectorBinding(t, newEstateVector)
	other := vectorBinding(t, "paype-devnet-revision-1")
	if other.GenesisHash == binding.GenesisHash {
		t.Fatal("the two vectors must name different genesis hashes")
	}
	server, _ := genesisRPC(t, other.GenesisHash)
	err := requireEstateRPCGenesis(context.Background(), server.URL, binding, server.Client())
	if err == nil || !strings.HasPrefix(err.Error(), refusalRPCGenesisDiffers) {
		t.Fatalf("RPC serving another genesis was not refused by name: %v", err)
	}
}

func TestEstateRPCAbsentUnsafeOrUnboundIsRefusedByName(t *testing.T) {
	binding := vectorBinding(t, newEstateVector)
	for _, tc := range []struct {
		name, url, want string
		estate          estateBinding
	}{
		{"absent", "", refusalEstateRPCAbsent, binding},
		{"blank", "   ", refusalEstateRPCAbsent, binding},
		{"plain http", "http://127.0.0.1:8899", refusalEstateRPCInvalid, binding},
		{"userinfo", "https://user:secret@rpc.example.test", refusalEstateRPCInvalid, binding},
		{"fragment", "https://rpc.example.test/#x", refusalEstateRPCInvalid, binding},
		{"no signed genesis", "https://rpc.example.test", refusalEstateGenesisAbsent, estateBinding{}},
	} {
		err := requireEstateRPCGenesis(context.Background(), tc.url, tc.estate, http.DefaultClient)
		if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
			t.Fatalf("%s: got %v, want %s", tc.name, err, tc.want)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatalf("%s: refusal echoed the endpoint credential: %v", tc.name, err)
		}
	}
}

func TestOnlyManifestAndHelpSkipTheChain(t *testing.T) {
	for _, sub := range []string{"preflight", "publish", "approve", "repair-catalog", "recover-live", "abandon-init", "reject-proposed"} {
		if !subcommandReadsChain(sub) {
			t.Fatalf("%s must prove the estate RPC genesis", sub)
		}
	}
	for _, sub := range []string{"manifest", "help", "-h", "--help"} {
		if subcommandReadsChain(sub) {
			t.Fatalf("%s reads no chain", sub)
		}
	}
}

// The source carries no chain: neither the former devnet genesis nor the
// devnet endpoint may be compiled into mel-release.
func TestMelReleaseCompilesNoChain(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG", "api.devnet.solana.com"} {
			if strings.Contains(string(raw), forbidden) {
				t.Fatalf("%s compiles %s", name, forbidden)
			}
		}
	}
}
