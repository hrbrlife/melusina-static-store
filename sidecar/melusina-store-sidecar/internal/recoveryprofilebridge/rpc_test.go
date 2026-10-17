package recoveryprofilebridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecoveryBridgeOneFinalizedSlotAndNoMissingAccount(t *testing.T) {
	bridge, _, _, _, raw := rawFixture(t)
	response := func(missing bool) []byte {
		values := make([]any, 5)
		accounts := []RawAccount{{Owner: testAddress("squads"), Data: []byte{1}}, raw.Trust}
		for _, member := range bridge.Statement.Members {
			accounts = append(accounts, raw.Entries[member.Role])
		}
		for i, account := range accounts {
			if missing && i == 4 {
				continue
			}
			values[i] = map[string]any{"owner": account.Owner, "data": []string{base64.StdEncoding.EncodeToString(account.Data), "base64"}}
		}
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "result": map[string]any{"context": map[string]any{"slot": uint64(512168632)}, "value": values}})
		return body
	}
	missing := false
	wrongGenesis := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if request.Method == "getGenesisHash" {
			genesis := bridge.Statement.Genesis
			if wrongGenesis {
				genesis = testAddress("foreign-genesis")
			}
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "result": genesis})
			return
		}
		if request.Method != "getMultipleAccounts" || len(request.Params) != 2 {
			t.Error("unexpected recovery RPC request")
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var options struct {
			Commitment string `json:"commitment"`
			Encoding   string `json:"encoding"`
		}
		if json.Unmarshal(request.Params[1], &options) != nil || options.Commitment != "finalized" || options.Encoding != "base64" {
			t.Error("recovery RPC was not one finalized raw scan")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(response(missing))
	}))
	defer server.Close()
	readback, err := FetchFinalizedReadback(context.Background(), server.URL, bridge, server.Client())
	if err != nil || readback.Slot != 512168632 || len(readback.Entries) != 3 {
		t.Fatalf("finalized scan: %v", err)
	}
	missing = true
	if _, err := FetchFinalizedReadback(context.Background(), server.URL, bridge, server.Client()); !errors.Is(err, ErrChainDrift) {
		t.Fatalf("missing member became a successful scan: %v", err)
	}
	missing, wrongGenesis = false, true
	if _, err := FetchFinalizedReadback(context.Background(), server.URL, bridge, server.Client()); !errors.Is(err, ErrChainDrift) {
		t.Fatalf("foreign genesis became a successful scan: %v", err)
	}
}
