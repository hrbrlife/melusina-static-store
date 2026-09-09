package staging

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func TestAuthorityObserverChecksOriginalPDAOwnerLicenseDomainAndStatus(t *testing.T) {
	license := "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe"
	domain := "bazaar.example"
	master, _ := primitives.PubkeyFromBase58(license)
	hash := primitives.StoreDomainHash(domain)
	data := make([]byte, 193)
	disc := sha256.Sum256([]byte("account:StoreOperatorAuthorization"))
	copy(data[:8], disc[:8])
	copy(data[8:40], master[:])
	copy(data[40:72], hash[:])
	copy(data[72:104], bytes.Repeat([]byte{7}, 32))
	data[142] = 0
	owner := "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"
	var expectedAddress string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.Method != "getAccountInfo" || len(request.Params) != 2 {
			t.Fatal("not a fixed account read")
		}
		var address string
		_ = json.Unmarshal(request.Params[0], &address)
		if address != expectedAddress {
			t.Fatal("authority PDA came from caller")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"context": map[string]any{"slot": 123}, "value": map[string]any{"data": []string{base64.StdEncoding.EncodeToString(data), "base64"}, "owner": owner, "executable": false, "lamports": 1, "rentEpoch": 0}}})
	}))
	defer server.Close()
	observer, err := NewAuthorityObserver(server.URL, license, domain)
	if err != nil {
		t.Fatal(err)
	}
	expectedAddress = observer.authorization
	observer.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	key, gotDomain, err := observer.Observe(t.Context())
	if err != nil || !bytes.Equal(key, bytes.Repeat([]byte{7}, 32)) || gotDomain != hash {
		t.Fatalf("authority: %v", err)
	}
	for _, offset := range []int{0, 8, 40, 142} {
		old := data[offset]
		data[offset] ^= 3
		if _, _, err := observer.Observe(t.Context()); err == nil {
			t.Fatalf("changed authority field %d accepted", offset)
		}
		data[offset] = old
	}
	owner = "11111111111111111111111111111111"
	if _, _, err := observer.Observe(t.Context()); err == nil {
		t.Fatal("foreign program authority accepted")
	}
}
