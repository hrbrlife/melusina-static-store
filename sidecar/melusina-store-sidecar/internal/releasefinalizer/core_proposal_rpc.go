package releasefinalizer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/squadsproof"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const coreObserverMaxRPCBytes = 8 << 20

func newCoreObserverHTTPClient(endpoint string) (*http.Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("Core observer requires one service-configured bare HTTPS RPC origin")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("Core observer RPC redirects are forbidden")
	}}, nil
}

type coreRPCAccount struct {
	Data       []string `json:"data"`
	Owner      string   `json:"owner"`
	Executable bool     `json:"executable"`
	Lamports   uint64   `json:"lamports"`
	RentEpoch  uint64   `json:"rentEpoch"`
	Space      uint64   `json:"space,omitempty"`
}

type coreRPCReply struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Error   json.RawMessage `json:"error,omitempty"`
	Result  *struct {
		Context struct {
			Slot       uint64 `json:"slot"`
			APIVersion string `json:"apiVersion,omitempty"`
		} `json:"context"`
		Value []*coreRPCAccount `json:"value"`
	} `json:"result"`
}

// readAccounts has one fixed Solana method and at most four derived accounts.
// It never accepts an HTTP method, RPC operation, transaction, bearer token or
// endpoint from a finalization request. The second read is one atomic finalized
// account cohort at least as recent as the discovery read.
func (o *CoreProposalObserver) readAccounts(ctx context.Context, addresses []squadsproof.Pubkey, minSlot uint64) ([]squadsproof.Account, uint64, error) {
	if len(addresses) != 1 && len(addresses) != 4 {
		return nil, 0, errors.New("Core observer account cohort has an invalid size")
	}
	keys := make([]string, len(addresses))
	for i, key := range addresses {
		keys[i] = primitives.EncodeBase58(key[:])
	}
	options := map[string]any{"encoding": "base64", "commitment": "finalized"}
	if minSlot != 0 {
		options["minContextSlot"] = minSlot
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "getMultipleAccounts", "params": []any{keys, options}})
	if err != nil {
		return nil, 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := o.client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	limit := int64(coreObserverMaxRPCBytes)
	if response.StatusCode != http.StatusOK {
		limit = 16 << 10
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(raw)) > limit || response.StatusCode != http.StatusOK {
		return nil, 0, errors.New("Core observer RPC response failed or exceeded its bound")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, 0, errors.New("Core observer RPC response is not JSON")
	}
	if err := exactCoreRPCKeys(raw); err != nil {
		return nil, 0, err
	}
	var reply coreRPCReply
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&reply); err != nil || decoder.Decode(&struct{}{}) != io.EOF || reply.JSONRPC != "2.0" || reply.ID != 1 || (len(reply.Error) != 0 && string(reply.Error) != "null") || reply.Result == nil || reply.Result.Context.Slot == 0 || reply.Result.Context.Slot < minSlot || len(reply.Result.Value) != len(addresses) {
		return nil, 0, errors.New("Core observer RPC response is not the exact finalized account cohort")
	}
	accounts := make([]squadsproof.Account, len(addresses))
	for i, value := range reply.Result.Value {
		accounts[i].Address = addresses[i]
		if value == nil {
			continue
		}
		if value.Executable || len(value.Data) != 2 || value.Data[1] != "base64" {
			return nil, 0, errors.New("Core observer account encoding or executable status is invalid")
		}
		owner, err := squadsproof.DecodePubkey(value.Owner)
		if err != nil {
			return nil, 0, err
		}
		data, err := base64.StdEncoding.Strict().DecodeString(value.Data[0])
		if err != nil || len(data) == 0 || len(data) > 1<<20 || base64.StdEncoding.EncodeToString(data) != value.Data[0] {
			return nil, 0, errors.New("Core observer account data is malformed or oversized")
		}
		accounts[i].Owner, accounts[i].Data = owner, data
	}
	return accounts, reply.Result.Context.Slot, nil
}

// Refuse duplicate keys and aliases before Go's case-insensitive field decoder
// interprets the small RPC vocabulary. This also bounds recursive error input.
func exactCoreRPCKeys(raw []byte) error {
	allowed := map[string]bool{"jsonrpc": true, "id": true, "error": true, "result": true, "context": true, "slot": true, "apiVersion": true, "value": true, "data": true, "owner": true, "executable": true, "lamports": true, "rentEpoch": true, "space": true, "code": true, "message": true}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 24 {
			return errors.New("Core RPC JSON depth exceeded")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]bool)
			for d.More() {
				token, err := d.Token()
				key, ok := token.(string)
				if err != nil || !ok || !allowed[key] || seen[strings.ToLower(key)] {
					return errors.New("Core RPC JSON has unknown, aliased or duplicate fields")
				}
				seen[strings.ToLower(key)] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			if token, err := d.Token(); err != nil || token != json.Delim('}') {
				return errors.New("Core RPC JSON object is malformed")
			}
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			if token, err := d.Token(); err != nil || token != json.Delim(']') {
				return errors.New("Core RPC JSON array is malformed")
			}
		default:
			return errors.New("Core RPC JSON contains an unexpected delimiter")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return errors.New("Core RPC JSON has trailing data")
	}
	return nil
}
