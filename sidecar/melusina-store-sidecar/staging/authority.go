package staging

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/catalogselection"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// AuthorityObserver preserves cmd/submit's original on-chain receipt authority
// derivation. All routing and scope are service configuration, never receipt
// claims. The registry is the original devnet registry, with no override.
type AuthorityObserver struct {
	client        *http.Client
	endpoint      string
	license       [32]byte
	authorization string
	domain        [32]byte
}

func NewAuthorityObserver(rpcURL, licenseMint, domain string) (*AuthorityObserver, error) {
	u, err := url.Parse(rpcURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("stage authority requires a fixed HTTPS RPC origin")
	}
	if domain == "" || domain != strings.ToLower(domain) || strings.ContainsAny(domain, "/:\\?#@ \r\n\t") {
		return nil, errors.New("stage authority domain is invalid")
	}
	master, err := primitives.PubkeyFromBase58(licenseMint)
	if err != nil {
		return nil, err
	}
	registry, _ := primitives.PubkeyFromBase58("7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb")
	hash := primitives.StoreDomainHash(domain)
	authorization, _, err := pda.StoreOperatorAuthorization(master, hash, registry)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("stage authority refuses RPC redirects") }}
	return &AuthorityObserver{client: client, endpoint: rpcURL, license: master, authorization: authorization.Base58(), domain: hash}, nil
}

func (o *AuthorityObserver) Observe(ctx context.Context) (ed25519.PublicKey, [32]byte, error) {
	if o == nil || o.client == nil {
		return nil, [32]byte{}, errors.New("stage authority observer unavailable")
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "getAccountInfo", "params": []any{o.authorization, map[string]string{"encoding": "base64", "commitment": "finalized"}}})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, [32]byte{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := o.client.Do(request)
	if err != nil {
		return nil, [32]byte{}, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || response.StatusCode != 200 || len(raw) > 64<<10 {
		return nil, [32]byte{}, errors.New("stage authority RPC read failed")
	}
	var reply struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      int             `json:"id"`
		Error   json.RawMessage `json:"error,omitempty"`
		Result  *struct {
			Context struct {
				Slot       uint64 `json:"slot"`
				APIVersion string `json:"apiVersion,omitempty"`
			} `json:"context"`
			Value *struct {
				Data       []string `json:"data"`
				Owner      string   `json:"owner"`
				Executable bool     `json:"executable"`
				Lamports   uint64   `json:"lamports"`
				RentEpoch  uint64   `json:"rentEpoch"`
				Space      uint64   `json:"space,omitempty"`
			} `json:"value"`
		} `json:"result"`
	}
	if catalogselection.DecodeExact(raw, &reply) != nil || reply.JSONRPC != "2.0" || reply.ID != 1 || (len(reply.Error) != 0 && string(reply.Error) != "null") || reply.Result == nil || reply.Result.Context.Slot == 0 || reply.Result.Value == nil {
		return nil, [32]byte{}, errors.New("stage authority RPC response is malformed")
	}
	value := reply.Result.Value
	if value.Owner != "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb" || value.Executable || len(value.Data) != 2 || value.Data[1] != "base64" {
		return nil, [32]byte{}, errors.New("stage authority account owner or encoding differs")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(value.Data[0])
	disc := sha256.Sum256([]byte("account:StoreOperatorAuthorization"))
	if err != nil || len(data) < 185 || len(data) > 193 || base64.StdEncoding.EncodeToString(data) != value.Data[0] || !bytes.Equal(data[:8], disc[:8]) || !bytes.Equal(data[8:40], o.license[:]) || data[136] > 1 {
		return nil, [32]byte{}, errors.New("stage authority account type or license differs")
	}
	authority, err := verify.ReadStoreOperatorAuthz(data)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if authority.Status.RequireActive() != nil || authority.StoreDomainHash != o.domain || authority.StoreAuthority == ([32]byte{}) {
		return nil, [32]byte{}, errors.New("original Store operator authorization is inactive or out of scope")
	}
	return append(ed25519.PublicKey(nil), authority.StoreAuthority[:]...), o.domain, nil
}
