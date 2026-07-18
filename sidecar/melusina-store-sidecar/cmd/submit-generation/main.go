// Command submit-generation is the canonical self-service promote client for a
// typed DesiredGeneration. It never writes a store tree or signs as the store:
// an authorized vertical supplies its component facts, signs a v2 publish
// envelope addressed to the configured store operator, and the store alone
// re-verifies chain facts, CAS-promotes, and operator-signs the served pointer.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

const (
	generationPromoteSchema = "melusina-generation-promote-v1"
	generationPromoteTarget = "/publish/generation"
	defaultChainID          = "solana:devnet"
	defaultProgramID        = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"
	maxRequestBytes         = 1 << 20
)

type publisherKeyFile struct {
	Ref      identity.Ref `json:"ref"`
	SignSeed string       `json:"sign_seed_hex"`
	BoxSeed  string       `json:"box_seed_hex"`
}

// GenerationPromoteRequest mirrors the wire request owned by the store. The
// raw JSON supplied by the publisher is signed exactly as supplied; this type
// is only for fail-closed local preflight before a network request is made.
type GenerationPromoteRequest struct {
	Schema                    string                              `json:"schema"`
	Channel                   string                              `json:"channel"`
	ExpectedCurrentGeneration uint64                              `json:"expectedCurrentGeneration"`
	Components                []componentrelease.ComponentRelease `json:"components"`
}

type generationPromoteBody struct {
	Envelope   envelope.Signed `json:"envelope"`
	RequestB64 string          `json:"request_b64"`
}

type generationPromoteResult struct {
	GenerationID       uint64 `json:"generationId"`
	PreviousGeneration uint64 `json:"previousGeneration"`
	GenerationHash     string `json:"generationHash"`
	ServedSHA256       string `json:"servedSha256"`
	Path               string `json:"path"`
}

type options struct {
	store         string
	storeID       string
	requestPath   string
	publisherKey  string
	storePubkey   string
	verifiedSlot  uint64
	timeout       time.Duration
	generationOut string
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "submit-generation:", err)
		os.Exit(1)
	}
}

func parseFlags(args []string) (options, error) {
	fs := flag.NewFlagSet("submit-generation", flag.ContinueOnError)
	var o options
	fs.StringVar(&o.store, "store", "", "HTTPS store base URL (required)")
	fs.StringVar(&o.storeID, "store-id", "", "pinned store identity/destination for read-back verification (required)")
	fs.StringVar(&o.requestPath, "request", "", "exact GenerationPromoteRequest JSON to sign (required)")
	fs.StringVar(&o.publisherKey, "publisher-key", "", "publisher identity JSON path, or env:NAME (required)")
	fs.StringVar(&o.storePubkey, "store-pubkey", "", "store operator identity.Public JSON (required)")
	fs.Uint64Var(&o.verifiedSlot, "verified-slot", 1, "publisher's verified chain slot (must be nonzero)")
	fs.DurationVar(&o.timeout, "timeout", 60*time.Second, "promote plus read-back timeout")
	fs.StringVar(&o.generationOut, "generation-out", "", "write verified raw served generation JSON atomically to this path")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	var missing []string
	for name, value := range map[string]string{
		"--store": o.store, "--store-id": o.storeID, "--request": o.requestPath,
		"--publisher-key": o.publisherKey, "--store-pubkey": o.storePubkey,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		return o, fmt.Errorf("missing required flag(s): %s", strings.Join(missing, " "))
	}
	if _, err := storeURL(o.store); err != nil {
		return o, err
	}
	if o.verifiedSlot == 0 {
		return o, errors.New("--verified-slot must be greater than zero")
	}
	if o.timeout <= 0 {
		return o, errors.New("--timeout must be positive")
	}
	return o, nil
}

func run(args []string, stdout io.Writer) error {
	o, err := parseFlags(args)
	if err != nil {
		return err
	}
	requestBytes, err := os.ReadFile(o.requestPath)
	if err != nil {
		return fmt.Errorf("read --request: %w", err)
	}
	if len(requestBytes) == 0 || len(requestBytes) > maxRequestBytes {
		return fmt.Errorf("request must be between 1 and %d bytes", maxRequestBytes)
	}
	if _, err := decodeRequest(requestBytes); err != nil {
		return fmt.Errorf("request preflight: %w", err)
	}
	publisher, err := loadPublisherKey(o.publisherKey)
	if err != nil {
		return fmt.Errorf("publisher key: %w", err)
	}
	destination, err := loadStorePubkey(o.storePubkey)
	if err != nil {
		return fmt.Errorf("store pubkey: %w", err)
	}
	ttl := o.timeout + 2*time.Minute
	if ttl < 5*time.Minute {
		ttl = 5 * time.Minute
	}
	sum := sha256.Sum256(requestBytes)
	signed, err := envelope.Sign(envelope.KindPublishRequest, publisher, destination, envelope.SignOptions{
		Method:      http.MethodPost,
		Target:      generationPromoteTarget,
		Body:        requestBytes,
		BodyHash:    hex.EncodeToString(sum[:]),
		RequestHash: hex.EncodeToString(sum[:]),
		TTL:         ttl,
		Chain: envelope.ChainEvidence{
			ChainID:      firstNonEmpty(publisher.Public().Ref.ChainID, defaultChainID),
			ProgramID:    firstNonEmpty(publisher.Public().Ref.ProgramID, defaultProgramID),
			VerifiedSlot: o.verifiedSlot,
		},
	})
	if err != nil {
		return fmt.Errorf("sign promote envelope: %w", err)
	}
	if signed.Payload.Method != http.MethodPost || signed.Payload.Target != generationPromoteTarget {
		return errors.New("internal error: signed envelope does not bind POST /publish/generation")
	}

	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	client := &http.Client{Timeout: o.timeout}
	result, err := postPromote(ctx, client, o.store, signed, requestBytes)
	if err != nil {
		return err
	}
	operatorKey, err := destination.SignPublicKey()
	if err != nil {
		return fmt.Errorf("store public signing key: %w", err)
	}
	raw, doc, err := fetchAndVerifyGeneration(ctx, client, o.store, o.storeID, operatorKey)
	if err != nil {
		return err
	}
	servedSum := sha256.Sum256(raw)
	if result.GenerationID != doc.GenerationID || result.PreviousGeneration != doc.PreviousGeneration ||
		result.GenerationHash != doc.GenerationHash || result.ServedSHA256 != hex.EncodeToString(servedSum[:]) ||
		result.Path != "/update/generation.json" {
		return fmt.Errorf("promote response does not bind the verified served generation: %#v", result)
	}
	if o.generationOut != "" {
		if err := atomicWrite(o.generationOut, raw); err != nil {
			return fmt.Errorf("write verified generation: %w", err)
		}
	}
	return json.NewEncoder(stdout).Encode(map[string]any{
		"status":               "PROMOTE_GENERATION_OK",
		"generationId":         doc.GenerationID,
		"previousGeneration":   doc.PreviousGeneration,
		"generationHash":       doc.GenerationHash,
		"servedSha256":         hex.EncodeToString(servedSum[:]),
		"verifiedStoreId":      o.storeID,
		"verifiedBundleOrigin": doc.BundleOrigin,
	})
}

func postPromote(ctx context.Context, client *http.Client, store string, signed envelope.Signed, requestBytes []byte) (generationPromoteResult, error) {
	var result generationPromoteResult
	if signed.Payload.Method != http.MethodPost || signed.Payload.Target != generationPromoteTarget {
		return result, errors.New("refusing to send an envelope not bound to POST /publish/generation")
	}
	body, err := json.Marshal(generationPromoteBody{Envelope: signed, RequestB64: base64.StdEncoding.EncodeToString(requestBytes)})
	if err != nil {
		return result, fmt.Errorf("marshal promote request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(store, "/")+generationPromoteTarget, bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return result, fmt.Errorf("generation promote POST: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRequestBytes))
	if err != nil {
		return result, err
	}
	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("store rejected generation promote: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return result, fmt.Errorf("decode generation promote result: %w", err)
	}
	return result, nil
}

func fetchAndVerifyGeneration(ctx context.Context, client *http.Client, store, storeID string, operatorKey []byte) ([]byte, componentrelease.DesiredGeneration, error) {
	var zero componentrelease.DesiredGeneration
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(store, "/")+"/update/generation.json", nil)
	if err != nil {
		return nil, zero, err
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return nil, zero, fmt.Errorf("read promoted generation: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRequestBytes+1))
	if err != nil {
		return nil, zero, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, zero, fmt.Errorf("promoted generation read-back HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if len(raw) == 0 || len(raw) > maxRequestBytes {
		return nil, zero, errors.New("promoted generation response is empty or exceeds the bounded size")
	}
	if err := assertNoDuplicateJSONKeys(raw); err != nil {
		return nil, zero, fmt.Errorf("promoted generation duplicate keys: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&zero); err != nil {
		return nil, zero, fmt.Errorf("decode promoted generation: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return nil, zero, errors.New("promoted generation has trailing data")
	}
	if err := componentrelease.Verify(operatorKey, storeID, zero); err != nil {
		return nil, zero, fmt.Errorf("verify promoted generation: %w", err)
	}
	return raw, zero, nil
}

func decodeRequest(raw []byte) (GenerationPromoteRequest, error) {
	var request GenerationPromoteRequest
	if err := assertNoDuplicateJSONKeys(raw); err != nil {
		return request, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil {
		return request, err
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return request, errors.New("unexpected trailing data")
	}
	if request.Schema != generationPromoteSchema {
		return request, fmt.Errorf("schema must be %q", generationPromoteSchema)
	}
	if strings.TrimSpace(request.Channel) == "" || len(request.Components) == 0 {
		return request, errors.New("channel and at least one component are required")
	}
	return request, nil
}

func assertNoDuplicateJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	return scanNoDupKeys(dec)
}

func scanNoDupKeys(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := keyToken.(string)
			if seen[key] {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = true
			if err := scanNoDupKeys(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	case '[':
		for dec.More() {
			if err := scanNoDupKeys(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

func loadPublisherKey(arg string) (*identity.Private, error) {
	var raw []byte
	if name, ok := strings.CutPrefix(arg, "env:"); ok {
		if value := os.Getenv(name); value != "" {
			raw = []byte(value)
		} else {
			return nil, fmt.Errorf("env %s is empty", name)
		}
	} else {
		var err error
		raw, err = os.ReadFile(arg)
		if err != nil {
			return nil, err
		}
	}
	var key publisherKeyFile
	if err := json.Unmarshal(raw, &key); err != nil {
		return nil, err
	}
	signSeed, err := seed32(key.SignSeed)
	if err != nil {
		return nil, fmt.Errorf("sign_seed_hex: %w", err)
	}
	boxSeed, err := seed32(key.BoxSeed)
	if err != nil {
		return nil, fmt.Errorf("box_seed_hex: %w", err)
	}
	return identity.NewPrivate(key.Ref, signSeed, boxSeed)
}

func loadStorePubkey(path string) (identity.Public, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return identity.Public{}, err
	}
	return identity.ParsePublicJSON(raw)
}

func seed32(value string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return out, err
	}
	if len(raw) != len(out) {
		return out, fmt.Errorf("want 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func storeURL(value string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("--store must be a bare HTTPS origin with no userinfo, query, or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("--store must not include a path")
	}
	return u, nil
}

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".generation-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
