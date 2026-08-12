// Command bootstrap-legacy-manifest authorizes the narrow one-time projection
// from a verified DesiredGeneration to the legacy shell updater manifest.
//
// It does not choose a bundle, write the manifest, or sign as the store. The
// store re-verifies the persisted generation and its installer attestation,
// then produces the projection itself. This command only supplies the
// publisher-signed, purpose-bound request that the endpoint requires.
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
)

const (
	bootstrapSchema = "melusina-legacy-manifest-bootstrap-v1"
	bootstrapTarget = "/publish/legacy-manifest-bootstrap"
)

type publisherKeyFile struct {
	Ref      identity.Ref `json:"ref"`
	SignSeed string       `json:"sign_seed_hex"`
	BoxSeed  string       `json:"box_seed_hex"`
}

type bootstrapRequest struct {
	Schema     string `json:"schema"`
	Generation uint64 `json:"generationId"`
}

type bootstrapBody struct {
	Envelope   envelope.Signed `json:"envelope"`
	RequestB64 string          `json:"request_b64"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap-legacy-manifest:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("bootstrap-legacy-manifest", flag.ContinueOnError)
	store := fs.String("store", "", "HTTPS store base URL (required)")
	operatorPath := fs.String("store-pubkey", "", "store operator identity.Public JSON (required)")
	publisherPath := fs.String("publisher-key", "", "publisher identity JSON (required)")
	generation := fs.Uint64("generation", 0, "already-served DesiredGeneration ID (required)")
	verifiedSlot := fs.Uint64("verified-slot", 0, "publisher finalized chain slot (required)")
	timeout := fs.Duration("timeout", time.Minute, "request timeout")
	envelopeOut := fs.String("envelope-out", "", "write signed request body only; do not contact store")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for name, value := range map[string]string{"--store": *store, "--store-pubkey": *operatorPath, "--publisher-key": *publisherPath} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if *generation == 0 || *verifiedSlot == 0 {
		return errors.New("--generation and --verified-slot must be non-zero")
	}
	u, err := url.Parse(*store)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("--store must be an HTTPS origin")
	}
	if *timeout <= 0 {
		return errors.New("--timeout must be positive")
	}
	publisher, err := loadPublisher(*publisherPath)
	if err != nil {
		return err
	}
	opRaw, err := os.ReadFile(*operatorPath)
	if err != nil {
		return fmt.Errorf("read store public key: %w", err)
	}
	var operator identity.Public
	if err := json.Unmarshal(opRaw, &operator); err != nil || operator.Validate() != nil {
		return errors.New("store public key is not a valid identity.Public document")
	}
	request, err := json.Marshal(bootstrapRequest{Schema: bootstrapSchema, Generation: *generation})
	if err != nil {
		return err
	}
	sum := sha256.Sum256(request)
	signed, err := envelope.Sign(envelope.KindPublishRequest, publisher, operator, envelope.SignOptions{
		Method: http.MethodPost, Target: bootstrapTarget, Body: request,
		BodyHash: hex.EncodeToString(sum[:]), RequestHash: hex.EncodeToString(sum[:]),
		TTL:   5 * time.Minute,
		Chain: envelope.ChainEvidence{ChainID: "solana:devnet", ProgramID: "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb", VerifiedSlot: *verifiedSlot},
	})
	if err != nil {
		return fmt.Errorf("sign bootstrap envelope: %w", err)
	}
	body, err := json.Marshal(bootstrapBody{Envelope: signed, RequestB64: base64.StdEncoding.EncodeToString(request)})
	if err != nil {
		return err
	}
	if *envelopeOut != "" {
		if err := atomicWrite(*envelopeOut, body); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"status": "SIGNED_LEGACY_MANIFEST_BOOTSTRAP_OK", "envelopePath": *envelopeOut, "generationId": *generation})
	}
	ctx, cancel := contextWithTimeout(*timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(*store, "/")+bootstrapTarget, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: *timeout}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	response, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("store returned %s: %s", resp.Status, strings.TrimSpace(string(response)))
	}
	var result struct {
		Status     string `json:"status"`
		Generation uint64 `json:"generationId"`
		Build      int64  `json:"build"`
	}
	if err := json.Unmarshal(response, &result); err != nil || result.Status != "LEGACY_MANIFEST_BOOTSTRAP_OK" || result.Generation != *generation || result.Build <= 0 {
		return errors.New("store returned an invalid bootstrap receipt")
	}
	return json.NewEncoder(out).Encode(result)
}

func loadPublisher(path string) (*identity.Private, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read publisher key: %w", err)
	}
	var key publisherKeyFile
	if err := json.Unmarshal(raw, &key); err != nil {
		return nil, fmt.Errorf("parse publisher key: %w", err)
	}
	sign, err := seed32(key.SignSeed)
	if err != nil {
		return nil, fmt.Errorf("publisher sign seed: %w", err)
	}
	box, err := seed32(key.BoxSeed)
	if err != nil {
		return nil, fmt.Errorf("publisher box seed: %w", err)
	}
	return identity.NewPrivate(key.Ref, sign, box)
}

func seed32(text string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(strings.TrimSpace(text))
	if err != nil || len(raw) != 32 {
		return out, errors.New("must be 32-byte hex")
	}
	copy(out[:], raw)
	return out, nil
}
func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Isolated so tests can replace the clock-bound context policy if needed.
func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
