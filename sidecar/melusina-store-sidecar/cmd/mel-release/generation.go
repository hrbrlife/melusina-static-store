package main

// The signed DesiredGeneration transport, consolidated from cmd/submit-generation.
// mel-release assembles a SINGLE-component GenerationPromoteRequest (target
// scoping: one appId per approve names only that component), signs a v2 publish
// envelope addressed to the configured store operator, POSTs it, then READS BACK
// /update/generation.json and verifies it with the frozen componentrelease.Verify
// (destination-pinned, operator-signature-checked). The store — not this CLI —
// produces and operator-signs the authoritative generation; we only prove our
// component was folded into the served, verified document.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

const (
	generationPromoteSchema = "melusina-generation-promote-v1"
	generationPromoteTarget = "/publish/generation"
	generationServedPath    = "/update/generation.json"
	defaultChainID          = "solana:devnet"
	maxGenerationBytes      = 1 << 20
)

type publisherKeyFile struct {
	Ref      identity.Ref `json:"ref"`
	SignSeed string       `json:"sign_seed_hex"`
	BoxSeed  string       `json:"box_seed_hex"`
}

type generationPromoteRequest struct {
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

// componentFromCandidate rebuilds the frozen componentrelease app entry from the
// immutable candidate — no field is re-derived, so the DesiredGeneration names
// exactly what publish committed to.
func componentFromCandidate(c candidateReceipt) componentrelease.ComponentRelease {
	comp := c.Component
	return componentrelease.ComponentRelease{
		ComponentID:    comp.ComponentID,
		ComponentClass: comp.ComponentClass,
		Version:        c.Version,
		ArtifactName:   comp.ArtifactName,
		SHA256:         comp.SHA256,
		ContentSHA256:  comp.ContentSHA256,
		SizeBytes:      comp.SizeBytes,
		BundleURL:      comp.BundleURL,
		Chain: componentrelease.ChainAuthority{
			Kind:          comp.Chain.Kind,
			Program:       comp.Chain.Program,
			MasterNftMint: comp.Chain.MasterNftMint,
			ReleasePDA:    comp.Chain.ReleasePDA,
		},
		ReleaseHash:     comp.ReleaseHash,
		StageID:         comp.StageID,
		PreviousSHA256:  comp.PreviousSHA256,
		PreviousVersion: comp.PreviousVersion,
	}
}

// submitGeneration promotes the candidate's single component and returns the
// verified served GenerationID/hash. It is the approve-side GENERATED step.
func submitGeneration(c Config, cand candidateReceipt) (uint64, string, error) {
	comp := componentFromCandidate(cand)

	publisher, err := loadPublisherKey(c.PublisherKey)
	if err != nil {
		return 0, "", fmt.Errorf("publisher key: %w", err)
	}
	destination, err := loadStorePubkey(c.StorePubkey)
	if err != nil {
		return 0, "", fmt.Errorf("store pubkey: %w", err)
	}
	operatorKey, err := destination.SignPublicKey()
	if err != nil {
		return 0, "", fmt.Errorf("store public signing key: %w", err)
	}

	timeout := time.Duration(c.OpTimeoutSecs) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client := &http.Client{Timeout: timeout}

	expected, err := fetchCurrentGenerationID(ctx, client, c.StoreURL)
	if err != nil {
		return 0, "", err
	}

	request := generationPromoteRequest{
		Schema:                    generationPromoteSchema,
		Channel:                   c.Channel,
		ExpectedCurrentGeneration: expected,
		Components:                []componentrelease.ComponentRelease{comp},
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return 0, "", err
	}

	ttl := timeout + 2*time.Minute
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
			ProgramID:    firstNonEmpty(publisher.Public().Ref.ProgramID, c.ProgramID),
			VerifiedSlot: 1,
		},
	})
	if err != nil {
		return 0, "", fmt.Errorf("sign promote envelope: %w", err)
	}
	if signed.Payload.Method != http.MethodPost || signed.Payload.Target != generationPromoteTarget {
		return 0, "", errors.New("internal error: signed envelope does not bind POST /publish/generation")
	}

	result, err := postPromote(ctx, client, c.StoreURL, signed, requestBytes)
	if err != nil {
		return 0, "", err
	}

	raw, doc, err := fetchAndVerifyGeneration(ctx, client, c.StoreURL, c.StoreID, operatorKey)
	if err != nil {
		return 0, "", err
	}
	servedSum := sha256.Sum256(raw)
	if result.GenerationID != doc.GenerationID || result.PreviousGeneration != doc.PreviousGeneration ||
		result.GenerationHash != doc.GenerationHash || result.ServedSHA256 != hex.EncodeToString(servedSum[:]) ||
		result.Path != generationServedPath {
		return 0, "", fmt.Errorf("promote response does not bind the verified served generation: %#v", result)
	}
	// Prove OUR component is actually present in the served generation.
	got, ok := doc.Component(comp.ComponentID)
	if !ok {
		return 0, "", fmt.Errorf("served generation does not contain component %q", comp.ComponentID)
	}
	if got.SHA256 != comp.SHA256 || got.ContentSHA256 != comp.ContentSHA256 || got.Version != comp.Version {
		return 0, "", fmt.Errorf("served component %q does not match the candidate binding", comp.ComponentID)
	}
	return doc.GenerationID, doc.GenerationHash, nil
}

func postPromote(ctx context.Context, client *http.Client, store string, signed envelope.Signed, requestBytes []byte) (generationPromoteResult, error) {
	var result generationPromoteResult
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
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxGenerationBytes))
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(store, "/")+generationServedPath, nil)
	if err != nil {
		return nil, zero, err
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return nil, zero, fmt.Errorf("read promoted generation: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxGenerationBytes+1))
	if err != nil {
		return nil, zero, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, zero, fmt.Errorf("promoted generation read-back HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if len(raw) == 0 || len(raw) > maxGenerationBytes {
		return nil, zero, errors.New("promoted generation response is empty or exceeds the bounded size")
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

// fetchCurrentGenerationID reads the currently-served generationId as the CAS
// floor. A 404 (no generation yet) yields 0.
func fetchCurrentGenerationID(ctx context.Context, client *http.Client, store string) (uint64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(store, "/")+generationServedPath, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("read current generation: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxGenerationBytes+1))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return 0, nil
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("current generation read HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var doc struct {
		GenerationID uint64 `json:"generationId"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, fmt.Errorf("decode current generation: %w", err)
	}
	return doc.GenerationID, nil
}

func loadPublisherKey(arg string) (*identity.Private, error) {
	if strings.TrimSpace(arg) == "" {
		return nil, errors.New("MEL_RELEASE_PUBLISHER_KEY is required for approve")
	}
	var raw []byte
	if name, ok := strings.CutPrefix(arg, "env:"); ok {
		value := os.Getenv(name)
		if value == "" {
			return nil, fmt.Errorf("env %s is empty", name)
		}
		raw = []byte(value)
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
