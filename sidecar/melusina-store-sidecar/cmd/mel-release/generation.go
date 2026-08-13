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
	generationPromoteSchema   = "melusina-generation-promote-v1"
	generationPromoteTarget   = "/publish/generation"
	generationServedPath      = "/update/generation.json"
	generationReadinessSchema = "melusina-generation-promote-readiness-v1"
	defaultChainID            = "solana:devnet"
	maxGenerationBytes        = 1 << 20
)

// errNoGenerationServed marks a 404 read-back: no generation is served yet, which
// the idempotency probe treats as a clean "component not present" rather than an
// error.
var errNoGenerationServed = errors.New("no generation served")

// errGenerationServeUnavailable marks a fail-closed 503 from the public
// generation surface. It is recoverable only when the Store's separate
// readiness response supplies a locally verified CAS floor; it never makes a
// generic public-endpoint failure safe to ignore.
var errGenerationServeUnavailable = errors.New("generation serve surface unavailable")

type generationPromoteReadiness struct {
	Schema              string  `json:"schema"`
	Status              string  `json:"status"`
	CurrentGenerationID *uint64 `json:"currentGenerationId,omitempty"`
}

// requireGenerationPromotionReady is the publish-side interlock for the two
// command release protocol. A candidate may be privately staged and a Squads
// ReleaseEntry proposal may be created only when the RUNNING store advertises
// that it can complete approve's final signed DesiredGeneration promotion.
// Without this check an old store binary can strand a real chain proposal after
// the approve boundary, which is exactly the half-release the split protocol is
// meant to prevent.
func requireGenerationPromotionReady(c Config) error {
	timeout := time.Duration(c.OpTimeoutSecs) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, err := readGenerationPromotionReadiness(ctx, &http.Client{Timeout: timeout}, c.StoreURL)
	return err
}

// readGenerationPromotionReadiness reads the Store's bounded readiness
// contract. CurrentGenerationID is intentionally optional: it is present only
// when the Store locally verified its persisted signed generation and lets an
// already-authorized release repair a public serve-surface mismatch through the
// normal signed CAS request.
func readGenerationPromotionReadiness(ctx context.Context, client *http.Client, store string) (generationPromoteReadiness, error) {
	var status generationPromoteReadiness
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(store, "/")+generationPromoteTarget, nil)
	if err != nil {
		return status, fmt.Errorf("build generation readiness request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return status, fmt.Errorf("read generation readiness: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil {
		return status, fmt.Errorf("read generation readiness body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return status, fmt.Errorf("store lacks approval-side generation promotion (GET %s: HTTP %d: %s)", generationPromoteTarget, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&status); err != nil {
		return status, fmt.Errorf("decode generation readiness: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return status, errors.New("generation readiness has trailing data")
	}
	if status.Schema != generationReadinessSchema || status.Status != "ready" {
		return status, fmt.Errorf("store returned invalid generation readiness %q/%q", status.Schema, status.Status)
	}
	return status, nil
}

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

// maxGenerationCASAttempts bounds the compare-and-swap retry loop for the case
// where a concurrent app's approve wins the global generation pointer between our
// read of expectedCurrentGeneration and our POST (per-app locks do not serialize
// two different apps).
const maxGenerationCASAttempts = 6

// submitGeneration promotes the candidate's single component and returns the
// verified served GenerationID/hash. It is the approve-side GENERATED step, and
// it is idempotent: if the served, operator-verified generation ALREADY folds
// this exact component (a crash between the store folding it and the WAL
// advancing to GENERATED, or a concurrent promote that already carried it), it
// reuses that generation with NO new POST — it never mints a redundant
// whole-system generation on resume. Concurrent pointer contention is resolved
// by a bounded CAS retry against the refreshed floor.
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
	readiness, err := readGenerationPromotionReadiness(ctx, client, c.StoreURL)
	if err != nil {
		return 0, "", err
	}

	// Idempotent resume/no-op: the served generation is the durable guard. If it
	// already carries our component at the candidate's identity, we are done.
	if gid, ghash, ok, err := servedGenerationHas(ctx, client, c, operatorKey, comp); err != nil {
		if !errors.Is(err, errGenerationServeUnavailable) || readiness.CurrentGenerationID == nil {
			return 0, "", err
		}
	} else if ok {
		return gid, ghash, nil
	}

	var lastConflict error
	for attempt := 0; attempt < maxGenerationCASAttempts; attempt++ {
		expected, recoveryFloor, err := fetchCurrentGenerationID(ctx, client, c.StoreURL, readiness.CurrentGenerationID)
		if err != nil {
			return 0, "", err
		}
		gid, ghash, conflict, err := promoteOnce(ctx, client, c, publisher, destination, operatorKey, comp, expected, recoveryFloor)
		if err == nil {
			return gid, ghash, nil
		}
		if !conflict {
			return 0, "", err
		}
		lastConflict = err
		// Another app advanced the global pointer. If that advance already carried
		// our component we are done; otherwise retry against the fresh floor.
		readiness, err = readGenerationPromotionReadiness(ctx, client, c.StoreURL)
		if err != nil {
			return 0, "", err
		}
		if gid, ghash, ok, err := servedGenerationHas(ctx, client, c, operatorKey, comp); err != nil {
			if !errors.Is(err, errGenerationServeUnavailable) || readiness.CurrentGenerationID == nil {
				return 0, "", err
			}
		} else if ok {
			return gid, ghash, nil
		}
	}
	return 0, "", fmt.Errorf("generation promote did not converge after %d CAS attempts: %w", maxGenerationCASAttempts, lastConflict)
}

// servedGenerationHas fetches and operator-verifies the currently served
// generation and reports whether it already contains comp at the candidate's
// SHA256/ContentSHA256/Version identity. A 404 (no generation served yet) is a
// clean "not present" with no error.
func servedGenerationHas(ctx context.Context, client *http.Client, c Config, operatorKey []byte, comp componentrelease.ComponentRelease) (uint64, string, bool, error) {
	_, doc, err := fetchAndVerifyGeneration(ctx, client, c.StoreURL, c.StoreID, operatorKey)
	if err != nil {
		if errors.Is(err, errNoGenerationServed) {
			return 0, "", false, nil
		}
		return 0, "", false, err
	}
	got, ok := doc.Component(comp.ComponentID)
	if !ok {
		return 0, "", false, nil
	}
	if got.SHA256 != comp.SHA256 || got.ContentSHA256 != comp.ContentSHA256 || got.Version != comp.Version {
		// A DIFFERENT release of the same component is served; we must promote ours.
		return 0, "", false, nil
	}
	return doc.GenerationID, doc.GenerationHash, true, nil
}

// promoteOnce signs and POSTs a single-component promote at the given floor, then
// reads back and verifies the served generation. The bool return is true when the
// failure was a store CAS/lost-update conflict (HTTP 409), which the caller may
// retry against a refreshed floor.
func promoteOnce(ctx context.Context, client *http.Client, c Config, publisher *identity.Private, destination identity.Public, operatorKey []byte, comp componentrelease.ComponentRelease, expected uint64, recoveryFloor bool) (uint64, string, bool, error) {
	request := generationPromoteRequest{
		Schema:                    generationPromoteSchema,
		Channel:                   c.Channel,
		ExpectedCurrentGeneration: expected,
		Components:                []componentrelease.ComponentRelease{comp},
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return 0, "", false, err
	}

	timeout := time.Duration(c.OpTimeoutSecs) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
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
		return 0, "", false, fmt.Errorf("sign promote envelope: %w", err)
	}
	if signed.Payload.Method != http.MethodPost || signed.Payload.Target != generationPromoteTarget {
		return 0, "", false, errors.New("internal error: signed envelope does not bind POST /publish/generation")
	}

	// Superset preservation (audit FIX 4): capture the component set of the
	// generation served at this floor BEFORE the promote, so we can prove the
	// promote folds ours in WITHOUT silently dropping another app's component. A
	// 404 means no prior generation — nothing to preserve. When a verified
	// readiness floor is recovering a deliberately fail-closed 503 surface, the
	// Store itself still re-verifies and folds the persisted generation under its
	// writer lock; public bytes are unavailable to this client until that repair.
	var prevComponentIDs []string
	if recoveryFloor {
		// The normal post-promote read-back below remains mandatory; recovery
		// never reports success from the readiness floor alone.
	} else if _, prevDoc, perr := fetchAndVerifyGeneration(ctx, client, c.StoreURL, c.StoreID, operatorKey); perr == nil {
		prevComponentIDs = make([]string, 0, len(prevDoc.Components))
		for _, pc := range prevDoc.Components {
			prevComponentIDs = append(prevComponentIDs, pc.ComponentID)
		}
	} else if !errors.Is(perr, errNoGenerationServed) {
		return 0, "", false, perr
	}

	result, status, err := postPromote(ctx, client, c.StoreURL, signed, requestBytes)
	if err != nil {
		return 0, "", status == http.StatusConflict, err
	}

	raw, doc, err := fetchAndVerifyGeneration(ctx, client, c.StoreURL, c.StoreID, operatorKey)
	if err != nil {
		return 0, "", false, err
	}
	servedSum := sha256.Sum256(raw)
	if result.GenerationID != doc.GenerationID || result.PreviousGeneration != doc.PreviousGeneration ||
		result.GenerationHash != doc.GenerationHash || result.ServedSHA256 != hex.EncodeToString(servedSum[:]) ||
		result.Path != generationServedPath {
		return 0, "", false, fmt.Errorf("promote response does not bind the verified served generation: %#v", result)
	}
	// Prove OUR component is actually present in the served generation.
	got, ok := doc.Component(comp.ComponentID)
	if !ok {
		return 0, "", false, fmt.Errorf("served generation does not contain component %q", comp.ComponentID)
	}
	if got.SHA256 != comp.SHA256 || got.ContentSHA256 != comp.ContentSHA256 || got.Version != comp.Version {
		return 0, "", false, fmt.Errorf("served component %q does not match the candidate binding", comp.ComponentID)
	}
	// Prove the promote is a strict SUPERSET: every component present before it must
	// still be present (a single-component promote must never drop another app's).
	for _, id := range prevComponentIDs {
		if _, present := doc.Component(id); !present {
			return 0, "", false, fmt.Errorf("promoted generation dropped previously-served component %q (generation superset violated)", id)
		}
	}
	return doc.GenerationID, doc.GenerationHash, false, nil
}

func postPromote(ctx context.Context, client *http.Client, store string, signed envelope.Signed, requestBytes []byte) (generationPromoteResult, int, error) {
	var result generationPromoteResult
	body, err := json.Marshal(generationPromoteBody{Envelope: signed, RequestB64: base64.StdEncoding.EncodeToString(requestBytes)})
	if err != nil {
		return result, 0, fmt.Errorf("marshal promote request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(store, "/")+generationPromoteTarget, bytes.NewReader(body))
	if err != nil {
		return result, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return result, 0, fmt.Errorf("generation promote POST: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxGenerationBytes))
	if err != nil {
		return result, resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		return result, resp.StatusCode, fmt.Errorf("store rejected generation promote: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return result, resp.StatusCode, fmt.Errorf("decode generation promote result: %w", err)
	}
	return result, resp.StatusCode, nil
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
	if resp.StatusCode == http.StatusNotFound {
		return nil, zero, errNoGenerationServed
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, zero, fmt.Errorf("%w: %s", errGenerationServeUnavailable, strings.TrimSpace(string(raw)))
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
// floor. A 404 (no generation yet) yields 0. A 503 is usable only with a
// verified readiness fallback, and the bool reports that exceptional recovery
// path to the caller so it keeps the normal public supersession check intact.
func fetchCurrentGenerationID(ctx context.Context, client *http.Client, store string, fallback *uint64) (uint64, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(store, "/")+generationServedPath, nil)
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return 0, false, fmt.Errorf("read current generation: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxGenerationBytes+1))
	if err != nil {
		return 0, false, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return 0, false, nil
	}
	if resp.StatusCode == http.StatusServiceUnavailable && fallback != nil {
		return *fallback, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return 0, false, fmt.Errorf("current generation read HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var doc struct {
		GenerationID uint64 `json:"generationId"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, false, fmt.Errorf("decode current generation: %w", err)
	}
	return doc.GenerationID, false, nil
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
