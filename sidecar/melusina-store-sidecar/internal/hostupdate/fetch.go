package hostupdate

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

// maxGenerationBytes bounds the fetched desired-generation document. A generation
// is small typed JSON (component metadata, not artifacts); a lying origin cannot
// exhaust the controller's memory.
const maxGenerationBytes = 1 << 20 // 1 MiB

// FetchOptions pins everything the controller trusts about the store from its OWN
// config — never from the fetched document. The authorized operator key and the
// store identity are what make a foreign or tampered generation fail closed.
type FetchOptions struct {
	// URL is the desired-generation endpoint (…/update/generation.json). It MUST be
	// under ExpectedBundleOrigin — the controller does not follow a redirect or
	// fetch from an arbitrary host (the injected getter is no-redirect).
	URL string
	// ExpectedStoreID is the controller's pinned store identity (destination).
	ExpectedStoreID string
	// ExpectedBundleOrigin is the controller's pinned store origin; the fetched
	// document's bundleOrigin AND the fetch URL must both be under it.
	ExpectedBundleOrigin string
	// AuthorizedOperator is the store operator ed25519 key the target trusts,
	// pinned in controller config — the signer the generation must match.
	AuthorizedOperator ed25519.PublicKey
}

// FetchAndVerifyGeneration fetches the signed desired generation and returns it
// ONLY if it fully verifies against the controller's pinned trust anchors. It is
// fail-closed at every step and never trusts a field of the document to decide
// whether to trust the document:
//   - the fetch URL must be under the pinned origin (no off-origin fetch);
//   - the body is size-bounded and strictly decoded (unknown field, duplicate
//     key, or trailing data are refused — a downstream parser cannot be tricked);
//   - componentrelease.Verify checks the operator signature, the destination
//     storeId, and the canonical generationHash;
//   - the document's bundleOrigin must equal the pinned origin.
func FetchAndVerifyGeneration(ctx context.Context, get componentrelease.HTTPGetter, opts FetchOptions) (componentrelease.DesiredGeneration, error) {
	var zero componentrelease.DesiredGeneration
	origin := strings.TrimRight(strings.TrimSpace(opts.ExpectedBundleOrigin), "/")
	if origin == "" {
		return zero, errors.New("no pinned bundle origin")
	}
	if strings.TrimSpace(opts.ExpectedStoreID) == "" {
		return zero, errors.New("no pinned storeId")
	}
	if len(opts.AuthorizedOperator) != ed25519.PublicKeySize {
		return zero, errors.New("no pinned operator key")
	}
	if !strings.HasPrefix(opts.URL, origin+"/") {
		return zero, fmt.Errorf("generation URL %q is not under the pinned origin %q", opts.URL, origin)
	}
	if get == nil {
		return zero, errors.New("no generation fetcher")
	}

	rc, err := get(ctx, opts.URL)
	if err != nil {
		return zero, fmt.Errorf("fetch generation: %w", err)
	}
	defer rc.Close()
	body, err := io.ReadAll(io.LimitReader(rc, maxGenerationBytes+1))
	if err != nil {
		return zero, fmt.Errorf("read generation: %w", err)
	}
	if int64(len(body)) > maxGenerationBytes {
		return zero, fmt.Errorf("generation exceeds %d bytes", maxGenerationBytes)
	}

	if err := assertNoDuplicateJSONKeys(body); err != nil {
		return zero, fmt.Errorf("generation: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	var doc componentrelease.DesiredGeneration
	if err := dec.Decode(&doc); err != nil {
		return zero, fmt.Errorf("decode generation: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return zero, errors.New("generation has unexpected trailing data")
	}

	if err := componentrelease.Verify(opts.AuthorizedOperator, opts.ExpectedStoreID, doc); err != nil {
		return zero, fmt.Errorf("verify generation: %w", err)
	}
	if strings.TrimRight(strings.TrimSpace(doc.BundleOrigin), "/") != origin {
		return zero, fmt.Errorf("generation bundleOrigin %q != pinned origin %q", doc.BundleOrigin, origin)
	}
	return doc, nil
}

// assertNoDuplicateJSONKeys walks the document and refuses a duplicate key in any
// object — INCLUDING a CASE-SHADOWED duplicate. Go's encoding/json matches struct
// fields case-INSENSITIVELY, so {"storeId":expected,"StoreID":decoy} would let a
// decoy target the same trusted field with parser-order-dependent meaning; both
// spellings are rejected (strings.EqualFold), as is an exact duplicate.
func assertNoDuplicateJSONKeys(raw []byte) error {
	return scanNoDupKeys(json.NewDecoder(strings.NewReader(string(raw))))
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
		var keys []string
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := kt.(string)
			for _, k := range keys {
				if strings.EqualFold(k, key) {
					return fmt.Errorf("case-shadowed duplicate JSON key %q vs %q", k, key)
				}
			}
			keys = append(keys, key)
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
	}
	return nil
}
