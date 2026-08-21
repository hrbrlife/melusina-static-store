package hostupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

// VerifiedGeneration is a fully-verified desired generation plus the sha256 of the
// EXACT served bytes. The raw digest is what the poller persists (a Generation
// cursor) to refuse equivocation/replay — the same generation id must never be
// served with different bytes.
type VerifiedGeneration struct {
	Doc       componentrelease.DesiredGeneration
	RawSHA256 string
}

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
func FetchAndVerifyGeneration(ctx context.Context, get componentrelease.HTTPGetter, opts FetchOptions) (VerifiedGeneration, error) {
	var zero VerifiedGeneration
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
	rawSum := sha256.Sum256(body)
	return VerifiedGeneration{Doc: doc, RawSHA256: hex.EncodeToString(rawSum[:])}, nil
}

// GenerationCursor is the poller's PERSISTED anti-replay state: the last generation
// it acted on and that generation's raw served-bytes digest.
type GenerationCursor struct {
	Schema         string `json:"schema,omitempty"`
	GenerationID   uint64 `json:"generationId"`
	GenerationHash string `json:"generationHash,omitempty"`
	RawSHA256      string `json:"rawSha256"`
}

// AcceptAgainstCursor decides whether a freshly fetched+verified generation may be
// acted on, given the poller's persisted cursor. Fail-closed anti-equivocation /
// replay:
//   - refuse a generation OLDER than the committed one (downgrade);
//   - refuse the SAME generation id served with a DIFFERENT raw digest (the store
//     equivocated — same version, different bytes);
//   - refuse a forward generation whose previousGeneration is BEHIND the cursor
//     (it would bypass a generation this host already reached -- notably one that
//     FAILED and rolled back here);
//   - otherwise accept a forward generation, whether or not this host observed
//     the records between the cursor and it.
//
// A genesis cursor (GenerationID 0) accepts any first generation.
//
// Forward acceptance is deliberate and load-bearing. The estate supports
// independent and duplicated stores: an operator may run their own, generation
// numbering need not be dense, and a host that was down misses generations it
// will never be served again -- the producer keeps exactly ONE generation
// document, so a skipped predecessor is unfetchable by construction.
//
// The previous rule required previousGeneration == committed EXACTLY, which made
// a MISSING RECORD indistinguishable from an ATTACK. It bricked this rail in
// production (F-235/F-237): one generation whose components were already at
// target opened no WAL, so the cursor never advanced, and every later generation
// was then refused "chain break" forever, with no product path out.
//
// Nothing that actually protects a host is given up here. A version is withdrawn
// by CRYPTOGRAPHIC RECALL, never by document linkage: the operator signature and
// store binding are checked in FetchAndVerify above, and every component is
// re-verified against the chain immediately before mutation and again before
// Complete, where a revoked or superseded release refuses the apply and restores
// the prior artifact. The two checks that genuinely need the cursor -- downgrade
// and equivocation -- are unchanged, and so is the refusal of a successor that
// chains from BEHIND the cursor: that is not a missing record but a lineage that
// bypasses a generation this host already reached, including one that failed and
// rolled back here (see TestTerminalRollbackBridgesTheNextSignedRecoveryGeneration).
func AcceptAgainstCursor(cursor GenerationCursor, vg VerifiedGeneration) error {
	if cursor.GenerationID == 0 {
		return nil
	}
	gen := vg.Doc.GenerationID
	switch {
	case gen < cursor.GenerationID:
		return fmt.Errorf("stale generation %d < committed %d (downgrade refused)", gen, cursor.GenerationID)
	case gen == cursor.GenerationID:
		if !strings.EqualFold(vg.RawSHA256, cursor.RawSHA256) {
			return fmt.Errorf("equivocation: generation %d served raw digest %s != committed %s", gen, vg.RawSHA256, cursor.RawSHA256)
		}
		// Same id + same raw bytes but a DIFFERENT signed generationHash is also
		// equivocation — the operator re-signed the same generation id over
		// different canonical content (only meaningful when the cursor pins a hash).
		if cursor.GenerationHash != "" && !strings.EqualFold(vg.Doc.GenerationHash, cursor.GenerationHash) {
			return fmt.Errorf("equivocation: generation %d generationHash %s != committed %s", gen, vg.Doc.GenerationHash, cursor.GenerationHash)
		}
		return nil // same generation, same bytes — already committed, no-op
	default: // gen > cursor.GenerationID
		// A gap between cursor.GenerationID and gen is a record this host never saw,
		// not evidence of tampering, so it is accepted; the cursor's own advance
		// (e.g. 185 -> 188) is the durable record that a gap occurred. A predecessor
		// BEHIND the cursor is a different thing entirely -- that lineage bypasses a
		// generation this host already reached, which may be one that failed and
		// rolled back here -- and stays refused.
		if vg.Doc.PreviousGeneration < cursor.GenerationID {
			return fmt.Errorf("fork: generation %d previousGeneration %d is behind committed %d", gen, vg.Doc.PreviousGeneration, cursor.GenerationID)
		}
		return nil
	}
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
