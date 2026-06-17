package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// maxPublishBody bounds the total /publish request body (envelope + RELEASE.json
// + SPK). SPKs in the gh-pages catalog are kept under 100 MiB (build-store.sh);
// allow some envelope/release overhead on top.
const maxPublishBody = 110 << 20 // 110 MiB

// publishService holds the single-writer state for POST /publish: the on-chain
// reader (the trust gate), the operator's signing identity (receipt signer +
// envelope destination), the catalog assembler, and a replay-protection nonce
// cache. The mutex enforces the SINGLE WRITER invariant — one in-flight publish
// at a time.
type publishService struct {
	cfg       Config
	cr        chainReader
	operator  *identity.Private
	assembler *CatalogAssembler
	nonces    envelope.NonceCache

	mu sync.Mutex // SINGLE WRITER: serializes the verify→assemble→receipt path
}

// publishRequest is the JSON wire form accepted when the client does not use
// multipart/form-data. Each field is base64-std unless noted.
type publishRequest struct {
	// Envelope is the publisher's signed artifact envelope (JSON object).
	Envelope envelope.Signed `json:"envelope"`
	// ReleaseB64 is the RELEASE.json body (the envelope Body), base64-std.
	ReleaseB64 string `json:"release_b64"`
	// SPKB64 is the raw .spk bytes, base64-std.
	SPKB64 string `json:"spk_b64"`
	// MetadataB64 is the app's metadata.json bytes, base64-std. Together with the
	// SPK they form the canonical tree the on-chain AppHash binds; the gate
	// recomputes that AppHash, so a missing/tampered metadata fails check=app_hash.
	MetadataB64 string `json:"metadata_b64"`
}

// newRouter builds the sidecar HTTP surface.
//
//	READ surface (public, unauthenticated, byte-identical to today's static store):
//	  GET /            -> dist-publish/  (SPA, /apps/index.json, /attest/*, /packages/*, /verifier/*)
//	WRITE surface (gated; the sidecar is the SINGLE WRITER):
//	  POST /publish    -> sealed/signed envelope verify + on-chain re-verification
//	Ops:
//	  GET /healthz
//
// There is deliberately NO MELUSINA_ATTEST_OFFLINE / SKIP_STEPS / SCAN_NOOP
// bypass on this receive path (FEDERATED-STORE-MVP §5 S7). The Go on-chain
// verify (VerifyPublish) is the trust gate; build-store.sh is only an assembler.
//
// operator is the sidecar's signing identity (receipt signer + the envelope
// destination publishers address). cr is the on-chain reader (a
// *verify.RPCClient in production, a mock in tests). Either may be nil only when
// the gated path is not exercised (e.g. the READ-only smoke in main before boot
// identity is wired) — in that case /publish fails closed with 503.
//
// mirror is the reseller ROOT-MIRROR worker (FEDERATED-STORE-MVP §C2.6) or nil.
// When non-nil, its verified snapshot is served under /root/ (X-Store-Origin:
// root). The root operator passes nil (it originates, never mirrors).
func newRouter(cfg Config, operator *identity.Private, cr chainReader, mirror *rootMirror) http.Handler {
	mux := http.NewServeMux()

	svc := &publishService{
		cfg:       cfg,
		cr:        cr,
		operator:  operator,
		assembler: NewCatalogAssembler(cfg.CatalogRepoRoot),
		nonces:    envelope.NewMemoryNonceCache(),
	}

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"store":   cfg.StoreID,
			"domain":  cfg.Domain,
			"surface": "read + gated /publish (on-chain verified, single writer)",
		})
	})

	mux.HandleFunc("/publish", svc.handlePublish)

	// RESELLER ROOT-MIRROR surface (§C2.6) — serve the verified snapshot of the
	// root's installer + basic apps under /root/, fail-closed (503) until a cycle
	// verifies. Registered BEFORE the catch-all FileServer so /root/* never falls
	// through to the local dist tree. nil on a root operator (it does not mirror).
	if mirror != nil {
		mux.Handle("/root/", mirror.rootHandler())
		log.Printf("reseller root-mirror: serving verified root snapshot under /root/ (X-Store-Origin: root)")
	}

	// READ surface — static assets are served byte-identically, but SPK fetches
	// under /packages/ pass the SERVE-TIME on-chain gate (canon §5b, B1-01): the
	// served bytes must content-match an Active on-chain ReleaseEntry or the GET
	// is refused (403). Fail-closed: with no chain reader, SPK serves 503.
	gate := newServeGate(cfg, cr, http.FileServer(http.Dir(cfg.DistDir)))
	mux.Handle("/", gate)

	if cr == nil {
		log.Printf("read surface: %q — WARNING: no chain reader; /packages/* SPK serves fail CLOSED (503) until rpc_url is set", cfg.DistDir)
	} else {
		log.Printf("read surface: %q — static byte-identical; /packages/* gated by on-chain ReleaseEntry at serve time (verdict TTL %s)", cfg.DistDir, gate.verifyTTL)
	}
	return mux
}

// handlePublish is the gated write path. It fails closed and names the failing
// check on any rejection (4xx). On success it returns 200 + the store-signed
// provenance Receipt JSON.
func (s *publishService) handlePublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Fail-closed: there is no receive-side bypass. Reject loudly if a caller
	// tries to smuggle the dev-only offline/skip escape hatches (spec §5 S7).
	if os.Getenv("MELUSINA_ATTEST_OFFLINE") != "" || os.Getenv("SKIP_STEPS") != "" || os.Getenv("MELUSINA_SCAN_NOOP") != "" {
		http.Error(w, "receive-path attest/scan bypass is disabled on the store sidecar", http.StatusBadRequest)
		return
	}

	// The gated path requires both the on-chain reader and the operator signing
	// identity. If boot did not wire them, fail closed (never accept unverified).
	if s.cr == nil || s.operator == nil {
		http.Error(w, "publish gate not initialized (no chain reader / operator identity)", http.StatusServiceUnavailable)
		return
	}

	sig, releaseBytes, spk, metadata, err := parsePublishBody(r)
	if err != nil {
		http.Error(w, "check=request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Verify the publisher's envelope: it must be a KindArtifact addressed to
	// THIS sidecar, its RequestHash must equal sha256(SPK) (binding the envelope
	// to the exact bytes), its BodyHash must equal sha256(RELEASE.json), and the
	// nonce must be fresh (replay protection).
	operatorPub := s.operator.Public()
	spkHashHex := hex.EncodeToString(sha256Sum(spk))
	if err := envelope.Verify(sig, envelope.VerifyOptions{
		ExpectedKind:        envelope.KindArtifact,
		ExpectedDestination: &operatorPub,
		ExpectedRequestHash: spkHashHex,
		NonceCache:          s.nonces,
	}); err != nil {
		http.Error(w, "check=envelope: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// The envelope binds the body hash; require the RELEASE.json we received
	// matches it (the body travels plaintext alongside the SIGN-only envelope).
	bodyHashHex := hex.EncodeToString(sha256Sum(releaseBytes))
	if !strings.EqualFold(bodyHashHex, sig.Payload.BodyHashHex) {
		http.Error(w, fmt.Sprintf("check=body_hash: sha256(release)=%s != envelope.body_hash=%s", bodyHashHex, sig.Payload.BodyHashHex), http.StatusBadRequest)
		return
	}

	var rel ReleaseJSON
	if err := json.Unmarshal(releaseBytes, &rel); err != nil {
		http.Error(w, "check=release_json: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Optional policy: this store only accepts releases listed by configured
	// publishers (by ReleaseEntry PDA). Empty list = accept any chain-attested
	// release (the on-chain gate below is the real authority).
	if !s.publisherAccepted(rel) {
		http.Error(w, "check=accept_publishers: release publisher not in store policy accept_publishers", http.StatusForbidden)
		return
	}

	// SINGLE WRITER: only one publish performs the on-chain verify → assemble →
	// receipt sequence at a time.
	s.mu.Lock()
	defer s.mu.Unlock()

	// THE TRUST GATE: re-verify on-chain. No env bypass is reachable here. The
	// FoundationApp tier ceiling (B1-05/B2-05) is resolved INSIDE VerifyPublish
	// from the on-chain ReleaseEntry.app_id → FoundationAppEntry — the sidecar no
	// longer passes a dead tier=0.
	operatorSignPub, err := signPubkey32(operatorPub)
	if err != nil {
		http.Error(w, "check=operator_key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := VerifyPublish(r.Context(), s.cr, s.cfg, spk, metadata, rel, operatorSignPub); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// Gate passed → invoke the catalog assembler (convenience, not authority).
	// First persist the SPK + RELEASE.json into the packages tree would be the
	// publish-client's job (C3); here we run the aggregator over the working
	// tree. A failed assembly is a 500 (verified-but-not-written).
	if out, err := s.assembler.Assemble(r.Context()); err != nil {
		log.Printf("publish: catalog assemble failed: %v\n%s", err, out)
		http.Error(w, "check=assemble: catalog assembler failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Compute the receipt tuple from the now-verified facts.
	appHash, err := hash32FromHex(strings.ToLower(strings.TrimSpace(rel.AppHash)))
	if err != nil {
		http.Error(w, "check=receipt: appHash: "+err.Error(), http.StatusBadRequest)
		return
	}
	releaseHash, err := hash32FromHex(strings.ToLower(strings.TrimSpace(rel.ReleaseHash)))
	if err != nil {
		http.Error(w, "check=receipt: releaseHash: "+err.Error(), http.StatusBadRequest)
		return
	}
	servingDomainHash := primitives.StoreDomainHash(s.cfg.Domain)

	receipt := SignReceipt(s.operator, appHash, releaseHash, servingDomainHash)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(receipt)
}

// publisherAccepted enforces the optional store policy.accept_publishers list
// against the release's ReleaseEntry PDA. An empty list accepts any release
// (the on-chain ReleaseEntry/StoreOperatorAuthorization gate is the authority).
func (s *publishService) publisherAccepted(rel ReleaseJSON) bool {
	allow := s.cfg.Policy.AcceptPublishers
	if len(allow) == 0 {
		return true
	}
	pda := strings.TrimSpace(rel.ReleaseEntryPda)
	for _, a := range allow {
		if strings.TrimSpace(a) == pda {
			return true
		}
	}
	return false
}

// parsePublishBody extracts the signed envelope, the RELEASE.json bytes, the raw
// SPK bytes, and the metadata.json bytes from either a multipart/form-data request
// (fields: envelope, release, spk, metadata) or a JSON request (publishRequest).
// metadata is REQUIRED (the on-chain AppHash binds {app.spk, metadata.json}); a
// publish without it cannot recompute the AppHash and is malformed.
func parsePublishBody(r *http.Request) (sig envelope.Signed, release []byte, spk []byte, metadata []byte, err error) {
	r.Body = http.MaxBytesReader(nil, r.Body, maxPublishBody)
	ct := r.Header.Get("Content-Type")

	if strings.HasPrefix(ct, "multipart/form-data") {
		if perr := r.ParseMultipartForm(32 << 20); perr != nil {
			return sig, nil, nil, nil, fmt.Errorf("parse multipart: %w", perr)
		}
		envBytes, perr := readFormFile(r, "envelope")
		if perr != nil {
			return sig, nil, nil, nil, fmt.Errorf("envelope part: %w", perr)
		}
		if perr := json.Unmarshal(envBytes, &sig); perr != nil {
			return sig, nil, nil, nil, fmt.Errorf("decode envelope JSON: %w", perr)
		}
		release, perr = readFormFile(r, "release")
		if perr != nil {
			return sig, nil, nil, nil, fmt.Errorf("release part: %w", perr)
		}
		spk, perr = readFormFile(r, "spk")
		if perr != nil {
			return sig, nil, nil, nil, fmt.Errorf("spk part: %w", perr)
		}
		metadata, perr = readFormFile(r, "metadata")
		if perr != nil {
			return sig, nil, nil, nil, fmt.Errorf("metadata part: %w", perr)
		}
		if len(metadata) == 0 {
			return sig, nil, nil, nil, errors.New("metadata is empty")
		}
		return sig, release, spk, metadata, nil
	}

	// JSON wire form (base64 fields).
	body, perr := io.ReadAll(r.Body)
	if perr != nil {
		return sig, nil, nil, nil, fmt.Errorf("read body: %w", perr)
	}
	var req publishRequest
	if perr := json.Unmarshal(body, &req); perr != nil {
		return sig, nil, nil, nil, fmt.Errorf("decode JSON body: %w", perr)
	}
	sig = req.Envelope
	release, perr = stdB64(req.ReleaseB64)
	if perr != nil {
		return sig, nil, nil, nil, fmt.Errorf("release_b64: %w", perr)
	}
	spk, perr = stdB64(req.SPKB64)
	if perr != nil {
		return sig, nil, nil, nil, fmt.Errorf("spk_b64: %w", perr)
	}
	if len(spk) == 0 {
		return sig, nil, nil, nil, errors.New("spk is empty")
	}
	metadata, perr = stdB64(req.MetadataB64)
	if perr != nil {
		return sig, nil, nil, nil, fmt.Errorf("metadata_b64: %w", perr)
	}
	if len(metadata) == 0 {
		return sig, nil, nil, nil, errors.New("metadata is empty")
	}
	return sig, release, spk, metadata, nil
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
