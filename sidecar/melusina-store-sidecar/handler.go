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
	"path/filepath"
	"strings"
	"sync"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	// maxAppPublishBody bounds /publish (envelope + RELEASE.json + SPK).
	// Catalog SPKs stay under 100 MiB; keep this narrow because app publication
	// has no reason to accept shell-sized payloads.
	maxAppPublishBody int64 = 256 << 20 // 256 MiB

	// maxInstallerPublishBody bounds /publish/installer. Shell bundles are
	// currently about 280 MiB, so the app limit cannot also be the installer
	// limit. Keep a finite ceiling while leaving room for signed release growth.
	maxInstallerPublishBody int64 = 512 << 20 // 512 MiB
)

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
	// Developer/Repo/Slug OPTIONALLY name the catalog slot
	// (packages/<developer>/<repo>/<slug>) for the FIRST publish of a new app.
	// A re-publish resolves its existing slot by the appId in metadata.json and
	// may omit these (if present they must agree with the resolved slot).
	Developer string `json:"developer,omitempty"`
	Repo      string `json:"repo,omitempty"`
	Slug      string `json:"slug,omitempty"`
}

// installerPublishRequest is the JSON wire form for POST /publish/installer.
// ArtifactB64 is the raw whole-file artifact bytes (shell bundle, sidecar ELF,
// Python/rootfs tarball, bootstrap tarball); class+name select the served
// /releases/<class>/<name> path.
type installerPublishRequest struct {
	// Envelope is the publisher's signed artifact envelope (JSON object). It
	// binds RequestHash to sha256(artifact), matching /publish's author gate.
	Envelope    envelope.Signed `json:"envelope"`
	Class       string          `json:"class"`
	Name        string          `json:"name"`
	ArtifactB64 string          `json:"artifact_b64"`
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
		assembler: NewCatalogAssembler(cfg.CatalogRepoRoot, cfg.DistDir),
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
	mux.HandleFunc("/publish/installer", svc.handlePublishInstaller)

	// SIGNED UPDATE MANIFEST (B2-04): the operator-signed Sandstorm-shell update
	// manifest the install-side melusina-update-checker.py fetches + verifies
	// before applying an update. Registered as an EXACT route so it beats the
	// catch-all FileServer (a dynamically re-signed manifest, not a static file);
	// the handler write-throughs the same bytes to <DistDir>/update/manifest.json.
	// Fail-closed 503 when the operator identity is unwired (no signer).
	mux.HandleFunc("/update/manifest.json", svc.handleUpdateManifest)

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

	if rejectReceiveBypass(w) {
		return
	}

	// The gated path requires both the on-chain reader and the operator signing
	// identity. If boot did not wire them, fail closed (never accept unverified).
	if s.cr == nil || s.operator == nil {
		http.Error(w, "publish gate not initialized (no chain reader / operator identity)", http.StatusServiceUnavailable)
		return
	}

	sig, releaseBytes, spk, metadata, hint, err := parsePublishBody(r)
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

	// Store policy: this store only accepts configured release PDAs or publisher
	// identities. Empty list is fail-closed; otherwise a root store with a boot
	// identity but no allowlist becomes accept-any.
	if !s.publisherAccepted(rel, sig.Payload.Source) {
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
		http.Error(w, err.Error(), publishErrorStatus(err))
		return
	}

	// (b-time) STORE HYGIENE — monotonic release time. The claimed signedAtUnix must
	// strictly advance past the version this app's slot currently serves (located by
	// the Sandstorm appId from metadata.json — the served-slot key, stable across a
	// master-NFT re-anchor), so a re-publish can never surface an older "updated" time
	// than the version it replaces. READ-ONLY over the served tree; a first publish
	// for the slot passes.
	if err := verifyReleaseTimestampForward(s.cfg.DistDir, metadataAppID(metadata), rel); err != nil {
		http.Error(w, err.Error(), publishErrorStatus(err))
		return
	}

	// Gate passed → persist the verified bytes into the catalog slot (C3: the
	// store itself writes what it verified; the served tree's inputs come from
	// this gate and nowhere else), then invoke the catalog assembler
	// (convenience, not authority). A failed assembly is a 500
	// (verified-and-persisted-but-not-assembled; the next successful publish or
	// assembler run picks the slot up — the receipt is only issued on success).
	slotDir, err := resolveAppSlot(s.cfg.CatalogRepoRoot, metadataAppID(metadata), hint)
	if err != nil {
		http.Error(w, "check=slot: "+err.Error(), slotErrorStatus(err))
		return
	}
	if err := persistPublishedApp(slotDir, spk, releaseBytes, metadata); err != nil {
		http.Error(w, "check=persist: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.assembler.AssemblePublishedApp(spk, releaseBytes, metadata); err != nil {
		log.Printf("publish: catalog assemble failed: %v", err)
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

// handlePublishInstaller is the whole-file artifact publish path for
// /releases/<class>/<name>. It is deliberately narrower than app /publish:
// InstallerReleaseEntry binds sha256(artifact) on-chain, while a root
// StoreOperatorAuthorization proves this store may originate installer artifacts.
func (s *publishService) handlePublishInstaller(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if rejectReceiveBypass(w) {
		return
	}
	if s.cr == nil || s.operator == nil {
		http.Error(w, "installer publish gate not initialized (no chain reader / operator identity)", http.StatusServiceUnavailable)
		return
	}

	sig, class, name, artifact, err := parseInstallerPublishBody(r)
	if err != nil {
		http.Error(w, "check=request: "+err.Error(), http.StatusBadRequest)
		return
	}
	artifactHash := sha256.Sum256(artifact)
	operatorIdentity := s.operator.Public()
	artifactHashHex := hex.EncodeToString(artifactHash[:])
	if err := envelope.Verify(sig, envelope.VerifyOptions{
		ExpectedKind:        envelope.KindArtifact,
		ExpectedDestination: &operatorIdentity,
		ExpectedRequestHash: artifactHashHex,
		NonceCache:          s.nonces,
	}); err != nil {
		http.Error(w, "check=envelope: "+err.Error(), http.StatusUnauthorized)
		return
	}
	if !s.publisherIdentityAccepted(sig.Payload.Source) {
		http.Error(w, "check=accept_publishers: installer publisher not in store policy accept_publishers", http.StatusForbidden)
		return
	}

	operatorPub, err := signPubkey32(operatorIdentity)
	if err != nil {
		http.Error(w, "check=operator_key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, _, err := VerifyStoreOperator(r.Context(), s.cr, s.cfg, operatorPub, true /* requireRoot */); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := VerifyInstallerReleaseHash(r.Context(), s.cr, s.cfg, artifactHash); err != nil {
		code := http.StatusForbidden
		if errors.Is(err, errReleaseMasterMintRequired) {
			code = http.StatusServiceUnavailable
		}
		http.Error(w, err.Error(), code)
		return
	}
	if err := s.verifyInstallerPublishForward(r.Context(), class, name, artifactHash); err != nil {
		http.Error(w, err.Error(), publishErrorStatus(err))
		return
	}
	if err := writePublishedReleaseArtifact(s.cfg.DistDir, class, name, artifact); err != nil {
		http.Error(w, "check=write_release: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"class":          class,
		"name":           name,
		"installer_hash": hex.EncodeToString(artifactHash[:]),
		"path":           "/releases/" + class + "/" + name,
	})
}

func rejectReceiveBypass(w http.ResponseWriter) bool {
	// Fail-closed: there is no receive-side bypass. Reject loudly if a caller
	// tries to smuggle the dev-only offline/skip escape hatches (spec §5 S7).
	if os.Getenv("MELUSINA_ATTEST_OFFLINE") != "" || os.Getenv("SKIP_STEPS") != "" || os.Getenv("MELUSINA_SCAN_NOOP") != "" {
		http.Error(w, "receive-path attest/scan bypass is disabled on the store sidecar", http.StatusBadRequest)
		return true
	}
	return false
}

func publishErrorStatus(err error) int {
	if errors.Is(err, errVersionConflict) || errors.Is(err, errSupersedeRequired) || errors.Is(err, errReleaseTimestampNotMonotonic) {
		return http.StatusConflict
	}
	return http.StatusForbidden
}

// publisherAccepted enforces store policy.accept_publishers against either the
// release's ReleaseEntry PDA or the publisher identity. An empty list fails
// closed; the on-chain gate is necessary but not sufficient.
func (s *publishService) publisherAccepted(rel ReleaseJSON, publisher identity.Public) bool {
	allow := s.cfg.Policy.AcceptPublishers
	if len(allow) == 0 {
		return false
	}
	pda := strings.TrimSpace(rel.ReleaseEntryPda)
	pub := strings.TrimSpace(publisher.SignPubkeyB58)
	digest := strings.TrimSpace(publisher.DigestHex())
	for _, a := range allow {
		item := strings.TrimSpace(a)
		if item == pda || item == pub || item == digest {
			return true
		}
	}
	return false
}

func (s *publishService) publisherIdentityAccepted(publisher identity.Public) bool {
	if len(s.cfg.Policy.AcceptPublishers) == 0 {
		return false
	}
	pub := strings.TrimSpace(publisher.SignPubkeyB58)
	digest := strings.TrimSpace(publisher.DigestHex())
	for _, a := range s.cfg.Policy.AcceptPublishers {
		item := strings.TrimSpace(a)
		if item == pub || item == digest {
			return true
		}
	}
	return false
}

// parsePublishBody extracts the signed envelope, the RELEASE.json bytes, the raw
// SPK bytes, the metadata.json bytes, and the optional catalog-slot hint from
// either a multipart/form-data request (file fields: envelope, release, spk,
// metadata; value fields: developer, repo, slug) or a JSON request
// (publishRequest). metadata is REQUIRED (the on-chain AppHash binds
// {app.spk, metadata.json}); a publish without it cannot recompute the AppHash
// and is malformed.
func parsePublishBody(r *http.Request) (sig envelope.Signed, release []byte, spk []byte, metadata []byte, hint slotHint, err error) {
	if err := limitPublishBody(r, maxAppPublishBody); err != nil {
		return sig, nil, nil, nil, hint, err
	}
	ct := r.Header.Get("Content-Type")

	if strings.HasPrefix(ct, "multipart/form-data") {
		if perr := r.ParseMultipartForm(32 << 20); perr != nil {
			return sig, nil, nil, nil, hint, fmt.Errorf("parse multipart: %w", perr)
		}
		envBytes, perr := readFormFile(r, "envelope")
		if perr != nil {
			return sig, nil, nil, nil, hint, fmt.Errorf("envelope part: %w", perr)
		}
		if perr := json.Unmarshal(envBytes, &sig); perr != nil {
			return sig, nil, nil, nil, hint, fmt.Errorf("decode envelope JSON: %w", perr)
		}
		release, perr = readFormFile(r, "release")
		if perr != nil {
			return sig, nil, nil, nil, hint, fmt.Errorf("release part: %w", perr)
		}
		spk, perr = readFormFile(r, "spk")
		if perr != nil {
			return sig, nil, nil, nil, hint, fmt.Errorf("spk part: %w", perr)
		}
		metadata, perr = readFormFile(r, "metadata")
		if perr != nil {
			return sig, nil, nil, nil, hint, fmt.Errorf("metadata part: %w", perr)
		}
		if len(metadata) == 0 {
			return sig, nil, nil, nil, hint, errors.New("metadata is empty")
		}
		hint = slotHint{
			Developer: strings.TrimSpace(r.FormValue("developer")),
			Repo:      strings.TrimSpace(r.FormValue("repo")),
			Slug:      strings.TrimSpace(r.FormValue("slug")),
		}
		return sig, release, spk, metadata, hint, nil
	}

	// JSON wire form (base64 fields).
	body, perr := io.ReadAll(r.Body)
	if perr != nil {
		return sig, nil, nil, nil, hint, fmt.Errorf("read body: %w", perr)
	}
	var req publishRequest
	if perr := json.Unmarshal(body, &req); perr != nil {
		return sig, nil, nil, nil, hint, fmt.Errorf("decode JSON body: %w", perr)
	}
	sig = req.Envelope
	release, perr = stdB64(req.ReleaseB64)
	if perr != nil {
		return sig, nil, nil, nil, hint, fmt.Errorf("release_b64: %w", perr)
	}
	spk, perr = stdB64(req.SPKB64)
	if perr != nil {
		return sig, nil, nil, nil, hint, fmt.Errorf("spk_b64: %w", perr)
	}
	if len(spk) == 0 {
		return sig, nil, nil, nil, hint, errors.New("spk is empty")
	}
	metadata, perr = stdB64(req.MetadataB64)
	if perr != nil {
		return sig, nil, nil, nil, hint, fmt.Errorf("metadata_b64: %w", perr)
	}
	if len(metadata) == 0 {
		return sig, nil, nil, nil, hint, errors.New("metadata is empty")
	}
	hint = slotHint{
		Developer: strings.TrimSpace(req.Developer),
		Repo:      strings.TrimSpace(req.Repo),
		Slug:      strings.TrimSpace(req.Slug),
	}
	return sig, release, spk, metadata, hint, nil
}

func parseInstallerPublishBody(r *http.Request) (sig envelope.Signed, class string, name string, artifact []byte, err error) {
	if err := limitPublishBody(r, maxInstallerPublishBody); err != nil {
		return sig, "", "", nil, err
	}
	ct := r.Header.Get("Content-Type")

	if strings.HasPrefix(ct, "multipart/form-data") {
		if perr := r.ParseMultipartForm(32 << 20); perr != nil {
			return sig, "", "", nil, fmt.Errorf("parse multipart: %w", perr)
		}
		envBytes, perr := readFormFile(r, "envelope")
		if perr != nil {
			return sig, "", "", nil, fmt.Errorf("envelope part: %w", perr)
		}
		if perr := json.Unmarshal(envBytes, &sig); perr != nil {
			return sig, "", "", nil, fmt.Errorf("decode envelope JSON: %w", perr)
		}
		class = strings.TrimSpace(r.FormValue("class"))
		name = strings.TrimSpace(r.FormValue("name"))
		artifact, err = readFormFile(r, "artifact")
		if err != nil {
			return sig, "", "", nil, fmt.Errorf("artifact part: %w", err)
		}
	} else {
		body, perr := io.ReadAll(r.Body)
		if perr != nil {
			return sig, "", "", nil, fmt.Errorf("read body: %w", perr)
		}
		var req installerPublishRequest
		if perr := json.Unmarshal(body, &req); perr != nil {
			return sig, "", "", nil, fmt.Errorf("decode JSON body: %w", perr)
		}
		sig = req.Envelope
		class = strings.TrimSpace(req.Class)
		name = strings.TrimSpace(req.Name)
		artifact, err = stdB64(req.ArtifactB64)
		if err != nil {
			return sig, "", "", nil, fmt.Errorf("artifact_b64: %w", err)
		}
	}

	if !isSafePathSegment(class) {
		return sig, "", "", nil, errors.New("class must be a single safe path segment")
	}
	if !isSafePathSegment(name) {
		return sig, "", "", nil, errors.New("name must be a single safe path segment")
	}
	if len(artifact) == 0 {
		return sig, "", "", nil, errors.New("artifact is empty")
	}
	return sig, class, name, artifact, nil
}

func limitPublishBody(r *http.Request, limit int64) error {
	if r.ContentLength > limit {
		return fmt.Errorf("request body is %d bytes; limit is %d", r.ContentLength, limit)
	}
	r.Body = http.MaxBytesReader(nil, r.Body, limit)
	return nil
}

func writePublishedReleaseArtifact(distDir, class, name string, artifact []byte) error {
	dir := filepath.Join(distDir, "releases", class)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return atomicWriteInto(dir, name, artifact)
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
