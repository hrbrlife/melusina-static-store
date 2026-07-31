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
	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// maxPublishBody bounds the total /publish request body (envelope + RELEASE.json
// + SPK). The 100 MiB figure it used to track is GitHub's push limit, which
// constrains the gh-pages MIRROR of the catalog — it was never a property of a
// self-hosted store, and it is not a trust boundary (the on-chain ReleaseEntry
// is). At 110 MiB the cap also bit far earlier than it looked: the default wire
// form base64-encodes the SPK, so it rejected packages above ~82 MB, and the
// store aborted mid-upload — the client saw only an opaque nginx 502 with no
// check= line. Bound the body generously; the real gate stays on-chain.
const maxPublishBody = 512 << 20 // 512 MiB

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
	// RuntimeContractB64 is the raw RUNTIME-CONTRACT.json bytes, base64-std.
	// RELEASE.json binds sha256(this exact byte sequence), and the contract in
	// turn binds sha256(SPK).  This makes a runtime declaration a release
	// artifact rather than a mutable catalog annotation.
	RuntimeContractB64 string `json:"runtime_contract_b64"`
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

	sig, releaseBytes, spk, metadata, runtimeContract, hint, err := parsePublishBody(r)
	if err != nil {
		http.Error(w, "check=request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Verify the publisher's envelope: it must be a KindPublishRequest addressed
	// to THIS sidecar, signed by a key THIS STORE'S POLICY authorizes, its
	// RequestHash must equal sha256(SPK) (binding the envelope to the exact
	// bytes), its BodyHash must equal sha256(RELEASE.json), and the nonce must
	// be fresh (replay protection).
	//
	// KindPublishRequest, not KindArtifact: the name was RECLAIMED (§4.3) for
	// durable evidence records. This message is transport — a 2-minute TTL and a
	// nonce — and the two must not share a word.
	operatorPub := s.operator.Public()

	if err := requireEnvelopePresent(sig); err != nil {
		http.Error(w, "check=envelope: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Store policy FIRST, so an unlisted publisher gets its own diagnostic
	// rather than a generic envelope failure. This check needs only the claimed
	// source identity — it used to be stuck below the envelope verify because it
	// also consumed the parsed RELEASE.json's self-asserted PDA (D-10). Deleting
	// that self-asserted input is what lets the policy check move to where it
	// belongs. Empty list fails closed.
	if !s.publisherAccepted(sig.Payload.Source) {
		http.Error(w, "check=accept_publishers: release publisher not in store policy accept_publishers", http.StatusForbidden)
		return
	}

	spkHashHex := hex.EncodeToString(sha256Sum(spk))
	if err := s.verifyPublishEnvelope(sig, operatorPub, spkHashHex); err != nil {
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

	// Runtime-contract gate.  The on-chain ReleaseEntry remains the authority
	// for what bytes may be served; this additional release-bound declaration
	// makes a future app publish state exactly how its real UI + sidecar behavior
	// must be proven after installation.  It is intentionally AFTER the chain
	// gate so an invalid or revoked artifact still reports its load-bearing
	// on-chain refusal, never a distracting metadata error.
	if _, err := runtimecontract.Validate(runtimeContract, runtimecontract.Binding{
		SPK:                   spk,
		Metadata:              metadata,
		AppHash:               strings.ToLower(strings.TrimSpace(rel.AppHash)),
		Version:               rel.Version,
		ReleaseContractSHA256: rel.RuntimeContractSHA256,
		ReleaseContractSchema: rel.RuntimeContractSchema,
	}); err != nil {
		http.Error(w, "check=runtime_contract: "+err.Error(), http.StatusBadRequest)
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
	if err := persistPublishedApp(slotDir, spk, releaseBytes, metadata, runtimeContract); err != nil {
		http.Error(w, "check=persist: "+err.Error(), http.StatusInternalServerError)
		return
	}
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
	if err := requireEnvelopePresent(sig); err != nil {
		http.Error(w, "check=envelope: "+err.Error(), http.StatusUnauthorized)
		return
	}
	// Policy first, then authority — the same order as the app route, so the two
	// routes cannot report the same condition with different codes.
	if !s.publisherIdentityAccepted(sig.Payload.Source) {
		http.Error(w, "check=accept_publishers: installer publisher not in store policy accept_publishers", http.StatusForbidden)
		return
	}
	if err := s.verifyPublishEnvelope(sig, operatorIdentity, artifactHashHex); err != nil {
		http.Error(w, "check=envelope: "+err.Error(), http.StatusUnauthorized)
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

// publisherAccepted enforces store policy.accept_publishers as POLICY.
//
// It is NOT the signer authority — that is resolveAcceptedPublisherKey below,
// and the envelope's signature is verified against the key THAT returns
// (PROVENANCE_CONTRACTS.md §7.6(4)). Keeping this check as well is deliberate:
// it fails closed on an empty list (:390-392), which is the only reason the
// live gate was safe before the signer authority existed (§0.2 finding 3). It
// is the right instinct at the wrong altitude; it keeps its altitude.
//
// D-10: the `rel.ReleaseEntryPda` match is GONE. It compared a SELF-ASSERTED
// RELEASE.json field against the allowlist — a value the publisher types, used
// inside an authority decision. It was not exploitable on its own (VerifyPublish
// independently re-resolves chain from rel), but a self-asserted value has no
// business in this decision, and it is precisely the shape that lets an
// allowlist entry authorize a signature nobody checked.
func (s *publishService) publisherAccepted(publisher identity.Public) bool {
	_, ok := s.resolveAcceptedPublisherKey(publisher)
	return ok
}

// resolveAcceptedPublisherKey returns the signing key THIS STORE'S POLICY
// authorizes for the claimed publisher, and is the sole signer authority for a
// publish (§7.6(4)).
//
// THE DIRECTION IS THE SECURITY PROPERTY. `claimed` is the key the envelope
// carries, and it is used ONLY as a lookup hint into our own allowlist; the key
// returned — and therefore the key the signature is verified against — is OUR
// policy's copy. A claimed key that is not in the allowlist resolves to nothing
// and the publish is refused. So the blob can select WHICH allowlisted publisher
// it claims to be, and can never introduce a key.
//
// This is the discipline jointicket.Verify has always had (a mandatory
// expectedSignerPubkey, verified against the caller's key rather than
// s.SignerPubkeyBase58) and that envelope.Verify lacked until the v2 cutover:
// it verified against the pubkey carried inside the payload being verified,
// which any key satisfies for its own blob.
func (s *publishService) resolveAcceptedPublisherKey(claimed identity.Public) (string, bool) {
	want := strings.TrimSpace(claimed.SignPubkeyB58)
	if want == "" {
		return "", false
	}
	for _, a := range s.cfg.Policy.AcceptPublishers {
		if strings.TrimSpace(a) == want {
			// Return the POLICY's copy, not the blob's. Identical strings today;
			// the point is that the value flows from configuration into the
			// verification, never from the thing being verified.
			return strings.TrimSpace(a), true
		}
	}
	return "", false
}

// requireEnvelopePresent separates "the client sent no envelope" from "this
// publisher is not allowlisted".
//
// Both are refusals, and the gate is equally closed either way — but an
// operator who reads "not in store policy accept_publishers" will go and edit
// their allowlist, when the real fault is a client that posted nothing. The
// policy check runs before the signature check (so an unlisted publisher gets
// its own diagnostic), which is exactly what makes this distinction necessary.
func requireEnvelopePresent(sig envelope.Signed) error {
	if strings.TrimSpace(sig.SignatureB58) == "" {
		return errors.New("missing envelope signature")
	}
	if strings.TrimSpace(sig.Payload.Source.SignPubkeyB58) == "" {
		return errors.New("envelope carries no source identity")
	}
	return nil
}

// verifyPublishEnvelope is the ONE place a publish envelope is authenticated.
//
// Both publish routes call it so the two cannot drift apart — they already had
// two hand-copied envelope.Verify blocks, and D-9's kill-list missed a third
// signing site in cmd/submit-installer, which is what copy-paste at a security
// boundary costs.
func (s *publishService) verifyPublishEnvelope(sig envelope.Signed, operatorPub identity.Public, requestHashHex string) error {
	signerKey, ok := s.resolveAcceptedPublisherKey(sig.Payload.Source)
	if !ok {
		// Deliberately does not echo the claimed key as though it were an
		// identity: it is an unauthenticated string at this point.
		return fmt.Errorf("publisher is not in store policy accept_publishers (the allowlist must contain the publisher's base58 SIGNING PUBKEY; a ReleaseEntry PDA no longer authorizes a publish — see D-10)")
	}
	// NOTE what is deliberately NOT pinned here: ExpectedLicenseMint and
	// ExpectedDomain. Payload.Domain / Payload.LicenseMint are the PUBLISHER's
	// own values, and this store authenticates EXTERNAL app publishers, each
	// under their own license and domain. accept_publishers holds keys, not
	// licenses — the store has no pinned value to compare against.
	//
	// The only way to populate them here would be
	// `ExpectedLicenseMint: sig.Payload.Source.Ref.LicenseMint` — comparing the
	// blob against itself. That check can never fail while LOOKING like a
	// control, which is worse than no check at all and is the exact class of
	// defect this migration exists to delete. (A first draft of this function
	// did precisely that and pinned ExpectedDomain to the OPERATOR's domain;
	// the publish tests caught it as "domain mismatch" on every valid publish.)
	//
	// The authority that decides a publish is the signing key, and it is pinned.
	return envelope.Verify(sig, envelope.VerifyOptions{
		ExpectedSignerPubkeyB58: signerKey,
		ExpectedKind:            envelope.KindPublishRequest,
		ExpectedDestination:     &operatorPub,
		ExpectedRequestHash:     requestHashHex,
		NonceCache:              s.nonces,
	})
}

// publisherIdentityAccepted is the installer route's policy check. It is the
// SAME rule as publisherAccepted — one allowlist, one meaning.
//
// These were two near-identical loops with subtly different rules (the app route
// also matched a self-asserted PDA; both also matched an identity digest that no
// documented config ever contains and that cannot yield a signing key). Two
// spellings of one policy is how the two drift, and the drift is invisible until
// one of them is the only thing standing between a publisher and the catalog.
func (s *publishService) publisherIdentityAccepted(publisher identity.Public) bool {
	return s.publisherAccepted(publisher)
}

// parsePublishBody extracts the signed envelope, RELEASE.json, raw SPK,
// metadata.json, and RUNTIME-CONTRACT.json plus the optional catalog-slot hint.
// The contract travels as its own raw artifact because RELEASE.json binds its
// SHA-256 and the contract binds sha256(SPK).  It is REQUIRED for every new
// /publish; historical catalog cards are grandfathered only on the READ path,
// where they are surfaced as explicitly uncertified.
//
// Multipart file fields: envelope, release, spk, metadata, runtime_contract.
// JSON fields use their corresponding *_b64 names.  metadata remains required
// because the on-chain AppHash binds {app.spk, metadata.json}.
func parsePublishBody(r *http.Request) (sig envelope.Signed, release []byte, spk []byte, metadata []byte, runtimeContract []byte, hint slotHint, err error) {
	r.Body = http.MaxBytesReader(nil, r.Body, maxPublishBody)
	ct := r.Header.Get("Content-Type")

	if strings.HasPrefix(ct, "multipart/form-data") {
		if perr := r.ParseMultipartForm(32 << 20); perr != nil {
			return sig, nil, nil, nil, nil, hint, fmt.Errorf("parse multipart: %w", perr)
		}
		envBytes, perr := readFormFile(r, "envelope")
		if perr != nil {
			return sig, nil, nil, nil, nil, hint, fmt.Errorf("envelope part: %w", perr)
		}
		if perr := json.Unmarshal(envBytes, &sig); perr != nil {
			return sig, nil, nil, nil, nil, hint, fmt.Errorf("decode envelope JSON: %w", perr)
		}
		release, perr = readFormFile(r, "release")
		if perr != nil {
			return sig, nil, nil, nil, nil, hint, fmt.Errorf("release part: %w", perr)
		}
		spk, perr = readFormFile(r, "spk")
		if perr != nil {
			return sig, nil, nil, nil, nil, hint, fmt.Errorf("spk part: %w", perr)
		}
		metadata, perr = readFormFile(r, "metadata")
		if perr != nil {
			return sig, nil, nil, nil, nil, hint, fmt.Errorf("metadata part: %w", perr)
		}
		if len(metadata) == 0 {
			return sig, nil, nil, nil, nil, hint, errors.New("metadata is empty")
		}
		runtimeContract, perr = readFormFile(r, "runtime_contract")
		// Keep an omitted contract as an empty artifact for the release-bound
		// gate below.  That preserves the useful authorization/on-chain error
		// precedence for otherwise invalid submissions and gives both wire
		// formats the same check=runtime_contract refusal once they are valid.
		if perr != nil && !errors.Is(perr, http.ErrMissingFile) {
			return sig, nil, nil, nil, nil, hint, fmt.Errorf("runtime_contract part: %w", perr)
		}
		hint = slotHint{
			Developer: strings.TrimSpace(r.FormValue("developer")),
			Repo:      strings.TrimSpace(r.FormValue("repo")),
			Slug:      strings.TrimSpace(r.FormValue("slug")),
		}
		return sig, release, spk, metadata, runtimeContract, hint, nil
	}

	// JSON wire form (base64 fields).
	body, perr := io.ReadAll(r.Body)
	if perr != nil {
		return sig, nil, nil, nil, nil, hint, fmt.Errorf("read body: %w", perr)
	}
	var req publishRequest
	if perr := json.Unmarshal(body, &req); perr != nil {
		return sig, nil, nil, nil, nil, hint, fmt.Errorf("decode JSON body: %w", perr)
	}
	sig = req.Envelope
	release, perr = stdB64(req.ReleaseB64)
	if perr != nil {
		return sig, nil, nil, nil, nil, hint, fmt.Errorf("release_b64: %w", perr)
	}
	spk, perr = stdB64(req.SPKB64)
	if perr != nil {
		return sig, nil, nil, nil, nil, hint, fmt.Errorf("spk_b64: %w", perr)
	}
	if len(spk) == 0 {
		return sig, nil, nil, nil, nil, hint, errors.New("spk is empty")
	}
	metadata, perr = stdB64(req.MetadataB64)
	if perr != nil {
		return sig, nil, nil, nil, nil, hint, fmt.Errorf("metadata_b64: %w", perr)
	}
	if len(metadata) == 0 {
		return sig, nil, nil, nil, nil, hint, errors.New("metadata is empty")
	}
	runtimeContract, perr = stdB64(req.RuntimeContractB64)
	if perr != nil {
		return sig, nil, nil, nil, nil, hint, fmt.Errorf("runtime_contract_b64: %w", perr)
	}
	hint = slotHint{
		Developer: strings.TrimSpace(req.Developer),
		Repo:      strings.TrimSpace(req.Repo),
		Slug:      strings.TrimSpace(req.Slug),
	}
	return sig, release, spk, metadata, runtimeContract, hint, nil
}

func parseInstallerPublishBody(r *http.Request) (sig envelope.Signed, class string, name string, artifact []byte, err error) {
	r.Body = http.MaxBytesReader(nil, r.Body, maxPublishBody)
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
