package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// ── canonical publisher: envelope-authorized generation promote (POST /publish/generation) ──
//
// The network entry of the canonical self-service publisher's promote step. An
// authorized vertical, after building + on-chain-sealing + publishing its
// component artifacts through the existing /publish paths, POSTs a v2
// KindPublishRequest envelope sealing a GenerationPromoteRequest. The store,
// under the SINGLE-WRITER lock, re-verifies the store operator authority and each
// component against the chain + the served bytes (never trusting the publisher's
// claims), then composes + CAS-promotes + operator-signs the next generation.
// Same three-step envelope order as /publish and /publish/installer so the routes
// cannot report the same condition with different codes.

// generationPromoteBody is the wire form: the v2 envelope + the base64 canonical
// GenerationPromoteRequest bytes the envelope's RequestHash binds.
type generationPromoteBody struct {
	Envelope   envelope.Signed `json:"envelope"`
	RequestB64 string          `json:"request_b64"`
}

// generationPromoteReadiness is the deliberately small, read-only contract
// checked before a release ceremony. CurrentGenerationID is present only when
// the persisted generation is signed by this store's active operator for this
// exact StoreID. It lets a publisher repair a non-servable generation through
// the ordinary signed CAS POST; it never exposes the generation contents,
// policy, staged bytes, or any authority material.
type generationPromoteReadiness struct {
	Schema              string  `json:"schema"`
	Status              string  `json:"status"`
	CurrentGenerationID *uint64 `json:"currentGenerationId,omitempty"`
}

// A promotion carries release facts and an envelope, never an artifact. Keep
// this endpoint narrowly bounded instead of inheriting the app-SPK upload cap.
const maxGenerationPromoteBody int64 = 1 << 20 // 1 MiB

func (s *publishService) handleGeneratePromote(w http.ResponseWriter, r *http.Request) {
	// Publish must fail before it creates an irreversible ReleaseEntry proposal
	// when the running store cannot also complete the approval-side generation
	// promotion. A read-only readiness document is the contract checked by
	// mel-release publish. It deliberately discloses neither policy keys nor
	// staged content.
	if r.Method == http.MethodGet {
		if s.cr == nil || s.operator == nil {
			http.Error(w, "generation promote gate not initialized (no chain reader / operator identity)", http.StatusServiceUnavailable)
			return
		}
		// The approve-side promotion immediately persists a DesiredGeneration
		// whose bundle origin is signed.  Advertising readiness without this
		// deployer-provided public origin lets a publisher create an on-chain
		// proposal that the store cannot make consumable.  Refuse before any
		// irreversible ReleaseEntry ceremony instead.
		if strings.TrimRight(strings.TrimSpace(s.cfg.PublicBaseURL), "/") == "" {
			http.Error(w, "generation promote gate not initialized (no public_base_url to pin the bundle origin)", http.StatusServiceUnavailable)
			return
		}
		readiness := generationPromoteReadiness{
			Schema: "melusina-generation-promote-readiness-v1",
			Status: "ready",
		}
		// The public serve endpoint may correctly fail closed when an older
		// signed generation no longer matches the current catalog pointer. Only
		// a locally re-verified persisted generation may supply the CAS floor
		// needed to repair that state through the normal signed POST.
		if operatorKey, err := operatorSignPublicKey(s.operator); err == nil {
			if current, _, err := loadCurrentGeneration(s.cfg.DistDir); err == nil {
				if err := componentrelease.Verify(operatorKey, s.cfg.StoreID, current); err == nil {
					id := current.GenerationID
					readiness.CurrentGenerationID = &id
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(readiness)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if rejectReceiveBypass(w) {
		return
	}
	if s.cr == nil || s.operator == nil {
		http.Error(w, "generation promote gate not initialized (no chain reader / operator identity)", http.StatusServiceUnavailable)
		return
	}
	if err := limitPublishBody(r, maxGenerationPromoteBody); err != nil {
		http.Error(w, "check=request: "+err.Error(), http.StatusBadRequest)
		return
	}
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "check=request: "+err.Error(), http.StatusBadRequest)
		return
	}
	// json.Decoder otherwise silently keeps the last duplicate key. The wire
	// wrapper contains both the authorization envelope and its bound request, so
	// reject ambiguity before extracting either of them.
	if err := assertNoDuplicateJSONKeys(rawBody); err != nil {
		http.Error(w, "check=request: "+err.Error(), http.StatusBadRequest)
		return
	}
	var body generationPromoteBody
	decBody := json.NewDecoder(bytes.NewReader(rawBody))
	decBody.DisallowUnknownFields()
	if err := decBody.Decode(&body); err != nil {
		http.Error(w, "check=request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := decBody.Decode(new(json.RawMessage)); err != io.EOF {
		http.Error(w, "check=request: unexpected trailing data", http.StatusBadRequest)
		return
	}
	requestBytes, err := base64.StdEncoding.DecodeString(body.RequestB64)
	if err != nil {
		http.Error(w, "check=request: bad request_b64: "+err.Error(), http.StatusBadRequest)
		return
	}
	requestHash := sha256.Sum256(requestBytes)
	requestHashHex := hex.EncodeToString(requestHash[:])
	operatorIdentity := s.operator.Public()

	// Envelope auth — identical order to /publish/installer.
	if err := requireEnvelopePresent(body.Envelope); err != nil {
		http.Error(w, "check=envelope: "+err.Error(), http.StatusUnauthorized)
		return
	}
	signerKey, ok := s.resolveAcceptedPublisherKey(body.Envelope.Payload.Source)
	if !ok {
		http.Error(w, "check=accept_publishers: promote publisher not in store policy accept_publishers", http.StatusForbidden)
		return
	}
	if err := envelope.Verify(body.Envelope, envelope.VerifyOptions{
		ExpectedKind:            envelope.KindPublishRequest,
		ExpectedSignerPubkeyB58: signerKey,
		ExpectedDestination:     &operatorIdentity,
		ExpectedRequestHash:     requestHashHex,
		NonceCache:              s.nonces,
	}); err != nil {
		http.Error(w, "check=envelope: "+err.Error(), http.StatusUnauthorized)
		return
	}
	// A valid publish envelope for another endpoint must never be replayable at
	// this route. Verify() authenticates the signed payload; the route owns this
	// explicit purpose comparison.
	if body.Envelope.Payload.Method != http.MethodPost || body.Envelope.Payload.Target != "/publish/generation" {
		http.Error(w, "check=envelope_purpose: signed purpose must be POST /publish/generation", http.StatusUnauthorized)
		return
	}

	// Strict-decode the promote request (an unknown field is a smuggled host
	// action; a duplicate/trailing is ambiguity — refuse).
	if err := assertNoDuplicateJSONKeys(requestBytes); err != nil {
		http.Error(w, "check=promote_request: "+err.Error(), http.StatusBadRequest)
		return
	}
	var req GenerationPromoteRequest
	dec := json.NewDecoder(bytes.NewReader(requestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "check=promote_request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		http.Error(w, "check=promote_request: unexpected trailing data", http.StatusBadRequest)
		return
	}

	// SUBMISSION BOUNDARY: a generation carries HOST components only. Refuse an
	// app before any chain read or writer-lock acquisition, and say why — an app
	// publisher that reaches this route is using the wrong rail, not failing a
	// check. Apps go out through their own signed catalog pointer + ReleaseEntry.
	if err := componentrelease.RejectAppComponents(req.Components); err != nil {
		http.Error(w, "check=component_class: "+err.Error(), http.StatusBadRequest)
		return
	}

	operatorPub, err := signPubkey32(operatorIdentity)
	if err != nil {
		http.Error(w, "check=operator_key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// SINGLE-WRITER: the store-operator gate, the per-component on-chain re-verify,
	// and the CAS promote all happen under one lock so a concurrent publish cannot
	// slip between the verify and the promote.
	s.mu.Lock()
	defer s.mu.Unlock()

	// A store may originate its own sidecar/app desired generation under its
	// domain-scoped operator authorization.  Root authority is necessary only
	// when this generation carries an installer artifact, because the program
	// reserves is_root for the canonical melusina-os.org store domain. Requiring
	// root unconditionally made a correctly-attested non-root sidecar store
	// impossible to promote at all.
	if _, _, err := VerifyStoreOperator(r.Context(), s.cr, s.cfg, operatorPub, generationPromoteRequiresRoot(req.Components)); err != nil {
		http.Error(w, "check=store_operator: "+err.Error(), http.StatusForbidden)
		return
	}
	for _, c := range req.Components {
		if err := s.verifyComponentReleaseOnChain(r.Context(), c); err != nil {
			http.Error(w, "check=component_chain: "+err.Error(), componentChainStatus(err))
			return
		}
	}

	raw, err := s.promoteGenerationLocked(req, s.currentTime())
	if err != nil {
		http.Error(w, "check=promote: "+err.Error(), promoteErrorStatus(err))
		return
	}

	var promoted componentrelease.DesiredGeneration
	_ = json.Unmarshal(raw, &promoted)
	rawHash := sha256.Sum256(raw)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"generationId":       promoted.GenerationID,
		"previousGeneration": promoted.PreviousGeneration,
		"generationHash":     promoted.GenerationHash,
		"servedSha256":       hex.EncodeToString(rawHash[:]),
		"path":               "/update/generation.json",
	})
}

// generationPromoteRequiresRoot keeps the root-store boundary narrow: only
// installer-release artifacts can require the canonical root store. Unknown
// authority kinds remain fail-closed later in verifyComponentReleaseOnChain.
func generationPromoteRequiresRoot(components []componentrelease.ComponentRelease) bool {
	for _, component := range components {
		if component.Chain.Kind == componentrelease.AuthorityInstallerRelease {
			return true
		}
	}
	return false
}

// verifyComponentReleaseOnChain re-verifies ONE HOST component against the chain
// and the served bytes — the store never trusts the publisher's asserted
// hash/PDA. installer_release (shell + data) is wired via
// VerifyInstallerReleaseHash; sidecar_identity via the SidecarIdentity re-derive.
// release_v2 (app) is refused: apps are not generation components.
func (s *publishService) verifyComponentReleaseOnChain(ctx context.Context, c componentrelease.ComponentRelease) error {
	switch c.Chain.Kind {
	case componentrelease.AuthorityInstallerRelease:
		hash, err := hash32FromHex(c.SHA256)
		if err != nil {
			return fmt.Errorf("component %s: bad sha256: %w", c.ComponentID, err)
		}
		if err := VerifyInstallerReleaseHash(ctx, s.cr, s.cfg, hash); err != nil {
			return fmt.Errorf("component %s: %w", c.ComponentID, err)
		}
		return s.verifyComponentServedBytes(c)
	case componentrelease.AuthoritySidecarIdentity:
		return s.verifySidecarComponentOnChain(ctx, c)
	case componentrelease.AuthorityReleaseV2:
		// release_v2 is the app authority. handleGeneratePromote already refuses
		// app components at the submission boundary; this arm keeps the switch
		// exhaustive and fail-closed if any other caller ever reaches it.
		return fmt.Errorf("component %s: %w", c.ComponentID, componentrelease.ErrAppNotAGenerationComponent)
	default:
		return fmt.Errorf("component %s: unknown authority kind %q", c.ComponentID, c.Chain.Kind)
	}
}

// openDistRegularNoFollow opens and validates the final path through the same
// descriptor. Callers still bind bytes/size themselves, so an in-place writer
// cannot turn a later hash into a trusted claim.
func openDistRegularNoFollow(path string) (*os.File, int64, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, 0, fmt.Errorf("unsafe non-regular file mode %s", info.Mode())
	}
	return f, info.Size(), nil
}

// verifySidecarComponentOnChain re-verifies a sidecar-class component. The promote
// handler already gates on a ROOT StoreOperatorAuthorization, so the root operator
// is trusted to name a legitimate sidecar; the store re-derives the
// SidecarIdentityEntry PDA itself (never trusting the publisher's claimed PDA),
// requires it Active, and requires its on-chain binary_hash to equal the served
// artifact sha256. The full Global/Local approval cascade is the external
// controller's apply-time gate (ADAPTER-DESIGN §4), not the store's release gate.
func (s *publishService) verifySidecarComponentOnChain(ctx context.Context, c componentrelease.ComponentRelease) error {
	sidecarID := strings.TrimSpace(c.Chain.SidecarID)
	if err := primitives.ValidateSidecarID(sidecarID); err != nil {
		return fmt.Errorf("component %s: bad sidecarId: %w", c.ComponentID, err)
	}
	licenseMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(c.Chain.LicenseNftMint))
	if err != nil {
		return fmt.Errorf("component %s: bad licenseNftMint: %w", c.ComponentID, err)
	}
	keyVersion := c.Chain.KeyVersion
	if keyVersion == 0 {
		keyVersion = 1
	}
	sidPDA, _, err := pda.SidecarIdentity(licenseMint, sidecarID, keyVersion, programID)
	if err != nil {
		return fmt.Errorf("component %s: derive SidecarIdentityEntry PDA: %w", c.ComponentID, err)
	}
	sid, err := s.cr.FetchSidecarIdentity(ctx, sidPDA.Base58())
	if err != nil {
		return fmt.Errorf("component %s: fetch SidecarIdentityEntry %s: %w", c.ComponentID, sidPDA.Base58(), err)
	}
	if err := sid.Status.RequireActive(); err != nil {
		return fmt.Errorf("component %s: sidecar identity status %s not Active: %w", c.ComponentID, sid.Status, err)
	}
	artifactHash, err := hash32FromHex(c.SHA256)
	if err != nil {
		return fmt.Errorf("component %s: bad sha256: %w", c.ComponentID, err)
	}
	if sid.BinaryHash != artifactHash {
		return fmt.Errorf("component %s: on-chain sidecar binary_hash %x != served sha256 %x", c.ComponentID, sid.BinaryHash[:], artifactHash[:])
	}
	// The 3-PDA SidecarIdentity check above is necessary but NOT sufficient: the
	// deployed program's require_active_sidecar_cascade also requires License,
	// GlobalSidecarApproval (hash-bound), LocalSidecarApproval, ResellerSidecar-
	// Approval and ResellerEntry all Active. Mirror the full cascade so a reseller/
	// license/global/local revocation cannot leave the identity looking green.
	if err := s.verifyFiveFactCascade(ctx, componentReleaseChainView{sidecarID: sidecarID, licenseMint: licenseMint}, artifactHash); err != nil {
		return fmt.Errorf("component %s: sidecar authorization cascade: %w", c.ComponentID, err)
	}
	return s.verifyComponentServedBytes(c)
}

// verifyComponentServedBytes confirms the artifact the generation points at is
// actually served under this store's DistDir and its bytes hash to the
// component's sha256 — the generation cannot point at bytes that were never
// published (card B: "verify served bytes").
func (s *publishService) verifyComponentServedBytes(c componentrelease.ComponentRelease) error {
	origin := strings.TrimRight(strings.TrimSpace(s.cfg.PublicBaseURL), "/")
	rel := strings.TrimPrefix(c.BundleURL, origin)
	if !strings.HasPrefix(rel, "/releases/") {
		return fmt.Errorf("component %s: bundleUrl %q is not under %s/releases/", c.ComponentID, c.BundleURL, origin)
	}
	clean := filepath.Clean(strings.TrimPrefix(rel, "/"))
	if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return fmt.Errorf("component %s: unsafe served path %q", c.ComponentID, rel)
	}
	p := filepath.Join(s.cfg.DistDir, filepath.FromSlash(clean))
	f, size, err := openDistRegularNoFollow(p)
	if err != nil {
		return fmt.Errorf("component %s: served artifact not found (%s): %w", c.ComponentID, rel, err)
	}
	defer f.Close()
	if size != c.SizeBytes {
		return fmt.Errorf("component %s: served artifact size %d != component size %d", c.ComponentID, size, c.SizeBytes)
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return fmt.Errorf("component %s: hash served artifact: %w", c.ComponentID, err)
	}
	if n != c.SizeBytes {
		return fmt.Errorf("component %s: served artifact size changed during hash: got %d want %d", c.ComponentID, n, c.SizeBytes)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != strings.ToLower(strings.TrimSpace(c.SHA256)) {
		return fmt.Errorf("component %s: served artifact sha256 %s != component sha256 %s", c.ComponentID, got, c.SHA256)
	}
	return nil
}

// componentChainStatus maps a re-verify failure to an HTTP status: a store not
// yet configured with a release master mint is 503 (transient/config), everything
// else is a 403 refusal.
func componentChainStatus(err error) int {
	if err != nil && strings.Contains(err.Error(), errReleaseMasterMintRequired.Error()) {
		return http.StatusServiceUnavailable
	}
	return http.StatusForbidden
}

// promoteErrorStatus maps a promote failure to an HTTP status: a CAS/lost-update
// conflict is 409, an internal (sign/persist/load) failure is 500, and a bad
// request (validation/schema) is 400.
func promoteErrorStatus(err error) int {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "stale promote"),
		strings.Contains(msg, "non-monotonic"),
		strings.Contains(msg, "rollback-floor mismatch"):
		return http.StatusConflict
	case strings.Contains(msg, "sign generation"),
		strings.Contains(msg, "persist generation"),
		strings.Contains(msg, "marshal generation"),
		strings.Contains(msg, "load current generation"):
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}
