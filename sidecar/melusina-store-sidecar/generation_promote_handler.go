package main

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
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
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
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"schema": "melusina-generation-promote-readiness-v1",
			"status": "ready",
		})
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

// verifyComponentReleaseOnChain re-verifies ONE component against the chain and
// the served bytes — the store never trusts the publisher's asserted hash/PDA.
// installer_release (shell + data) is fully wired via VerifyInstallerReleaseHash;
// release_v2 (app) and sidecar_identity (sidecar) are fail-closed pending their
// verify wiring (app comes with the app-publisher branch; sidecar with the
// SidecarIdentity + approval-cascade verify).
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
		return s.verifyAppComponentOnChain(ctx, c)
	default:
		return fmt.Errorf("component %s: unknown authority kind %q", c.ComponentID, c.Chain.Kind)
	}
}

// verifyAppComponentOnChain re-derives the ReleaseEntry PDA from the app's
// content hash (the on-chain tree hash, deliberately distinct from the served
// SPK hash), requires that exact account to be Active and hash-pinned, then
// proves the advertised SPK AND catalog metadata recompute to that tree hash.
// Neither a publisher-supplied PDA, a matching artifact hash, nor a
// store-signed pointer alone is authority.
func (s *publishService) verifyAppComponentOnChain(ctx context.Context, c componentrelease.ComponentRelease) error {
	if c.ComponentClass != componentrelease.ClassApp {
		return fmt.Errorf("component %s: release_v2 authority requires app class", c.ComponentID)
	}
	if strings.TrimSpace(c.Chain.Program) != programID.Base58() {
		return fmt.Errorf("component %s: chain program %q != pinned %q", c.ComponentID, c.Chain.Program, programID.Base58())
	}
	contentHash, err := hash32FromHex(c.ContentSHA256)
	if err != nil {
		return fmt.Errorf("component %s: bad app contentSha256: %w", c.ComponentID, err)
	}
	master, err := primitives.PubkeyFromBase58(strings.TrimSpace(c.Chain.MasterNftMint))
	if err != nil {
		return fmt.Errorf("component %s: bad masterNftMint: %w", c.ComponentID, err)
	}
	derived, _, err := pda.Release(master, contentHash, programID)
	if err != nil {
		return fmt.Errorf("component %s: derive ReleaseEntry PDA: %w", c.ComponentID, err)
	}
	claimed, err := primitives.PubkeyFromBase58(strings.TrimSpace(c.Chain.ReleasePDA))
	if err != nil || claimed != derived {
		return fmt.Errorf("component %s: ReleaseEntry PDA does not equal the locally derived content-hash PDA", c.ComponentID)
	}
	meta, err := s.cr.FetchReleaseEntryMeta(ctx, derived.Base58())
	if err != nil {
		return fmt.Errorf("component %s: fetch ReleaseEntry %s: %w", c.ComponentID, derived.Base58(), err)
	}
	if meta.AppHash != contentHash {
		return fmt.Errorf("component %s: on-chain app_hash %x != contentSha256 %x", c.ComponentID, meta.AppHash[:], contentHash[:])
	}
	if err := meta.Status.RequireActive(); err != nil {
		return fmt.Errorf("component %s: ReleaseEntry not Active: %w", c.ComponentID, err)
	}
	return s.verifyAppComponentServedBytes(c)
}

// verifyAppComponentServedBytes binds an app-class ComponentRelease to the
// store's already-signed catalog selection. Apps are deliberately different
// from host artifacts: their SPKs are served as /packages/<packageId>, never
// under /releases/. A matching ReleaseEntry and an arbitrary SPK hash are not
// enough; the exact current signed pointer and apps/index.json must select the
// same package for the same app before a DesiredGeneration may name it.
func (s *publishService) verifyAppComponentServedBytes(c componentrelease.ComponentRelease) error {
	if s.operator == nil {
		return fmt.Errorf("component %s: store operator identity is required to verify app catalog pointer", c.ComponentID)
	}
	origin := strings.TrimRight(strings.TrimSpace(s.cfg.PublicBaseURL), "/")
	prefix := origin + "/packages/"
	if !strings.HasPrefix(c.BundleURL, prefix) {
		return fmt.Errorf("component %s: app bundleUrl %q is not an exact package URL under %s", c.ComponentID, c.BundleURL, prefix)
	}
	packageID := strings.TrimPrefix(c.BundleURL, prefix)
	if !validCatalogPackageID(packageID) {
		return fmt.Errorf("component %s: app bundleUrl packageId %q is invalid", c.ComponentID, packageID)
	}
	if strings.TrimSpace(c.ArtifactName) != packageID {
		return fmt.Errorf("component %s: app artifactName %q != bundle packageId %q", c.ComponentID, c.ArtifactName, packageID)
	}
	if !isSafePathSegment(c.ComponentID) {
		return fmt.Errorf("component %s: unsafe appId", c.ComponentID)
	}

	// App publishing atomically switches the immutable catalog/current
	// generation. The HTTP reader resolves that generation once for every
	// request, so generation promotion must verify the same served snapshot
	// rather than the legacy flat staging directory. Otherwise a valid signed
	// pointer can be visible to consumers while this gate incorrectly reports it
	// missing from the old flat tree.
	catalogRoot, err := s.servedAppCatalogRoot()
	if err != nil {
		return fmt.Errorf("component %s: resolve served app catalog: %w", c.ComponentID, err)
	}
	pointerPath := filepath.Join(catalogRoot, "apps", "pointers", c.ComponentID+".json")
	pointerBody, err := readDistRegularNoFollow(pointerPath, maxAppCatalogJSONBytes)
	if err != nil {
		return fmt.Errorf("component %s: read signed app catalog pointer: %w", c.ComponentID, err)
	}
	if err := assertNoDuplicateJSONKeys(pointerBody); err != nil {
		return fmt.Errorf("component %s: signed app catalog pointer: %w", c.ComponentID, err)
	}
	var pointer AppCatalogPointer
	dec := json.NewDecoder(bytes.NewReader(pointerBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pointer); err != nil {
		return fmt.Errorf("component %s: decode signed app catalog pointer: %w", c.ComponentID, err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return fmt.Errorf("component %s: signed app catalog pointer has trailing data", c.ComponentID)
	}
	operatorPub, err := operatorSignPublicKey(s.operator)
	if err != nil {
		return fmt.Errorf("component %s: operator public key: %w", c.ComponentID, err)
	}
	if err := verifyAppCatalogPointer(operatorPub, pointer); err != nil {
		return fmt.Errorf("component %s: signed app catalog pointer: %w", c.ComponentID, err)
	}
	domainHash := primitives.StoreDomainHash(s.cfg.Domain)
	wantDomainHash := hex.EncodeToString(domainHash[:])
	if pointer.AppID != c.ComponentID || pointer.PackageID != packageID ||
		pointer.Version != c.Version || pointer.AppHash != c.ContentSHA256 ||
		pointer.ServingDomainHash != wantDomainHash {
		return fmt.Errorf("component %s: signed app catalog pointer does not bind this app/package/version/content/domain", c.ComponentID)
	}
	if c.ReleaseHash != "" && pointer.ReleaseHash != c.ReleaseHash {
		return fmt.Errorf("component %s: signed app catalog pointer releaseHash mismatch", c.ComponentID)
	}
	if c.StageID != "" && pointer.StageID != c.StageID {
		return fmt.Errorf("component %s: signed app catalog pointer stageId mismatch", c.ComponentID)
	}

	indexBody, err := readDistRegularNoFollow(filepath.Join(catalogRoot, "apps", "index.json"), maxAppCatalogJSONBytes)
	if err != nil {
		return fmt.Errorf("component %s: read app catalog index: %w", c.ComponentID, err)
	}
	if err := assertNoDuplicateJSONKeys(indexBody); err != nil {
		return fmt.Errorf("component %s: app catalog index: %w", c.ComponentID, err)
	}
	indexHash := sha256.Sum256(indexBody)
	if pointer.CatalogSHA256 != hex.EncodeToString(indexHash[:]) {
		return fmt.Errorf("component %s: signed app catalog pointer catalog sha256 mismatch", c.ComponentID)
	}
	var index catalogIndex
	if err := json.Unmarshal(indexBody, &index); err != nil {
		return fmt.Errorf("component %s: decode app catalog index: %w", c.ComponentID, err)
	}
	found := false
	for _, app := range index.Apps {
		if strings.TrimSpace(app.AppID) != c.ComponentID {
			continue
		}
		if found || strings.TrimSpace(app.PackageID) != packageID {
			return fmt.Errorf("component %s: app catalog does not select exactly the signed package", c.ComponentID)
		}
		found = true
	}
	if !found {
		return fmt.Errorf("component %s: app catalog has no selected package", c.ComponentID)
	}
	metadataPath := filepath.Join(catalogRoot, "signatures", c.ComponentID, "metadata.json")
	metadata, err := readDistRegularNoFollow(metadataPath, maxAppCatalogJSONBytes)
	if err != nil {
		return fmt.Errorf("component %s: read served app metadata: %w", c.ComponentID, err)
	}

	packagePath := filepath.Join(catalogRoot, "packages", packageID)
	f, size, err := openDistRegularNoFollow(packagePath)
	if err != nil {
		return fmt.Errorf("component %s: open served app package: %w", c.ComponentID, err)
	}
	defer f.Close()
	if size != c.SizeBytes {
		return fmt.Errorf("component %s: served app package size %d != component size %d", c.ComponentID, size, c.SizeBytes)
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return fmt.Errorf("component %s: hash served app package: %w", c.ComponentID, err)
	}
	if n != c.SizeBytes {
		return fmt.Errorf("component %s: served app package size %d != component size %d", c.ComponentID, n, c.SizeBytes)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != strings.ToLower(strings.TrimSpace(c.SHA256)) {
		return fmt.Errorf("component %s: served app package sha256 %s != component sha256 %s", c.ComponentID, got, c.SHA256)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("component %s: rewind served app package for content binding: %w", c.ComponentID, err)
	}
	gotContentHash, err := apphash.Canonical(f, metadata)
	if err != nil {
		return fmt.Errorf("component %s: recompute served app contentSha256: %w", c.ComponentID, err)
	}
	if gotContentHash != strings.ToLower(strings.TrimSpace(c.ContentSHA256)) {
		return fmt.Errorf("component %s: served {app.spk,metadata.json} contentSha256 %s != component contentSha256 %s", c.ComponentID, gotContentHash, c.ContentSHA256)
	}
	return nil
}

// servedAppCatalogRoot returns the exact catalog root exposed by the app HTTP
// surface. Older stores serve directly from DistDir; generation-aware stores
// serve only from their selected immutable catalog generation.
func (s *publishService) servedAppCatalogRoot() (string, error) {
	if strings.TrimSpace(s.catalogGenerations.Root) == "" {
		return s.cfg.DistDir, nil
	}
	current, err := s.catalogGenerations.ResolveCurrent()
	if err != nil {
		return "", err
	}
	return current.Root, nil
}

// readDistRegularNoFollow reads a bounded, final regular file from the serving
// tree. Promotion is an authority decision, so an Lstat followed by os.ReadFile
// is insufficient: a replace-to-symlink race would otherwise let bytes outside
// DistDir participate in an on-chain promotion. The descriptor is the object
// that is checked and read.
func readDistRegularNoFollow(path string, limit int64) ([]byte, error) {
	f, size, err := openDistRegularNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if size > limit {
		return nil, fmt.Errorf("regular file size %d exceeds cap %d", size, limit)
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("regular file grew beyond cap %d while reading", limit)
	}
	return body, nil
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
	f, err := os.Open(p)
	if err != nil {
		return fmt.Errorf("component %s: served artifact not found (%s): %w", c.ComponentID, rel, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("component %s: stat served artifact: %w", c.ComponentID, err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("component %s: served artifact is not a regular file", c.ComponentID)
	}
	if st.Size() != c.SizeBytes {
		return fmt.Errorf("component %s: served artifact size %d != component size %d", c.ComponentID, st.Size(), c.SizeBytes)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("component %s: hash served artifact: %w", c.ComponentID, err)
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
