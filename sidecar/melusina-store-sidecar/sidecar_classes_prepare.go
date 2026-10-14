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
	"regexp"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const sidecarClassPreparePath = "/publish/sidecar-classes"

var stagedClassComponentID = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`)

type stagedSidecarClassRow struct {
	ID           string                           `json:"id"`
	Class        string                           `json:"class"`
	KeyCustody   string                           `json:"keyCustody"`
	ArtifactName string                           `json:"artifactName"`
	SHA256       string                           `json:"sha256"`
	SizeBytes    int64                            `json:"sizeBytes"`
	Chain        *componentrelease.ChainAuthority `json:"chain,omitempty"`
}

const parentSidecarPrepareSchema = "melusina.sidecar-classes-parent-prepare.v1"

func (s *publishService) classesFromParentStagedRequest(ctx context.Context, req stagedSidecarClassRequest, requestHash string, now time.Time) (sidecarClassTable, error) {
	if req.Schema != parentSidecarPrepareSchema || s.cr == nil {
		return sidecarClassTable{}, errors.New("sidecar-parent-prepare-invalid")
	}
	base := req
	base.Schema = "melusina.sidecar-classes-prepare.v1"
	table, err := s.classesFromStagedRequest(base, requestHash, now)
	if err != nil {
		return sidecarClassTable{}, err
	}
	_, ok := s.cr.(rawAccountReader)
	if !ok {
		return sidecarClassTable{}, errors.New("sidecar-parent-prepare-chain-reader-required")
	}
	mr, ok := s.cr.(multiAccountReader)
	if !ok {
		return sidecarClassTable{}, errors.New("sidecar-parent-prepare-batch-reader-required")
	}
	type parentCheck struct {
		id   string
		view componentReleaseChainView
		hash [32]byte
	}
	checks := make([]parentCheck, 0, len(req.Rows))
	addresses := make([]string, 0, 2*len(req.Rows)+1)
	seen := make(map[string]bool, 2*len(req.Rows)+1)
	appendAddress := func(address string) {
		if !seen[address] {
			seen[address] = true
			addresses = append(addresses, address)
		}
	}
	for _, row := range req.Rows {
		chain := row.Chain
		wantSidecarID := row.ID
		if row.ID == "fineract" {
			wantSidecarID = "fineract-v2"
		}
		if chain == nil || chain.Kind != row.Class || chain.Program != licenseRegistryProgramID().Base58() || chain.SidecarID != wantSidecarID || chain.IdentityPDA != "" && chain.Kind == componentrelease.AuthoritySidecarCascade {
			return sidecarClassTable{}, fmt.Errorf("sidecar-parent-prepare-chain-invalid:%s", row.ID)
		}
		license, err := primitives.PubkeyFromBase58(chain.LicenseNftMint)
		if err != nil {
			return sidecarClassTable{}, fmt.Errorf("sidecar-parent-prepare-license-invalid:%s", row.ID)
		}
		master, err := primitives.PubkeyFromBase58(chain.MasterNftMint)
		if err != nil {
			return sidecarClassTable{}, fmt.Errorf("sidecar-parent-prepare-master-invalid:%s", row.ID)
		}
		if chain.MasterNftMint != s.cfg.ReleaseMasterNftMint {
			return sidecarClassTable{}, fmt.Errorf("sidecar-parent-prepare-store-master-mismatch:%s", row.ID)
		}
		reseller, err := primitives.PubkeyFromBase58(s.cfg.ResellerNFTMint)
		if err != nil {
			return sidecarClassTable{}, fmt.Errorf("sidecar-parent-prepare-store-reseller-invalid:%s", row.ID)
		}
		global, _, err := primitives.DeriveGlobalSidecar(master, chain.SidecarID, licenseRegistryProgramID())
		if err != nil || chain.GlobalApprovalPDA != global.Base58() {
			return sidecarClassTable{}, fmt.Errorf("sidecar-parent-prepare-global-pda-invalid:%s", row.ID)
		}
		local, _, err := primitives.DeriveLocalSidecar(license, chain.SidecarID, licenseRegistryProgramID())
		if err != nil || chain.LocalApprovalPDA != local.Base58() {
			return sidecarClassTable{}, fmt.Errorf("sidecar-parent-prepare-local-pda-invalid:%s", row.ID)
		}
		if chain.Kind == componentrelease.AuthoritySidecarIdentity {
			identity, _, err := primitives.DeriveSidecarIdentity(license, chain.SidecarID, chain.KeyVersion, licenseRegistryProgramID())
			if err != nil || chain.KeyVersion == 0 || chain.IdentityPDA != identity.Base58() {
				return sidecarClassTable{}, fmt.Errorf("sidecar-parent-prepare-identity-pda-invalid:%s", row.ID)
			}
		} else if chain.KeyVersion != 0 || chain.IdentityPDA != "" {
			return sidecarClassTable{}, fmt.Errorf("sidecar-parent-prepare-keyless-identity-invalid:%s", row.ID)
		}
		hash, err := hash32FromHex(row.SHA256)
		if err != nil {
			return sidecarClassTable{}, fmt.Errorf("sidecar-parent-prepare-hash-invalid:%s", row.ID)
		}
		view := componentReleaseChainView{sidecarID: chain.SidecarID, licenseMint: license, masterMint: master, resellerMint: reseller, pinMaster: true, keyless: chain.Kind == componentrelease.AuthoritySidecarCascade}
		resellerApproval, _, err := primitives.DeriveResellerSidecar(reseller, chain.SidecarID, licenseRegistryProgramID())
		if err != nil {
			return sidecarClassTable{}, fmt.Errorf("sidecar-parent-prepare-reseller-pda-invalid:%s: %w", row.ID, err)
		}
		resellerEntry, _, err := primitives.FindProgramAddress([][]byte{[]byte("reseller"), reseller[:]}, licenseRegistryProgramID(), nil)
		if err != nil {
			return sidecarClassTable{}, fmt.Errorf("sidecar-parent-prepare-reseller-entry-pda-invalid:%s: %w", row.ID, err)
		}
		appendAddress(global.Base58())
		appendAddress(resellerApproval.Base58())
		appendAddress(resellerEntry.Base58())
		checks = append(checks, parentCheck{id: row.ID, view: view, hash: hash})
	}
	values, err := mr.fetchMultipleAccounts(ctx, addresses)
	if err != nil {
		return sidecarClassTable{}, fmt.Errorf("sidecar-parent-prepare-parent-read: %w", err)
	}
	if len(values) != len(addresses) {
		return sidecarClassTable{}, errors.New("sidecar-parent-prepare-parent-read-length-invalid")
	}
	snapshot := parentAccountSnapshot{accounts: make(map[string]accountValue, len(addresses))}
	for i, address := range addresses {
		snapshot.accounts[address] = values[i]
	}
	// Run the existing cascade decoder and authorization checks on the bounded
	// chain snapshot. The raw reader assertion above keeps the same capability
	// requirement as the original parent preparation path.
	for _, check := range checks {
		if err := checkSidecarParents(ctx, snapshot, check.view, check.hash); err != nil {
			return sidecarClassTable{}, fmt.Errorf("sidecar-parent-prepare-parent-refused:%s: %w", check.id, err)
		}
	}
	return table, nil
}

// parentAccountSnapshot refuses an unplanned address; an absent planned
// account remains absent so the ordinary cascade check fails closed.
type parentAccountSnapshot struct{ accounts map[string]accountValue }

func (s parentAccountSnapshot) fetchRawAccount(_ context.Context, address string) ([]byte, string, error) {
	value, planned := s.accounts[address]
	if !planned {
		return nil, "", fmt.Errorf("sidecar-parent-prepare-unplanned-account:%s", address)
	}
	if !value.present {
		return nil, "", nil
	}
	return value.data, value.owner, nil
}

type stagedSidecarClassRequest struct {
	Schema  string                  `json:"schema"`
	StoreID string                  `json:"storeId"`
	Rows    []stagedSidecarClassRow `json:"rows"`
}

// The table signs only class declarations for exact staged bytes. It gives no
// artifact serving authority: generation promotion still checks the chain,
// the complete cascade and those same bytes before anything can be served.
func (s *publishService) classesFromStagedRequest(req stagedSidecarClassRequest, requestHash string, now time.Time) (sidecarClassTable, error) {
	if s.operator == nil || req.Schema != "melusina.sidecar-classes-prepare.v1" ||
		req.StoreID != s.cfg.StoreID || len(req.Rows) < 1 || len(req.Rows) > 32 ||
		len(requestHash) != 64 || now.Unix() <= 0 {
		return sidecarClassTable{}, errors.New("sidecar-class-prepare-invalid")
	}
	origin := strings.TrimRight(strings.TrimSpace(s.cfg.PublicBaseURL), "/")
	if origin == "" {
		return sidecarClassTable{}, errors.New("sidecar-class-prepare-origin-missing")
	}
	pub, err := operatorSignPublicKey(s.operator)
	if err != nil {
		return sidecarClassTable{}, err
	}
	// A prepared table can add first-cohort classifications only. Once a
	// signed generation classifies an ID, its served class table is authoritative.
	classified := make(map[string]bool)
	if current, _, err := s.loadVerifiedDesiredGeneration(); err == nil {
		for _, component := range current.Components {
			if component.ComponentClass == componentrelease.ClassSidecar {
				classified[component.ComponentID] = true
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return sidecarClassTable{}, fmt.Errorf("sidecar-class-prepare-current-generation: %w", err)
	}
	table := sidecarClassTable{Schema: "melusina.sidecar-classes.v1", StoreID: req.StoreID,
		OperatorPubkey: primitives.EncodeBase58(pub), SignedAtUnix: now.Unix(), Rows: make([]sidecarClassRow, 0, len(req.Rows))}
	stamp := now.UTC().Truncate(time.Second).Format(time.RFC3339)
	previous := ""
	for _, row := range req.Rows {
		if !stagedClassComponentID.MatchString(row.ID) {
			return sidecarClassTable{}, fmt.Errorf("sidecar-class-prepare-id-invalid:%s", row.ID)
		}
		if classified[row.ID] {
			return sidecarClassTable{}, fmt.Errorf("sidecar-class-prepare-already-classified:%s", row.ID)
		}
		if row.ID <= previous || row.SizeBytes <= 0 || row.SizeBytes > 1<<31 ||
			len(row.SHA256) != 64 || strings.ToLower(row.SHA256) != row.SHA256 ||
			(row.Class == componentrelease.AuthoritySidecarCascade && row.KeyCustody != "none") ||
			(row.Class == componentrelease.AuthoritySidecarIdentity && row.KeyCustody != "sidecar-held-identity") ||
			!componentrelease.IsSidecarAuthority(row.Class) {
			return sidecarClassTable{}, fmt.Errorf("sidecar-class-prepare-row-invalid:%s", row.ID)
		}
		if _, err := hex.DecodeString(row.SHA256); err != nil {
			return sidecarClassTable{}, fmt.Errorf("sidecar-class-prepare-hash-invalid:%s", row.ID)
		}
		component := componentrelease.ComponentRelease{ComponentID: row.ID,
			ComponentClass: componentrelease.ClassSidecar, ArtifactName: row.ArtifactName,
			SHA256: row.SHA256, SizeBytes: row.SizeBytes,
			BundleURL: componentrelease.ReleaseBundleURL(origin, componentrelease.ClassSidecar, row.ArtifactName)}
		if err := s.verifyComponentServedBytes(component); err != nil {
			return sidecarClassTable{}, fmt.Errorf("sidecar-class-prepare-staged-bytes:%s: %w", row.ID, err)
		}
		table.Rows = append(table.Rows, sidecarClassRow{ID: row.ID, Class: row.Class,
			KeyCustody: row.KeyCustody, DeclaredAt: stamp, Source: "staged:" + requestHash})
		previous = row.ID
	}
	message, err := classSigningMessage(table)
	if err != nil {
		return sidecarClassTable{}, err
	}
	table.OperatorSignature = primitives.EncodeBase58(s.operator.Sign(message))
	return table, nil
}

// POST uses the same publisher envelope and on-chain Store-operator check as
// generation promotion. Its response is signed and fetched over the pinned
// Store TLS origin; no direct served-file edit or local key export is needed.
func (s *publishService) handlePrepareSidecarClasses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if rejectReceiveBypass(w) || !s.requirePublisherHeader(w, r, sidecarClassPreparePath) {
		return
	}
	if s.cr == nil || s.operator == nil {
		http.Error(w, "sidecar class prepare gate not initialized", http.StatusServiceUnavailable)
		return
	}
	if err := limitPublishBody(r, maxGenerationPromoteBody); err != nil {
		http.Error(w, "check=request: "+err.Error(), http.StatusBadRequest)
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil || assertNoDuplicateJSONKeys(raw) != nil {
		http.Error(w, "check=request: ambiguous or unreadable", http.StatusBadRequest)
		return
	}
	var body generationPromoteBody
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&body) != nil || dec.Decode(new(json.RawMessage)) != io.EOF {
		http.Error(w, "check=request: invalid wrapper", http.StatusBadRequest)
		return
	}
	requestBytes, err := base64.StdEncoding.DecodeString(body.RequestB64)
	if err != nil || len(requestBytes) == 0 || len(requestBytes) > 1<<20 || assertNoDuplicateJSONKeys(requestBytes) != nil {
		http.Error(w, "check=request: invalid body", http.StatusBadRequest)
		return
	}
	hash := sha256.Sum256(requestBytes)
	hashHex := hex.EncodeToString(hash[:])
	if err := requireEnvelopePresent(body.Envelope); err != nil {
		http.Error(w, "check=envelope: "+err.Error(), http.StatusUnauthorized)
		return
	}
	signerKey, ok := s.resolveAcceptedPublisherKey(body.Envelope.Payload.Source)
	if !ok {
		http.Error(w, "check=accept_publishers: unknown publisher", http.StatusForbidden)
		return
	}
	bodyEnvelope, err := json.Marshal(body.Envelope)
	if err != nil || matchPublisherHeader(r, bodyEnvelope) != nil {
		http.Error(w, "check=envelope_header_body_mismatch", http.StatusUnauthorized)
		return
	}
	if body.Envelope.Payload.Method != http.MethodPost || body.Envelope.Payload.Target != sidecarClassPreparePath {
		http.Error(w, "check=envelope_purpose: wrong route", http.StatusUnauthorized)
		return
	}
	operatorIdentity := s.operator.Public()
	if err := s.verifyDurableEnvelope(body.Envelope, envelope.VerifyOptions{
		ExpectedKind: envelope.KindPublishRequest, ExpectedSignerPubkeyB58: signerKey,
		ExpectedDestination: &operatorIdentity, ExpectedRequestHash: hashHex,
	}); err != nil {
		http.Error(w, "check=envelope: "+err.Error(), http.StatusUnauthorized)
		return
	}
	var req stagedSidecarClassRequest
	requestDecoder := json.NewDecoder(bytes.NewReader(requestBytes))
	requestDecoder.DisallowUnknownFields()
	if requestDecoder.Decode(&req) != nil || requestDecoder.Decode(new(json.RawMessage)) != io.EOF {
		http.Error(w, "check=sidecar_class_request: invalid", http.StatusBadRequest)
		return
	}
	operatorPub, err := signPubkey32(operatorIdentity)
	if err != nil {
		http.Error(w, "check=operator_key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, err := VerifyStoreOperator(r.Context(), s.cr, s.cfg, operatorPub, false); err != nil {
		http.Error(w, "check=store_operator: "+err.Error(), http.StatusForbidden)
		return
	}
	var table sidecarClassTable
	if req.Schema == parentSidecarPrepareSchema {
		table, err = s.classesFromParentStagedRequest(r.Context(), req, hashHex, s.currentTime())
	} else {
		table, err = s.classesFromStagedRequest(req, hashHex, s.currentTime())
	}
	if err != nil {
		http.Error(w, "check=sidecar_classes: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(table)
}
