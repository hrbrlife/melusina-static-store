package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	ID           string `json:"id"`
	Class        string `json:"class"`
	KeyCustody   string `json:"keyCustody"`
	ArtifactName string `json:"artifactName"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"sizeBytes"`
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
	table := sidecarClassTable{Schema: "melusina.sidecar-classes.v1", StoreID: req.StoreID,
		OperatorPubkey: primitives.EncodeBase58(pub), SignedAtUnix: now.Unix(), Rows: make([]sidecarClassRow, 0, len(req.Rows))}
	stamp := now.UTC().Truncate(time.Second).Format(time.RFC3339)
	previous := ""
	for _, row := range req.Rows {
		if !stagedClassComponentID.MatchString(row.ID) {
			return sidecarClassTable{}, fmt.Errorf("sidecar-class-prepare-id-invalid:%s", row.ID)
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
	table, err := s.classesFromStagedRequest(req, hashHex, s.currentTime())
	if err != nil {
		http.Error(w, "check=sidecar_classes: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(table)
}
