package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func TestPrepareFirstSidecarClassTableThroughPublisherRoute(t *testing.T) {
	route := newPromoteRoute(t)
	svc := route.svc
	publisher := newTestIdentity(t, "class-publisher", testLicenseMint, "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{publisher.Public().SignPubkeyB58}
	archive := []byte("signed route first sidecar")
	hash := sha256.Sum256(archive)
	name := "class-route-first.tar"
	writeReleaseArtifact(t, svc.cfg.DistDir, "sidecar", name, archive)
	request, err := json.Marshal(stagedSidecarClassRequest{Schema: "melusina.sidecar-classes-prepare.v1",
		StoreID: svc.cfg.StoreID, Rows: []stagedSidecarClassRow{{ID: "first-sidecar",
			Class: componentrelease.AuthoritySidecarCascade, KeyCustody: "none",
			ArtifactName: name, SHA256: hex.EncodeToString(hash[:]), SizeBytes: int64(len(archive))}}})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(request)
	signed, err := envelope.Sign(envelope.KindPublishRequest, publisher, svc.operator.Public(), envelope.SignOptions{
		Method: http.MethodPost, Target: sidecarClassPreparePath, Body: request,
		BodyHash: hex.EncodeToString(digest[:]), RequestHash: hex.EncodeToString(digest[:]), TTL: 5 * time.Minute,
		Chain: envelope.ChainEvidence{ChainID: "solana:devnet", ProgramID: testProg, VerifiedSlot: 42000},
	})
	if err != nil {
		t.Fatal(err)
	}
	envelopeRaw, _ := json.Marshal(signed)
	body, _ := json.Marshal(generationPromoteBody{Envelope: signed, RequestB64: base64.StdEncoding.EncodeToString(request)})
	r := httptest.NewRequest(http.MethodPost, sidecarClassPreparePath, bytes.NewReader(body))
	r.Header.Set(publisherEnvelopeHeader, base64.RawURLEncoding.EncodeToString(envelopeRaw))
	rec := httptest.NewRecorder()
	svc.handlePrepareSidecarClasses(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("FIRST_SIDECAR_CLASS_ROUTE_REFUSED: %d %s", rec.Code, rec.Body.String())
	}
	var table sidecarClassTable
	if json.Unmarshal(rec.Body.Bytes(), &table) != nil || len(table.Rows) != 1 || table.Rows[0].ID != "first-sidecar" {
		t.Fatal("FIRST_SIDECAR_CLASS_ROUTE_WRONG_TABLE")
	}
	r = httptest.NewRequest(http.MethodPost, sidecarClassPreparePath, bytes.NewReader(body))
	r.Header.Set(publisherEnvelopeHeader, base64.RawURLEncoding.EncodeToString(envelopeRaw))
	replay := httptest.NewRecorder()
	svc.handlePrepareSidecarClasses(replay, r)
	if replay.Code == http.StatusOK {
		t.Fatal("FIRST_SIDECAR_CLASS_ROUTE_REPLAY_ACCEPTED")
	}
}

func TestPrepareFirstSidecarClassTableFromStagedBytes(t *testing.T) {
	svc := promoteTestService(t)
	archive := []byte("canonical first sidecar archive")
	hash := sha256.Sum256(archive)
	name := "first-sidecar.tar"
	path := filepath.Join(svc.cfg.DistDir, "releases", "sidecar", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, archive, 0o644); err != nil {
		t.Fatal(err)
	}
	request := stagedSidecarClassRequest{Schema: "melusina.sidecar-classes-prepare.v1",
		StoreID: svc.cfg.StoreID, Rows: []stagedSidecarClassRow{{ID: "first-sidecar",
			Class: componentrelease.AuthoritySidecarCascade, KeyCustody: "none",
			ArtifactName: name, SHA256: hex.EncodeToString(hash[:]), SizeBytes: int64(len(archive))}}}
	now := time.Unix(1791850000, 0)
	table, err := svc.classesFromStagedRequest(request, strings.Repeat("a", 64), now)
	if err != nil {
		t.Fatalf("STAGED_CLASS_TABLE_POSITIVE_REFUSED: %v", err)
	}
	if len(table.Rows) != 1 || table.Rows[0].Source != "staged:"+strings.Repeat("a", 64) ||
		table.Rows[0].Class != componentrelease.AuthoritySidecarCascade {
		t.Fatalf("STAGED_CLASS_TABLE_ROW_CHANGED: %+v", table.Rows)
	}
	message, err := classSigningMessage(table)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := operatorSignPublicKey(svc.operator)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := primitives.DecodeBase58(table.OperatorSignature)
	if err != nil || !ed25519.Verify(publicKey, message, signature) {
		t.Fatal("STAGED_CLASS_TABLE_SIGNATURE_INVALID")
	}

	wrongClass := request
	wrongClass.Rows = append([]stagedSidecarClassRow(nil), request.Rows...)
	wrongClass.Rows[0].Class = componentrelease.AuthoritySidecarIdentity
	if _, err := svc.classesFromStagedRequest(wrongClass, strings.Repeat("a", 64), now); err == nil {
		t.Fatal("STAGED_CLASS_TABLE_CLASS_CUSTODY_MISMATCH_ACCEPTED")
	}
	wrongStore := request
	wrongStore.StoreID = "foreign-store"
	if _, err := svc.classesFromStagedRequest(wrongStore, strings.Repeat("a", 64), now); err == nil {
		t.Fatal("STAGED_CLASS_TABLE_FOREIGN_STORE_ACCEPTED")
	}
	unsafeName := request
	unsafeName.Rows = append([]stagedSidecarClassRow(nil), request.Rows...)
	unsafeName.Rows[0].ArtifactName = "../first-sidecar.tar"
	if _, err := svc.classesFromStagedRequest(unsafeName, strings.Repeat("a", 64), now); err == nil {
		t.Fatal("STAGED_CLASS_TABLE_PATH_TRAVERSAL_ACCEPTED")
	}
	unsafeID := request
	unsafeID.Rows = append([]stagedSidecarClassRow(nil), request.Rows...)
	unsafeID.Rows[0].ID = "../first-sidecar"
	if _, err := svc.classesFromStagedRequest(unsafeID, strings.Repeat("a", 64), now); err == nil {
		t.Fatal("STAGED_CLASS_TABLE_ID_TRAVERSAL_ACCEPTED")
	}
	if err := os.WriteFile(path, []byte("different staged bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.classesFromStagedRequest(request, strings.Repeat("a", 64), now); err == nil {
		t.Fatal("STAGED_CLASS_TABLE_ARCHIVE_DRIFT_ACCEPTED")
	}
}
