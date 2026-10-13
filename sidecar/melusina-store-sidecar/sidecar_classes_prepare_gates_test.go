package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

// Each authorization gate on POST /publish/sidecar-classes is isolated: the
// request is otherwise exactly the admitted positive, and only one gate's input
// changes. A refused request must name its gate and return no signed table.
func TestPrepareSidecarClassesRouteGates(t *testing.T) {
	route := newPromoteRoute(t)
	svc := route.svc
	publisher := newTestIdentity(t, "class-gate-publisher", testLicenseMint, "publisher.example.org")
	stranger := newTestIdentity(t, "class-gate-stranger", testLicenseMint, "stranger.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{publisher.Public().SignPubkeyB58}
	archive := []byte("class gate sidecar archive")
	hash := sha256.Sum256(archive)
	name := "class-gate-sidecar.tar"
	writeReleaseArtifact(t, svc.cfg.DistDir, "sidecar", name, archive)
	request, err := json.Marshal(stagedSidecarClassRequest{Schema: "melusina.sidecar-classes-prepare.v1",
		StoreID: svc.cfg.StoreID, Rows: []stagedSidecarClassRow{{ID: "class-gate-sidecar",
			Class: componentrelease.AuthoritySidecarCascade, KeyCustody: "none",
			ArtifactName: name, SHA256: hex.EncodeToString(hash[:]), SizeBytes: int64(len(archive))}}})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(request)
	slot := uint64(43000)
	sign := func(signer *identity.Private, target string) (envelope.Signed, []byte) {
		t.Helper()
		slot++
		signed, err := envelope.Sign(envelope.KindPublishRequest, signer, svc.operator.Public(), envelope.SignOptions{
			Method: http.MethodPost, Target: target, Body: request,
			BodyHash: hex.EncodeToString(digest[:]), RequestHash: hex.EncodeToString(digest[:]), TTL: 5 * time.Minute,
			Chain: envelope.ChainEvidence{ChainID: "solana:devnet", ProgramID: testProg, VerifiedSlot: slot},
		})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		return signed, raw
	}
	post := func(header []byte, body envelope.Signed) *httptest.ResponseRecorder {
		t.Helper()
		wire, err := json.Marshal(generationPromoteBody{Envelope: body, RequestB64: base64.StdEncoding.EncodeToString(request)})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, sidecarClassPreparePath, bytes.NewReader(wire))
		if header != nil {
			r.Header.Set(publisherEnvelopeHeader, base64.RawURLEncoding.EncodeToString(header))
		}
		rec := httptest.NewRecorder()
		svc.handlePrepareSidecarClasses(rec, r)
		return rec
	}
	refused := func(rec *httptest.ResponseRecorder, code int, check, name string) {
		t.Helper()
		if rec.Code != code || !strings.Contains(rec.Body.String(), check) || strings.Contains(rec.Body.String(), "operatorSignature") {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}

	// No pre-body publisher header: the body envelope alone must not admit.
	body, _ := sign(publisher, sidecarClassPreparePath)
	refused(post(nil, body), http.StatusUnauthorized, "check=envelope_header", "SIDECAR_CLASS_PREPARE_HEADERLESS_ACCEPTED")

	// Accepted header, body envelope from a publisher outside accept_publishers.
	_, header := sign(publisher, sidecarClassPreparePath)
	foreignBody, _ := sign(stranger, sidecarClassPreparePath)
	refused(post(header, foreignBody), http.StatusForbidden, "check=accept_publishers", "SIDECAR_CLASS_PREPARE_UNKNOWN_BODY_PUBLISHER_ACCEPTED")

	// Accepted header, body envelope signed by the accepted publisher for a
	// different route over the same request bytes.
	_, header = sign(publisher, sidecarClassPreparePath)
	otherRoute, _ := sign(publisher, "/publish/generation")
	refused(post(header, otherRoute), http.StatusUnauthorized, "check=envelope_purpose", "SIDECAR_CLASS_PREPARE_FOREIGN_ROUTE_BODY_ACCEPTED")

	// The Store's operator key is not the active on-chain Store operator.
	admitted := svc.cr
	svc.cr = newMockChainReader()
	body, header = sign(publisher, sidecarClassPreparePath)
	refused(post(header, body), http.StatusForbidden, "check=store_operator", "SIDECAR_CLASS_PREPARE_UNVERIFIED_STORE_OPERATOR_ACCEPTED")
	svc.cr = admitted

	// Positive control: the same construction with every gate satisfied.
	body, header = sign(publisher, sidecarClassPreparePath)
	if rec := post(header, body); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "operatorSignature") {
		t.Fatalf("SIDECAR_CLASS_PREPARE_GATE_POSITIVE_REFUSED: %d %s", rec.Code, rec.Body.String())
	}
}
