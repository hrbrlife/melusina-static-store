package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func TestSidecarClassesCurrentSignedGeneration(t *testing.T) {
	svc := promoteTestService(t)
	body := []byte("canonical sidecar archive")
	sum := sha256.Sum256(body)
	c := sidecarComp("fineract", hex.EncodeToString(sum[:]), "v2")
	c.SizeBytes = int64(len(body))
	c.Chain.KeyVersion = 2
	c.Chain.SidecarID = "fineract-v2"
	writeReleaseArtifact(t, svc.cfg.DistDir, "sidecar", c.ArtifactName, body)
	if _, err := svc.promoteGeneration(promoteReq(0, c), time.Unix(1784281821, 0)); err != nil {
		t.Fatalf("promote: %v", err)
	}
	get := func() *httptest.ResponseRecorder {
		r := httptest.NewRecorder()
		svc.handleSidecarClasses(r, httptest.NewRequest(http.MethodGet, "/update/sidecar-classes-v1.json", nil))
		return r
	}
	r := get()
	if r.Code != http.StatusOK {
		t.Fatalf("signed table: %d %s", r.Code, r.Body.String())
	}
	var table sidecarClassTable
	if err := json.Unmarshal(r.Body.Bytes(), &table); err != nil {
		t.Fatal(err)
	}
	if len(table.Rows) != 1 || table.Rows[0].ID != "fineract" ||
		table.Rows[0].Class != componentrelease.AuthoritySidecarIdentity ||
		table.Rows[0].KeyCustody != "sidecar-held-identity" {
		t.Fatalf("wrong generated row: %+v", table.Rows)
	}
	message, err := classSigningMessage(table)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := primitives.DecodeBase58(table.OperatorSignature)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := operatorSignPublicKey(svc.operator)
	if !ed25519.Verify(pub, message, signature) {
		t.Fatal("operator signature does not verify")
	}
	// Named mutation: the signed generation's artifact is no longer served.
	if err := os.WriteFile(filepath.Join(svc.cfg.DistDir, "releases", "sidecar", c.ArtifactName), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	r = get()
	if r.Code != http.StatusServiceUnavailable || !strings.Contains(r.Body.String(), "check=sidecar_classes") {
		t.Fatalf("mutated archive served a class table: %d %s", r.Code, r.Body.String())
	}
}
