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

func TestSidecarClassesProjectionExcludesNonSidecarComponents(t *testing.T) {
	svc := promoteTestService(t)
	c := sidecarComp("fineract", strings.Repeat("a", 64), "v2")
	c.Chain.KeyVersion = 2
	c.Chain.SidecarID = "fineract-v2"
	doc := componentrelease.DesiredGeneration{
		StoreID: svc.cfg.StoreID, OperatorPubkey: "synthetic-projection-key",
		SignedAtUnix: time.Unix(1784281821, 0).Unix(), GenerationHash: strings.Repeat("b", 64),
		Components: []componentrelease.ComponentRelease{c},
	}
	foreignClass := c
	foreignClass.ComponentID = "non-sidecar-component"
	foreignClass.ComponentClass = componentrelease.ClassShell
	doc.Components = append(doc.Components, foreignClass)
	table, err := svc.classesFromGeneration(doc)
	if err != nil || len(table.Rows) != 1 || table.Rows[0].ID != "fineract" {
		t.Fatalf("SIDECAR_CLASS_NON_SIDECAR_COMPONENT_ADMITTED: rows=%+v error=%v", table.Rows, err)
	}
	badAuthority := c
	badAuthority.Chain.Kind = componentrelease.AuthorityInstallerRelease
	doc.Components = []componentrelease.ComponentRelease{badAuthority}
	if _, err := svc.classesFromGeneration(doc); err == nil {
		t.Fatal("SIDECAR_CLASS_WRONG_AUTHORITY_ADMITTED")
	}
	invalidSignedRow := table
	invalidSignedRow.Rows = append([]sidecarClassRow(nil), table.Rows...)
	invalidSignedRow.Rows[0].Class = "unreviewed-authority"
	invalidSignedRow.Rows[0].KeyCustody = "none"
	if _, err := classSigningMessage(invalidSignedRow); err == nil {
		t.Fatal("SIDECAR_CLASS_UNREVIEWED_SIGNED_ROW_ADMITTED")
	}
}
