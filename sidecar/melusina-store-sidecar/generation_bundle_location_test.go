package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

// Seam audit round 2, findings 11 and 12. The typed installer refuses a
// generation whose component artifactName is not the escaped bundleUrl basename,
// and refuses an artifact whose release-gate class (the /releases/<class>/ path
// segment, sent as X-Store-Release-Class) is not the signed componentClass. The
// Store used to promote and serve both. These tests stage REAL bytes at the
// misplaced path, so each refusal below is the location rule and not a missing
// file.

// misplacedShell returns a shell component whose bytes are staged, byte-exact,
// under /releases/deployer/ — what `submit-installer --class deployer` produces
// — and the same component correctly placed under /releases/shell/.
func misplacedShell(t *testing.T, svc *publishService, tag string) (misplaced, placed componentrelease.ComponentRelease) {
	t.Helper()
	placed = promotableShellComp(t, svc, tag, "build-1")
	body := []byte("generation-promote-public-bundle:" + tag)
	writeReleaseArtifact(t, svc.cfg.DistDir, "deployer", placed.ArtifactName, body)
	misplaced = placed
	misplaced.BundleURL = svc.cfg.PublicBaseURL + "/releases/deployer/" + placed.ArtifactName
	return misplaced, placed
}

func TestPromoteGenerationRefusesMisplacedBundleByName(t *testing.T) {
	svc := promoteTestService(t)
	misplaced, placed := misplacedShell(t, svc, "location")
	now := time.Unix(1784281821, 0)

	if _, err := svc.promoteGeneration(promoteReq(0, misplaced), now); !errors.Is(err, componentrelease.ErrBundleURLNotReleasePath) {
		t.Fatalf("shell at /releases/deployer/: want %v, got %v", componentrelease.ErrBundleURLNotReleasePath, err)
	}
	renamed := placed
	renamed.ArtifactName = "sandstorm-build-65.tar.xz"
	if _, err := svc.promoteGeneration(promoteReq(0, renamed), now); !errors.Is(err, componentrelease.ErrArtifactNameNotBundleBasename) {
		t.Fatalf("artifactName not the bundleUrl basename: want %v, got %v", componentrelease.ErrArtifactNameNotBundleBasename, err)
	}
	if cur, err := svc.loadCurrentGenerationOrNil(); err != nil || cur != nil {
		t.Fatalf("a refused promote persisted a generation: %v %v", cur, err)
	}

	// POSITIVE CONTROL: the same bytes and facts at /releases/shell/ promote and
	// are served.
	if _, err := svc.promoteGeneration(promoteReq(0, placed), now); err != nil {
		t.Fatalf("positive control: correctly placed shell refused: %v", err)
	}
	if doc, code := servedGeneration(t, svc); code != http.StatusOK || doc.GenerationID != 1 {
		t.Fatalf("positive control: served generation %d status %d", doc.GenerationID, code)
	}
}

func TestVerifyComponentServedBytesRefusesForeignClassSegment(t *testing.T) {
	svc := promoteTestService(t)
	misplaced, placed := misplacedShell(t, svc, "served-bytes")

	// The bytes exist and hash correctly under /releases/deployer/, and that
	// path used to satisfy the "/releases/" prefix check.
	if err := svc.verifyComponentServedBytes(misplaced); !errors.Is(err, componentrelease.ErrBundleURLNotReleasePath) {
		t.Fatalf("served-bytes check: want %v, got %v", componentrelease.ErrBundleURLNotReleasePath, err)
	}
	// The serve surface of /update/generation.json runs the same check.
	doc := componentrelease.DesiredGeneration{Components: []componentrelease.ComponentRelease{misplaced}}
	if err := svc.verifyDesiredGenerationServeSurface(doc); !errors.Is(err, componentrelease.ErrBundleURLNotReleasePath) {
		t.Fatalf("serve surface: want %v, got %v", componentrelease.ErrBundleURLNotReleasePath, err)
	}
	renamed := placed
	renamed.ArtifactName = "sandstorm-build-65.tar.xz"
	if err := svc.verifyComponentServedBytes(renamed); !errors.Is(err, componentrelease.ErrArtifactNameNotBundleBasename) {
		t.Fatalf("served-bytes check: want %v, got %v", componentrelease.ErrArtifactNameNotBundleBasename, err)
	}
	// POSITIVE CONTROL.
	if err := svc.verifyComponentServedBytes(placed); err != nil {
		t.Fatalf("positive control: correctly placed shell refused: %v", err)
	}
	doc.Components = []componentrelease.ComponentRelease{placed}
	if err := svc.verifyDesiredGenerationServeSurface(doc); err != nil {
		t.Fatalf("positive control: serve surface refused a correctly placed shell: %v", err)
	}
}

// TestHandleGeneratePromoteRefusesMisplacedBundleByName drives the real route
// with an accepted publisher's route-bound envelope. The misplaced request is
// refused at check=component_bundle_location (400); the correctly placed one
// passes that check and is stopped by the NEXT gate, store_operator (the mock
// chain holds no StoreOperatorAuthorization) — proving the 400 comes from the
// location rule, before any chain read.
func TestHandleGeneratePromoteRefusesMisplacedBundleByName(t *testing.T) {
	op := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	publisher := newTestIdentity(t, "generation-publisher", testLicenseMint, "publisher.example.org")
	svc := &publishService{
		cfg: Config{
			DistDir:       t.TempDir(),
			PublicBaseURL: "https://bazaar.melusina-os.org",
			StoreID:       "melusina-os-root-store",
			Policy:        Policy{AcceptPublishers: []string{publisher.Public().SignPubkeyB58}},
		},
		operator: op,
		cr:       &mockChainReader{},
		nonces:   envelope.NewMemoryNonceCache(),
	}
	misplaced, placed := misplacedShell(t, svc, "handler")
	renamed := placed
	renamed.ArtifactName = "sandstorm-build-65.tar.xz"

	slot := uint64(22000)
	post := func(c componentrelease.ComponentRelease) *httptest.ResponseRecorder {
		t.Helper()
		reqJSON, err := json.Marshal(promoteReq(0, c))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(reqJSON)
		slot++
		sig, err := envelope.Sign(envelope.KindPublishRequest, publisher, op.Public(), envelope.SignOptions{
			Method:      http.MethodPost,
			Target:      "/publish/generation",
			Body:        reqJSON,
			BodyHash:    hex.EncodeToString(sum[:]),
			RequestHash: hex.EncodeToString(sum[:]),
			TTL:         5 * time.Minute,
			Chain:       envelope.ChainEvidence{ChainID: "solana:devnet", ProgramID: "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb", VerifiedSlot: slot},
		})
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(generationPromoteBody{Envelope: sig, RequestB64: base64.StdEncoding.EncodeToString(reqJSON)})
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		svc.handleGeneratePromote(rec, httptest.NewRequest(http.MethodPost, "/publish/generation", bytes.NewReader(body)))
		return rec
	}

	rec := post(misplaced)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "check=component_bundle_location") ||
		!strings.Contains(rec.Body.String(), componentrelease.ErrBundleURLNotReleasePath.Error()) {
		t.Fatalf("shell at /releases/deployer/: want 400 check=component_bundle_location %q, got %d: %s",
			componentrelease.ErrBundleURLNotReleasePath, rec.Code, rec.Body.String())
	}
	rec = post(renamed)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "check=component_bundle_location") ||
		!strings.Contains(rec.Body.String(), componentrelease.ErrArtifactNameNotBundleBasename.Error()) {
		t.Fatalf("artifactName not the bundleUrl basename: want 400 check=component_bundle_location %q, got %d: %s",
			componentrelease.ErrArtifactNameNotBundleBasename, rec.Code, rec.Body.String())
	}

	// POSITIVE CONTROL: the correctly placed component clears the location
	// check and reaches the store-operator gate.
	rec = post(placed)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "check=store_operator") {
		t.Fatalf("positive control: correctly placed shell should reach check=store_operator (403), got %d: %s", rec.Code, rec.Body.String())
	}
	if cur, err := svc.loadCurrentGenerationOrNil(); err != nil || cur != nil {
		t.Fatalf("no request here may persist a generation: %v %v", cur, err)
	}
}
