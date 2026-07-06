package main

import (
	"bytes"
	"context"
	"crypto/rand"
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

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// ── test identity / fixture builders ───────────────────────────────────────

// newTestIdentity builds a freshly-keyed sidecar identity bound to the given
// license mint + domain. Used for both the publisher (envelope source) and the
// store operator (envelope destination + receipt signer).
func newTestIdentity(t *testing.T, sidecarID, licenseMint, domain string) *identity.Private {
	t.Helper()
	var signSeed, boxSeed [32]byte
	if _, err := rand.Read(signSeed[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(boxSeed[:]); err != nil {
		t.Fatal(err)
	}
	ref := identity.Ref{
		Kind:        identity.KindSidecar,
		ChainID:     defaultChainID,
		ProgramID:   programIDB58,
		LicenseMint: licenseMint,
		Domain:      domain,
		PDA:         "11111111111111111111111111111111",
		SidecarID:   sidecarID,
		KeyVersion:  1,
	}
	priv, err := identity.NewPrivate(ref, signSeed, boxSeed)
	if err != nil {
		t.Fatalf("NewPrivate: %v", err)
	}
	return priv
}

func randPubkeyB58(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return primitives.EncodeBase58(b[:])
}

// signPub32 returns the identity's raw 32-byte ed25519 signing pubkey.
func signPub32(t *testing.T, p *identity.Private) [32]byte {
	t.Helper()
	raw, err := p.Public().SignPublicKey()
	if err != nil {
		t.Fatalf("SignPublicKey: %v", err)
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}

// testRelease returns a self-consistent (spk, metadata, RELEASE.json bytes, claims)
// bundle whose appHash == apphash.Canonical(spk, metadata) — the on-chain tree-hash,
// NOT sha256(spk).
func testRelease(t *testing.T, masterMintB58 string) (spk, metadata, releaseBytes []byte, claims ReleaseClaims) {
	t.Helper()
	spk = []byte("sandstorm package bytes — deterministic submit-client test SPK v1")
	metadata = []byte(`{"appTitle":"Submit Test","appVersion":"1.0.0"}`)
	appHashHex, err := apphash.Canonical(bytes.NewReader(spk), metadata)
	if err != nil {
		t.Fatal(err)
	}
	relSum := sha256.Sum256([]byte("release manifest bytes"))
	rel := map[string]any{
		"$schema":       "melusina-release-v1",
		"appHash":       appHashHex,
		"releaseHash":   hex.EncodeToString(relSum[:]),
		"version":       "1.0.0",
		"masterNftMint": masterMintB58,
	}
	b, err := json.Marshal(rel)
	if err != nil {
		t.Fatal(err)
	}
	return spk, metadata, b, ReleaseClaims{
		AppHash:       appHashHex,
		ReleaseHash:   hex.EncodeToString(relSum[:]),
		MasterNftMint: masterMintB58,
	}
}

// ── mock store-operator-authz fetcher ──────────────────────────────────────

type mockAuthzReader struct {
	byAddr map[string]mockAuthz
	err    error
}

type mockAuthz struct {
	status     verify.AuthorizationStatus
	authority  verify.Pubkey
	domainHash [32]byte
}

func (m *mockAuthzReader) FetchStoreOperatorAuthz(_ context.Context, addr string) (verify.AuthorizationStatus, verify.Pubkey, uint8, bool, [32]byte, error) {
	if m.err != nil {
		return 0, verify.Pubkey{}, 0, false, [32]byte{}, m.err
	}
	a, ok := m.byAddr[addr]
	if !ok {
		return 0, verify.Pubkey{}, 0, false, [32]byte{}, verify.ErrPDANotFound
	}
	return a.status, a.authority, 0, false, a.domainHash, nil
}

// pinAuthz wires the mock to vouch for the operator key at the derived PDA.
func pinAuthz(t *testing.T, m *mockAuthzReader, licenseMintB58, domain string, operatorKey [32]byte) {
	t.Helper()
	programID, err := primitives.PubkeyFromBase58(programIDB58)
	if err != nil {
		t.Fatal(err)
	}
	licenseMint, err := primitives.PubkeyFromBase58(licenseMintB58)
	if err != nil {
		t.Fatal(err)
	}
	dh := primitives.StoreDomainHash(domain)
	authzPDA, _, err := pda.StoreOperatorAuthorization(licenseMint, dh, programID)
	if err != nil {
		t.Fatal(err)
	}
	m.byAddr[authzPDA.Base58()] = mockAuthz{
		status:     verify.AuthorizationStatusActive,
		authority:  verify.Pubkey(operatorKey),
		domainHash: dh,
	}
}

// signReceipt produces a store-signed provenance receipt over the raw 96 bytes,
// byte-identical to the sidecar's SignReceipt. Used to fabricate a receipt the
// submit client must then verify.
func signReceipt(operator *identity.Private, appHash, releaseHash, servingDomainHash [32]byte) Receipt {
	msg := receiptMessage(appHash, releaseHash, servingDomainHash)
	sig := operator.Sign(msg)
	return Receipt{
		AppHash:           hex.EncodeToString(appHash[:]),
		ReleaseHash:       hex.EncodeToString(releaseHash[:]),
		ServingDomainHash: hex.EncodeToString(servingDomainHash[:]),
		OperatorSignature: primitives.EncodeBase58(sig),
		StoredAt:          time.Now().Unix(),
	}
}

// ── 1) envelope construction ───────────────────────────────────────────────

func TestBuildEnvelope_BindsKindBodyAndRequest(t *testing.T) {
	master := randPubkeyB58(t)
	spk, _, releaseBytes, claims := testRelease(t, master)

	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	op := newTestIdentity(t, "store-operator", randPubkeyB58(t), "store.example.org")

	sig, err := buildEnvelope(pub, op.Public(), spk, releaseBytes, claims, 12345, 5*time.Minute)
	if err != nil {
		t.Fatalf("buildEnvelope: %v", err)
	}

	if sig.Payload.Kind != envelope.KindArtifact {
		t.Errorf("kind = %q, want %q", sig.Payload.Kind, envelope.KindArtifact)
	}

	wantSPK := sha256.Sum256(spk)
	if sig.Payload.RequestHashHex != hex.EncodeToString(wantSPK[:]) {
		t.Errorf("request_hash = %s, want sha256(spk) %s", sig.Payload.RequestHashHex, hex.EncodeToString(wantSPK[:]))
	}
	wantBody := sha256.Sum256(releaseBytes)
	if sig.Payload.BodyHashHex != hex.EncodeToString(wantBody[:]) {
		t.Errorf("body_hash = %s, want sha256(release) %s", sig.Payload.BodyHashHex, hex.EncodeToString(wantBody[:]))
	}
	if sig.Payload.ChainEvidence.VerifiedSlot != 12345 {
		t.Errorf("verified_slot = %d, want 12345", sig.Payload.ChainEvidence.VerifiedSlot)
	}
	if sig.Payload.ChainEvidence.ProgramID != programIDB58 {
		t.Errorf("program_id = %s, want %s", sig.Payload.ChainEvidence.ProgramID, programIDB58)
	}
	if sig.Payload.ChainEvidence.ReleaseEntryPDA == "" {
		t.Error("expected ReleaseEntryPDA chain evidence to be populated")
	}

	// The envelope must verify exactly as the C2.3 handler verifies it: Kind,
	// Destination, RequestHash == sha256(spk).
	opPub := op.Public()
	if err := envelope.Verify(sig, envelope.VerifyOptions{
		ExpectedKind:        envelope.KindArtifact,
		ExpectedDestination: &opPub,
		ExpectedRequestHash: hex.EncodeToString(wantSPK[:]),
	}); err != nil {
		t.Fatalf("envelope.Verify (handler contract): %v", err)
	}
}

func TestBuildEnvelope_DestinationMustMatchOperator(t *testing.T) {
	master := randPubkeyB58(t)
	spk, _, releaseBytes, claims := testRelease(t, master)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	op := newTestIdentity(t, "store-operator", randPubkeyB58(t), "store.example.org")
	other := newTestIdentity(t, "other-operator", randPubkeyB58(t), "other.example.org")

	sig, err := buildEnvelope(pub, op.Public(), spk, releaseBytes, claims, 1, 5*time.Minute)
	if err != nil {
		t.Fatalf("buildEnvelope: %v", err)
	}
	// An envelope addressed to op must NOT verify against a different destination.
	otherPub := other.Public()
	if err := envelope.Verify(sig, envelope.VerifyOptions{
		ExpectedKind:        envelope.KindArtifact,
		ExpectedDestination: &otherPub,
	}); err == nil {
		t.Fatal("expected destination mismatch to fail verification")
	}
}

// ── 2) receipt-signature verification ──────────────────────────────────────

func receiptInputs(t *testing.T) (appHash, releaseHash, servingDomainHash [32]byte, licenseMint, domain string) {
	t.Helper()
	licenseMint = randPubkeyB58(t)
	domain = "store.example.org"
	appHash = sha256.Sum256([]byte("app"))
	releaseHash = sha256.Sum256([]byte("rel"))
	servingDomainHash = primitives.StoreDomainHash(domain)
	return
}

func TestVerifyReceipt_ValidReceiptVerifies(t *testing.T) {
	appHash, releaseHash, servingDomainHash, licenseMint, domain := receiptInputs(t)
	op := newTestIdentity(t, "store-operator", licenseMint, domain)
	opKey := signPub32(t, op)

	m := &mockAuthzReader{byAddr: map[string]mockAuthz{}}
	pinAuthz(t, m, licenseMint, domain, opKey)

	receipt := signReceipt(op, appHash, releaseHash, servingDomainHash)
	if err := verifyReceipt(context.Background(), m, licenseMint, domain, receipt); err != nil {
		t.Fatalf("expected valid receipt to verify, got: %v", err)
	}
}

func TestVerifyReceipt_TamperedSignatureFails(t *testing.T) {
	appHash, releaseHash, servingDomainHash, licenseMint, domain := receiptInputs(t)
	op := newTestIdentity(t, "store-operator", licenseMint, domain)
	opKey := signPub32(t, op)

	m := &mockAuthzReader{byAddr: map[string]mockAuthz{}}
	pinAuthz(t, m, licenseMint, domain, opKey)

	receipt := signReceipt(op, appHash, releaseHash, servingDomainHash)
	// Flip a byte in the (valid) signature.
	raw, err := primitives.DecodeBase58(receipt.OperatorSignature)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0xFF
	receipt.OperatorSignature = primitives.EncodeBase58(raw)

	err = verifyReceipt(context.Background(), m, licenseMint, domain, receipt)
	if err == nil {
		t.Fatal("expected tampered signature to fail verification")
	}
	if !strings.Contains(err.Error(), "check=receipt") {
		t.Fatalf("error %q does not name the receipt check", err.Error())
	}
}

func TestVerifyReceipt_WrongKeyFails(t *testing.T) {
	appHash, releaseHash, servingDomainHash, licenseMint, domain := receiptInputs(t)
	// The receipt is signed by `signer`, but the chain vouches for a DIFFERENT
	// store_authority — the install-side trust must reject this.
	signer := newTestIdentity(t, "rogue-operator", licenseMint, domain)
	authorized := newTestIdentity(t, "real-operator", licenseMint, domain)
	authorizedKey := signPub32(t, authorized)

	m := &mockAuthzReader{byAddr: map[string]mockAuthz{}}
	pinAuthz(t, m, licenseMint, domain, authorizedKey)

	receipt := signReceipt(signer, appHash, releaseHash, servingDomainHash)
	err := verifyReceipt(context.Background(), m, licenseMint, domain, receipt)
	if err == nil {
		t.Fatal("expected a receipt signed by an unauthorized key to fail")
	}
	if !strings.Contains(err.Error(), "does not verify against on-chain store_authority") {
		t.Fatalf("error %q does not name the store_authority mismatch", err.Error())
	}
}

func TestVerifyReceipt_TamperedTupleFails(t *testing.T) {
	appHash, releaseHash, servingDomainHash, licenseMint, domain := receiptInputs(t)
	op := newTestIdentity(t, "store-operator", licenseMint, domain)
	opKey := signPub32(t, op)

	m := &mockAuthzReader{byAddr: map[string]mockAuthz{}}
	pinAuthz(t, m, licenseMint, domain, opKey)

	receipt := signReceipt(op, appHash, releaseHash, servingDomainHash)
	// Swap the appHash to a different value: the signature now covers the old
	// tuple, so verification of the presented (new) tuple must fail.
	other := sha256.Sum256([]byte("a different app"))
	receipt.AppHash = hex.EncodeToString(other[:])

	if err := verifyReceipt(context.Background(), m, licenseMint, domain, receipt); err == nil {
		t.Fatal("expected a tampered appHash to fail verification")
	}
}

func TestVerifyReceipt_WrongServingDomainFails(t *testing.T) {
	appHash, releaseHash, _, licenseMint, domain := receiptInputs(t)
	op := newTestIdentity(t, "store-operator", licenseMint, domain)
	opKey := signPub32(t, op)

	m := &mockAuthzReader{byAddr: map[string]mockAuthz{}}
	pinAuthz(t, m, licenseMint, domain, opKey)

	// The operator validly signs a tuple whose servingDomainHash is for a
	// DIFFERENT domain than the store we are verifying against.
	wrongDomainHash := primitives.StoreDomainHash("evil.example.org")
	receipt := signReceipt(op, appHash, releaseHash, wrongDomainHash)

	err := verifyReceipt(context.Background(), m, licenseMint, domain, receipt)
	if err == nil {
		t.Fatal("expected a receipt for the wrong serving domain to fail")
	}
	if !strings.Contains(err.Error(), "servingDomainHash") {
		t.Fatalf("error %q does not name the servingDomainHash binding", err.Error())
	}
}

func TestVerifyReceipt_AuthzNotActiveFails(t *testing.T) {
	appHash, releaseHash, servingDomainHash, licenseMint, domain := receiptInputs(t)
	op := newTestIdentity(t, "store-operator", licenseMint, domain)
	opKey := signPub32(t, op)

	// Wire the authz as Revoked.
	programID, _ := primitives.PubkeyFromBase58(programIDB58)
	lm, _ := primitives.PubkeyFromBase58(licenseMint)
	dh := primitives.StoreDomainHash(domain)
	authzPDA, _, _ := pda.StoreOperatorAuthorization(lm, dh, programID)
	m := &mockAuthzReader{byAddr: map[string]mockAuthz{
		authzPDA.Base58(): {status: verify.AuthorizationStatusRevoked, authority: verify.Pubkey(opKey), domainHash: dh},
	}}

	receipt := signReceipt(op, appHash, releaseHash, servingDomainHash)
	err := verifyReceipt(context.Background(), m, licenseMint, domain, receipt)
	if err == nil {
		t.Fatal("expected a non-Active store authorization to fail")
	}
	if !strings.Contains(err.Error(), "check=store_operator_authz") {
		t.Fatalf("error %q does not name store_operator_authz", err.Error())
	}
}

func TestVerifyReceipt_AuthzNotFoundFails(t *testing.T) {
	appHash, releaseHash, servingDomainHash, licenseMint, domain := receiptInputs(t)
	op := newTestIdentity(t, "store-operator", licenseMint, domain)
	m := &mockAuthzReader{byAddr: map[string]mockAuthz{}} // nothing pinned

	receipt := signReceipt(op, appHash, releaseHash, servingDomainHash)
	if err := verifyReceipt(context.Background(), m, licenseMint, domain, receipt); err == nil {
		t.Fatal("expected a missing store authorization to fail closed")
	}
}

// ── publisher-key / store-pubkey loaders ───────────────────────────────────

func writePublisherKey(t *testing.T, ref identity.Ref) (path string) {
	t.Helper()
	var signSeed, boxSeed [32]byte
	if _, err := rand.Read(signSeed[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(boxSeed[:]); err != nil {
		t.Fatal(err)
	}
	f := publisherKeyFile{
		Ref:      ref,
		SignSeed: hex.EncodeToString(signSeed[:]),
		BoxSeed:  hex.EncodeToString(boxSeed[:]),
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "publisher.key.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadPublisherKey_FileAndEnv(t *testing.T) {
	ref := identity.Ref{
		Kind:        identity.KindSidecar,
		ChainID:     defaultChainID,
		ProgramID:   programIDB58,
		LicenseMint: randPubkeyB58(t),
		Domain:      "publisher.example.org",
		PDA:         "11111111111111111111111111111111",
		SidecarID:   "publisher",
		KeyVersion:  1,
	}
	path := writePublisherKey(t, ref)

	priv, err := loadPublisherKey(path)
	if err != nil {
		t.Fatalf("loadPublisherKey(file): %v", err)
	}
	if priv.Public().Ref.SidecarID != "publisher" {
		t.Errorf("loaded ref sidecar_id = %q", priv.Public().Ref.SidecarID)
	}

	// env: form
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PUB_KEY_JSON", string(raw))
	priv2, err := loadPublisherKey("env:PUB_KEY_JSON")
	if err != nil {
		t.Fatalf("loadPublisherKey(env): %v", err)
	}
	if priv2.Public().DigestHex() != priv.Public().DigestHex() {
		t.Error("env-loaded key differs from file-loaded key")
	}
}

func TestLoadStorePubkey_RoundTrip(t *testing.T) {
	op := newTestIdentity(t, "store-operator", randPubkeyB58(t), "store.example.org")
	b, err := json.Marshal(op.Public())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "store.pub.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	pub, err := loadStorePubkey(path)
	if err != nil {
		t.Fatalf("loadStorePubkey: %v", err)
	}
	if pub.Digest() != op.Public().Digest() {
		t.Error("round-tripped store pubkey digest differs")
	}
}

func TestHostFromURL(t *testing.T) {
	cases := map[string]string{
		"https://store.example.org":        "store.example.org",
		"https://store.example.org/":       "store.example.org",
		"https://store.example.org:8443/x": "store.example.org",
		"http://localhost:8080":            "localhost",
		"store.example.org":                "store.example.org",
	}
	for in, want := range cases {
		if got := hostFromURL(in); got != want {
			t.Errorf("hostFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// ── BONUS: end-to-end against an httptest server mimicking C2.3 accept ──────

// TestE2E_PostPublishAndVerifyReceipt drives the full client path: build the
// envelope, POST it (JSON wire form) to an httptest server that re-verifies the
// envelope exactly as the C2.3 handler does and returns a real store-signed
// receipt, then verify that receipt against a mock on-chain store_authority.
func TestE2E_PostPublishAndVerifyReceipt(t *testing.T) {
	master := randPubkeyB58(t)
	spk, metadata, releaseBytes, claims := testRelease(t, master)

	licenseMint := randPubkeyB58(t)
	domain := "store.example.org"
	op := newTestIdentity(t, "store-operator", licenseMint, domain)
	opKey := signPub32(t, op)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")

	servingDomainHash := primitives.StoreDomainHash(domain)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/publish" || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		// Parse EITHER the JSON wire form OR multipart/form-data, mirroring the
		// C2.3 handler's parsePublishBody.
		var sigIn envelope.Signed
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			if err := r.ParseMultipartForm(32 << 20); err != nil {
				http.Error(w, "bad multipart", http.StatusBadRequest)
				return
			}
			f, _, err := r.FormFile("envelope")
			if err != nil {
				http.Error(w, "no envelope part", http.StatusBadRequest)
				return
			}
			defer f.Close()
			if err := json.NewDecoder(f).Decode(&sigIn); err != nil {
				http.Error(w, "bad envelope part", http.StatusBadRequest)
				return
			}
		} else {
			var req publishRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}
			sigIn = req.Envelope
		}
		// Re-verify the envelope as the C2.3 handler does.
		spkSum := sha256.Sum256(spk)
		opPub := op.Public()
		// Fresh nonce cache per request: the e2e reuses one signed envelope
		// across the JSON + multipart POSTs, which a shared cache would reject as
		// a replay. The replay path is covered by the handler's own tests.
		if err := envelope.Verify(sigIn, envelope.VerifyOptions{
			ExpectedKind:        envelope.KindArtifact,
			ExpectedDestination: &opPub,
			ExpectedRequestHash: hex.EncodeToString(spkSum[:]),
			NonceCache:          envelope.NewMemoryNonceCache(),
		}); err != nil {
			http.Error(w, "check=envelope: "+err.Error(), http.StatusUnauthorized)
			return
		}
		// Sign and return a real provenance receipt.
		var appHash, releaseHash [32]byte
		ah, _ := hex.DecodeString(claims.AppHash)
		rh, _ := hex.DecodeString(claims.ReleaseHash)
		copy(appHash[:], ah)
		copy(releaseHash[:], rh)
		receipt := signReceipt(op, appHash, releaseHash, servingDomainHash)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(receipt)
	}))
	defer srv.Close()

	sig, err := buildEnvelope(pub, op.Public(), spk, releaseBytes, claims, 999, 5*time.Minute)
	if err != nil {
		t.Fatalf("buildEnvelope: %v", err)
	}
	body, status, err := postPublish(context.Background(), options{store: srv.URL, timeout: 10 * time.Second}, sig, releaseBytes, spk, metadata)
	if err != nil {
		t.Fatalf("postPublish: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", status, string(body))
	}
	var receipt Receipt
	if err := json.Unmarshal(body, &receipt); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}

	m := &mockAuthzReader{byAddr: map[string]mockAuthz{}}
	pinAuthz(t, m, licenseMint, domain, opKey)
	if err := verifyReceipt(context.Background(), m, licenseMint, domain, receipt); err != nil {
		t.Fatalf("e2e receipt verification failed: %v", err)
	}
	if receipt.AppHash != claims.AppHash {
		t.Errorf("receipt appHash %s != %s", receipt.AppHash, claims.AppHash)
	}

	// Also exercise the multipart path against the same server.
	body, status, err = postPublish(context.Background(), options{store: srv.URL, useMultipart: true, timeout: 10 * time.Second}, sig, releaseBytes, spk, metadata)
	if err != nil {
		t.Fatalf("postPublish(multipart): %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("multipart: expected 200, got %d: %s", status, string(body))
	}
}

// TestE2E_StoreRejectionSurfacesCheck asserts a non-200 from the store is
// surfaced as an error naming the store's failing check (exit-1 path).
func TestE2E_StoreRejectionSurfacesCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "check=app_hash: apphash(spk,metadata)=deadbeef != release.appHash=cafe", http.StatusForbidden)
	}))
	defer srv.Close()

	master := randPubkeyB58(t)
	spk, metadata, releaseBytes, claims := testRelease(t, master)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	op := newTestIdentity(t, "store-operator", randPubkeyB58(t), "store.example.org")
	sig, err := buildEnvelope(pub, op.Public(), spk, releaseBytes, claims, 1, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	body, status, err := postPublish(context.Background(), options{store: srv.URL, timeout: 10 * time.Second}, sig, releaseBytes, spk, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", status)
	}
	if !strings.Contains(string(body), "check=app_hash") {
		t.Fatalf("rejection body %q does not name the failing check", string(body))
	}
}
