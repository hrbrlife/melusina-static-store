package hostupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

const testOrigin = "https://bazaar.melusina-os.org"

func testOperator(t *testing.T) (*identity.Private, ed25519.PublicKey) {
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
		ChainID:     "solana:devnet",
		ProgramID:   "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
		LicenseMint: "35csavs4vjGKt24cbQRzsAjjQxBL2QP9mQf6iShHFCmN",
		Domain:      "bazaar.melusina-os.org",
		PDA:         "11111111111111111111111111111111",
		SidecarID:   "store-operator",
		KeyVersion:  1,
	}
	priv, err := identity.NewPrivate(ref, signSeed, boxSeed)
	if err != nil {
		t.Fatalf("NewPrivate: %v", err)
	}
	pub, err := priv.Public().SignPublicKey()
	if err != nil {
		t.Fatalf("SignPublicKey: %v", err)
	}
	return priv, pub
}

// genesisGeneration builds a valid genesis (generationId 1, previousGeneration 0)
// with one shell component — the simplest fully-valid signed generation.
func genesisGeneration(origin string) componentrelease.DesiredGeneration {
	return componentrelease.DesiredGeneration{
		GenerationID: 1,
		StoreID:      "melusina-os-root-store",
		BundleOrigin: origin,
		Channel:      "dev",
		SignedAtUnix: 1784281821,
		Components: []componentrelease.ComponentRelease{{
			ComponentID:    "sandstorm-shell",
			ComponentClass: componentrelease.ClassShell,
			Version:        "build-1",
			Build:          1,
			ArtifactName:   "sandstorm-aaaaaaaa.tar.xz",
			SHA256:         strings.Repeat("a", 64),
			SizeBytes:      1024,
			BundleURL:      origin + "/releases/shell/sandstorm-aaaaaaaa.tar.xz",
			Chain: componentrelease.ChainAuthority{
				Kind:          componentrelease.AuthorityInstallerRelease,
				Program:       "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
				MasterNftMint: "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe",
				ReleasePDA:    "FMRFyGPzrefaYiETSLTDw8fHqix8GVcGuri31qTZVtgY",
			},
		}},
	}
}

func staticGetter(body []byte) componentrelease.HTTPGetter {
	return func(_ context.Context, _ string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(string(body))), nil
	}
}

func signedGenBytes(t *testing.T, op *identity.Private, gen componentrelease.DesiredGeneration) []byte {
	t.Helper()
	signed, err := componentrelease.Sign(op, gen)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func baseOpts(pub ed25519.PublicKey) FetchOptions {
	return FetchOptions{
		URL:                  testOrigin + "/update/generation.json",
		ExpectedStoreID:      "melusina-os-root-store",
		ExpectedBundleOrigin: testOrigin,
		AuthorizedOperator:   pub,
	}
}

func TestFetchAndVerifyGenerationHappy(t *testing.T) {
	op, pub := testOperator(t)
	raw := signedGenBytes(t, op, genesisGeneration(testOrigin))
	got, err := FetchAndVerifyGeneration(context.Background(), staticGetter(raw), baseOpts(pub))
	if err != nil {
		t.Fatalf("valid generation rejected: %v", err)
	}
	if got.Doc.GenerationID != 1 || got.Doc.StoreID != "melusina-os-root-store" {
		t.Fatalf("wrong generation returned: %+v", got.Doc)
	}
	if got.RawSHA256 == "" {
		t.Fatal("VerifiedGeneration missing raw served-bytes digest")
	}
}

func TestAcceptAgainstCursor(t *testing.T) {
	// genesis cursor accepts any first generation
	if err := AcceptAgainstCursor(GenerationCursor{}, VerifiedGeneration{Doc: componentrelease.DesiredGeneration{GenerationID: 5}, RawSHA256: "aa"}); err != nil {
		t.Fatalf("genesis cursor rejected: %v", err)
	}
	cursor := GenerationCursor{GenerationID: 5, RawSHA256: "committed-digest"}
	// downgrade refused
	if err := AcceptAgainstCursor(cursor, VerifiedGeneration{Doc: componentrelease.DesiredGeneration{GenerationID: 4}, RawSHA256: "x"}); err == nil {
		t.Fatal("downgrade accepted")
	}
	// same generation, different bytes = equivocation refused
	if err := AcceptAgainstCursor(cursor, VerifiedGeneration{Doc: componentrelease.DesiredGeneration{GenerationID: 5}, RawSHA256: "DIFFERENT"}); err == nil {
		t.Fatal("equivocation accepted")
	}
	// same generation, same bytes = no-op accepted
	if err := AcceptAgainstCursor(cursor, VerifiedGeneration{Doc: componentrelease.DesiredGeneration{GenerationID: 5}, RawSHA256: "committed-digest"}); err != nil {
		t.Fatalf("same-gen same-bytes rejected: %v", err)
	}
	// forward generation not chaining onto the committed one = refused
	if err := AcceptAgainstCursor(cursor, VerifiedGeneration{Doc: componentrelease.DesiredGeneration{GenerationID: 6, PreviousGeneration: 4}, RawSHA256: "y"}); err == nil {
		t.Fatal("chain break accepted")
	}
	// valid forward advance (6 chains onto committed 5)
	if err := AcceptAgainstCursor(cursor, VerifiedGeneration{Doc: componentrelease.DesiredGeneration{GenerationID: 6, PreviousGeneration: 5}, RawSHA256: "z"}); err != nil {
		t.Fatalf("valid forward advance rejected: %v", err)
	}
}

func TestFetchRejectsOffOriginURL(t *testing.T) {
	op, pub := testOperator(t)
	raw := signedGenBytes(t, op, genesisGeneration(testOrigin))
	opts := baseOpts(pub)
	opts.URL = "https://evil.example/update/generation.json"
	if _, err := FetchAndVerifyGeneration(context.Background(), staticGetter(raw), opts); err == nil {
		t.Fatal("accepted a fetch URL outside the pinned origin")
	}
}

func TestFetchRejectsForeignOrigin(t *testing.T) {
	op, pub := testOperator(t)
	// A validly-signed generation whose bundleOrigin is a DIFFERENT store.
	raw := signedGenBytes(t, op, genesisGeneration("https://other-store.example"))
	// Fetch it as if served from our pinned origin's URL.
	if _, err := FetchAndVerifyGeneration(context.Background(), staticGetter(raw), baseOpts(pub)); err == nil {
		t.Fatal("accepted a generation whose bundleOrigin differs from the pinned origin")
	}
}

func TestFetchRejectsForeignOperator(t *testing.T) {
	op, _ := testOperator(t)
	_, otherPub := testOperator(t)
	raw := signedGenBytes(t, op, genesisGeneration(testOrigin))
	if _, err := FetchAndVerifyGeneration(context.Background(), staticGetter(raw), baseOpts(otherPub)); err == nil {
		t.Fatal("accepted a generation signed by an unauthorized operator")
	}
}

func TestFetchRejectsWrongStoreID(t *testing.T) {
	op, pub := testOperator(t)
	raw := signedGenBytes(t, op, genesisGeneration(testOrigin))
	opts := baseOpts(pub)
	opts.ExpectedStoreID = "some-other-store"
	if _, err := FetchAndVerifyGeneration(context.Background(), staticGetter(raw), opts); err == nil {
		t.Fatal("accepted a generation for a different destination store")
	}
}

func TestFetchRejectsUnknownField(t *testing.T) {
	op, pub := testOperator(t)
	raw := signedGenBytes(t, op, genesisGeneration(testOrigin))
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["hostAction"] = "systemctl restart anything"
	tampered, _ := json.Marshal(m)
	if _, err := FetchAndVerifyGeneration(context.Background(), staticGetter(tampered), baseOpts(pub)); err == nil {
		t.Fatal("accepted a generation with an unknown field")
	}
}

func TestFetchRejectsDuplicateKey(t *testing.T) {
	op, pub := testOperator(t)
	raw := signedGenBytes(t, op, genesisGeneration(testOrigin))
	// Prepend a decoy storeId; Go json keeps the last, but the ambiguity is refused.
	dup := append([]byte(`{"storeId":"wrong-store",`), raw[1:]...)
	if _, err := FetchAndVerifyGeneration(context.Background(), staticGetter(dup), baseOpts(pub)); err == nil {
		t.Fatal("accepted a generation with a duplicate key")
	}
}

func TestFetchRejectsOversizeBody(t *testing.T) {
	_, pub := testOperator(t)
	huge := make([]byte, maxGenerationBytes+2)
	for i := range huge {
		huge[i] = 'x'
	}
	if _, err := FetchAndVerifyGeneration(context.Background(), staticGetter(huge), baseOpts(pub)); err == nil {
		t.Fatal("accepted an oversize generation body")
	}
}
