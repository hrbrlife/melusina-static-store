package releasetest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease"
)

const vectorsPath = "../../../testdata/estate-profile-vectors.json"

// Encode is a fixture encoder; it must write exactly the committed Rust-typed
// vectors, or every test that builds an account with it proves nothing.
func TestEncodeWritesTheCommittedVectorsExactly(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "installer-release-entry-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Name       string `json:"name"`
			AccountHex string `json:"accountHex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range file.Vectors {
		account, err := hex.DecodeString(v.AccountHex)
		if err != nil {
			t.Fatal(err)
		}
		e, err := installerrelease.Decode(account)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if got := Encode(e); !bytes.Equal(got, account) {
			t.Fatalf("%s: Encode(Decode(vector)) differs from the vector", v.Name)
		}
	}
}

func TestFixtureEntryIsAdmittedOnlyUnderItsProfile(t *testing.T) {
	p := LoadProfileVector(t, vectorsPath, NewEstateVector)
	trust, _, err := installerrelease.TrustFromProfile(p.Profile)
	if err != nil {
		t.Fatal(err)
	}
	var hash [32]byte
	hash[0] = 0x42
	e := Entry(t, p.Profile, hash, "1.0.0", TrustedPublisher())
	decoded, err := installerrelease.Decode(Encode(e))
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.Admit(decoded, hash); err != nil {
		t.Fatalf("trusted fixture refused: %v", err)
	}
	if err := trust.Admit(Entry(t, p.Profile, hash, "1.0.0", UntrustedPublisher()), hash); err == nil {
		t.Fatal("untrusted fixture admitted")
	}
	// WithPublishers moves the trust to exactly the named keys.
	moved := WithPublishers(t, p, 1, UntrustedPublisher())
	movedTrust, digest, err := installerrelease.TrustFromProfile(moved.Profile)
	if err != nil || digest != moved.SHA256 || digest == p.SHA256 {
		t.Fatalf("re-signed profile: %v", err)
	}
	if err := movedTrust.Admit(Entry(t, p.Profile, hash, "1.0.0", UntrustedPublisher()), hash); err != nil {
		t.Fatalf("newly trusted key refused: %v", err)
	}
	if !bytes.Equal(TrustedPublisher().Public().(ed25519.PublicKey), VectorKey("rehearsal/publisher-1").Public().(ed25519.PublicKey)) {
		t.Fatal("trusted publisher label drifted")
	}
}
