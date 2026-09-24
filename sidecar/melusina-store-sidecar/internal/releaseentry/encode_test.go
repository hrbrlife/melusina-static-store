package releaseentry_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry/releaseentrytest"
)

// TestFixtureEncoderIsTheProgramLayout: the fixture encoder the release tool
// tests register entries with writes exactly the bytes the Rust-derived
// vectors hold, so a test account is the account the program would store.
func TestFixtureEncoderIsTheProgramLayout(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "release-entry-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Vectors []struct {
			Name       string `json:"name"`
			AccountHex string `json:"accountHex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, vec := range v.Vectors {
		account, err := hex.DecodeString(vec.AccountHex)
		if err != nil {
			t.Fatal(err)
		}
		e, err := releaseentry.Decode(account)
		if err != nil {
			t.Fatalf("%s: %v", vec.Name, err)
		}
		if got := releaseentrytest.Encode(e); !bytes.Equal(got, account) {
			t.Fatalf("%s: fixture encoding differs from the program-layout vector", vec.Name)
		}
	}
}
