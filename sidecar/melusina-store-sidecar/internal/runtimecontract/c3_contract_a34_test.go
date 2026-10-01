package runtimecontract_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
)

// The source template keeps the three candidate fields unresolved. The Store
// sees them only after the publisher materializes an immutable candidate.
func TestC3A34RuntimeTemplateAndStoreFlavour(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "testdata", "contracts", "C3-release-and-store-host", "C3-release-and-store-host.json"))
	if err != nil {
		t.Fatalf("C3-A34-vector-unreadable: %v", err)
	}
	var vector struct {
		RuntimeContract struct {
			Template               runtimecontract.Contract `json:"template"`
			MaterializedTestValues struct {
				Version   string `json:"version"`
				SPKSHA256 string `json:"spkSha256"`
				AppHash   string `json:"appHash"`
			} `json:"materializedTestValues"`
			MaterializeOnly []string `json:"materializeOnly"`
		} `json:"runtimeContract"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("C3-A34-vector-invalid: %v", err)
	}
	c := vector.RuntimeContract.Template
	if c.SchemaURL != "urn:melusina:runtime-contract:v1" || c.Schema != runtimecontract.Schema {
		t.Fatalf("C3-A34-runtime-contract-urn: schema %q, kind %q", c.SchemaURL, c.Schema)
	}
	if c.App.Version != "PENDING_BUILD" || c.App.SPKSHA256 != "PENDING_BUILD" || c.App.AppHash != "PENDING_BUILD" {
		t.Fatalf("C3-A34-source-placeholders: %+v", c.App)
	}
	if !reflect.DeepEqual(vector.RuntimeContract.MaterializeOnly, []string{"app.version", "app.spkSha256", "app.appHash"}) {
		t.Fatalf("C3-A34-materialization-scope: %q", vector.RuntimeContract.MaterializeOnly)
	}

	c.App.Version = vector.RuntimeContract.MaterializedTestValues.Version
	c.App.SPKSHA256 = vector.RuntimeContract.MaterializedTestValues.SPKSHA256
	c.App.AppHash = vector.RuntimeContract.MaterializedTestValues.AppHash
	materialized, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	materializedHash := sha256.Sum256(materialized)
	metadata, err := json.Marshal(map[string]string{"appId": c.App.AppID})
	if err != nil {
		t.Fatal(err)
	}
	binding := runtimecontract.Binding{
		Metadata: metadata, AppHash: c.App.AppHash, Version: c.App.Version,
		ReleaseContractSHA256: hex.EncodeToString(materializedHash[:]),
		ReleaseContractSchema: runtimecontract.Schema,
	}
	got, err := runtimecontract.ValidateClaim(materialized, binding)
	if runtimecontract.SchemaURL == c.SchemaURL {
		if err != nil || got.App.AppID != c.App.AppID {
			t.Fatalf("C3-A34-bootstrap-store-rejected-urn: contract=%+v err=%v", got, err)
		}
		binding.AppHash = strings.Repeat("b", 64)
		if _, err := runtimecontract.ValidateClaim(materialized, binding); err == nil || !strings.Contains(err.Error(), "appHash") {
			t.Fatalf("C3-A34-unbound-app-hash-accepted: %v", err)
		}
	} else if err == nil || !strings.Contains(err.Error(), "$schema") {
		t.Fatalf("C3-A34-urn-not-refused-by-legacy-flavour: %v", err)
	}
}
