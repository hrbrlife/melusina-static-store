package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
)

func TestEmbeddedRuntimeContractSchemaMatchesCanonicalSource(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	canonicalPath := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "schemas", "melusina-app-runtime-contract-v1.schema.json"))
	canonical, err := os.ReadFile(canonicalPath)
	if err != nil {
		t.Fatalf("read canonical runtime-contract schema: %v", err)
	}
	if string(canonical) != embeddedRuntimeContractSchema {
		t.Fatalf("embedded runtime-contract schema drifted from %s", canonicalPath)
	}
	var schema struct {
		ID string `json:"$id"`
	}
	if err := json.Unmarshal(canonical, &schema); err != nil {
		t.Fatalf("decode canonical runtime-contract schema: %v", err)
	}
	if schema.ID != runtimecontract.SchemaURL {
		t.Fatalf("canonical schema id = %q, want %q", schema.ID, runtimecontract.SchemaURL)
	}
}
