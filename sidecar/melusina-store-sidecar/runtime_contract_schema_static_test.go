package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
)

func TestEmbeddedRuntimeContractSchemaMatchesSelectedTemplate(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	templatePath := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "runtime-contract-schema", "melusina-app-runtime-contract-v1.schema.template.json"))
	template, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatalf("read runtime-contract schema template: %v", err)
	}
	if got := strings.Count(string(template), runtimeContractSchemaIDPlaceholder); got != 2 {
		t.Fatalf("runtime-contract schema template placeholder count = %d, want 2", got)
	}
	canonical := []byte(strings.ReplaceAll(string(template), runtimeContractSchemaIDPlaceholder, runtimecontract.SchemaURL))
	if string(canonical) != embeddedRuntimeContractSchema {
		t.Fatalf("embedded runtime-contract schema drifted from %s", templatePath)
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
