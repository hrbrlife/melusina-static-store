package main

import (
	_ "embed"
	"net/http"
	"strconv"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
)

const (
	runtimeContractSchemaPath          = "/schemas/melusina-app-runtime-contract-v1.schema.json"
	runtimeContractSchemaIDPlaceholder = "__MELUSINA_RUNTIME_CONTRACT_SCHEMA_ID__"
)

// embeddedRuntimeContractSchema is the release-bound schema endpoint. Keeping
// this versioned public schema in the governed ELF prevents a clean Store from
// depending on a mutable dist-publish seed file.
//
//go:embed runtime-contract-schema/melusina-app-runtime-contract-v1.schema.template.json
var embeddedRuntimeContractSchemaTemplate string

var embeddedRuntimeContractSchema = renderEmbeddedRuntimeContractSchema()

func renderEmbeddedRuntimeContractSchema() string {
	if strings.Count(embeddedRuntimeContractSchemaTemplate, runtimeContractSchemaIDPlaceholder) != 2 {
		panic("embedded runtime-contract schema template has an unexpected identifier placeholder count")
	}
	return strings.ReplaceAll(embeddedRuntimeContractSchemaTemplate, runtimeContractSchemaIDPlaceholder, runtimecontract.SchemaURL)
}

func isEmbeddedRuntimeContractSchemaPath(urlPath string) bool {
	return urlPath == runtimeContractSchemaPath
}

func serveEmbeddedRuntimeContractSchema(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/schema+json")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("Content-Length", strconv.Itoa(len(embeddedRuntimeContractSchema)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(embeddedRuntimeContractSchema))
}
