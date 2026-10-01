package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestC3D42SubmitGenerationConsumesExactRequest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "testdata", "contracts", "C3-release-and-store-host", "C3-release-and-store-host.json"))
	if err != nil {
		t.Fatalf("C3-D42-vector-unreadable: %v", err)
	}
	var vector struct {
		GenerationPromoteRequest json.RawMessage `json:"generationPromoteRequest"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("C3-D42-vector-invalid: %v", err)
	}
	request, err := decodeRequest(vector.GenerationPromoteRequest, false)
	if err != nil {
		t.Fatalf("C3-D42-submit-generation-request-rejected: %v", err)
	}
	if request.Schema != generationPromoteSchema || request.Channel != "stable" || request.ExpectedCurrentGeneration != 0 || len(request.Components) != 1 || request.Components[0].ComponentClass != "shell" {
		t.Fatalf("C3-D42-submit-generation-request-drift: %+v", request)
	}
	// The signed request bytes may not have a second interpretation at the
	// Store. Extra fields and duplicate keys must be refused before signing.
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(vector.GenerationPromoteRequest, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded["operatorChosenPath"] = json.RawMessage(`"/tmp/other"`)
	unknown, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRequest(unknown, false); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("C3-D42-generation-request-unknown-field-accepted: %v", err)
	}
	duplicate := bytes.Replace(vector.GenerationPromoteRequest, []byte(`"channel":`), []byte(`"channel":"dev","channel":`), 1)
	if bytes.Equal(duplicate, vector.GenerationPromoteRequest) {
		t.Fatal("C3-D42-duplicate-control-not-planted")
	}
	if _, err := decodeRequest(duplicate, false); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("C3-D42-generation-request-duplicate-key-accepted: %v", err)
	}
}
