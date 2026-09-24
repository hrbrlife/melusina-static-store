package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An enrolled Store's /release-info self-report (runtime_release_info.go,
// storeEnrollmentRuntimeReport) is never a controller runtime tuple. The
// Store's shared vector file holds its exact bodies; this decoder must refuse
// every one of them, by the name the vector file records, so a controller
// pointed at an enrolled Store can never bind that answer to an apply.
func TestDecodeReleaseInfoRefusesStoreEnrollmentSelfReport(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "store-enrollment-runtime-v1-vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema            string `json:"schema"`
		ControllerRefusal string `json:"controllerRefusal"`
		Vectors           []struct {
			Name string `json:"name"`
			Body string `json:"body"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if doc.Schema != "melusina.store-enrollment-runtime-vectors.v1" || doc.ControllerRefusal == "" || len(doc.Vectors) == 0 {
		t.Fatalf("%s: schema %q, refusal %q, %d vectors", path, doc.Schema, doc.ControllerRefusal, len(doc.Vectors))
	}
	for _, vector := range doc.Vectors {
		report, err := decodeReleaseInfo([]byte(vector.Body))
		if err == nil {
			t.Fatalf("vector %s: the controller decoded an enrolled Store's self-report as a runtime tuple: %+v", vector.Name, report)
		}
		if !strings.Contains(err.Error(), doc.ControllerRefusal) {
			t.Fatalf("vector %s: refused as %q, want %q", vector.Name, err, doc.ControllerRefusal)
		}
	}
}
