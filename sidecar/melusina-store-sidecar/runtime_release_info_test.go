package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

func TestCurrentRuntimeReleaseInfoRequiresExactLocalMarker(t *testing.T) {
	valid := map[string]string{
		"RRS_RUNTIME_SCHEMA":  componentrelease.RuntimeReleaseInfoSchema,
		"RRS_COMPONENT_ID":    "rrs-store",
		"RRS_GENERATION_ID":   "41",
		"RRS_SIDECAR_VERSION": "gen-41-aabbccdd",
		"RRS_ARTIFACT_SHA256": strings.Repeat("a", 64),
	}
	getenv := func(k string) string { return valid[k] }
	info, err := currentRuntimeReleaseInfo(getenv, 1234)
	if err != nil {
		t.Fatalf("valid marker refused: %v", err)
	}
	if info.GenerationID != 41 || info.PID != 1234 || info.ComponentID != "rrs-store" {
		t.Fatalf("valid marker decoded incorrectly: %+v", info)
	}
	for name, mutate := range map[string]func(map[string]string){
		"missing schema":   func(m map[string]string) { m["RRS_RUNTIME_SCHEMA"] = "" },
		"zero generation":  func(m map[string]string) { m["RRS_GENERATION_ID"] = "0" },
		"unsafe component": func(m map[string]string) { m["RRS_COMPONENT_ID"] = "rrs-store\nBAD=x" },
		"bad hash":         func(m map[string]string) { m["RRS_ARTIFACT_SHA256"] = strings.Repeat("z", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := make(map[string]string, len(valid))
			for k, v := range valid {
				candidate[k] = v
			}
			mutate(candidate)
			if _, err := currentRuntimeReleaseInfo(func(k string) string { return candidate[k] }, 1234); err == nil {
				t.Fatal("invalid marker accepted")
			}
		})
	}
}

func TestRuntimeReleaseInfoHTTPNeverFabricatesIdentity(t *testing.T) {
	t.Setenv("RRS_RUNTIME_SCHEMA", "")
	t.Setenv("RRS_COMPONENT_ID", "")
	t.Setenv("RRS_GENERATION_ID", "")
	t.Setenv("RRS_SIDECAR_VERSION", "")
	t.Setenv("RRS_ARTIFACT_SHA256", "")
	rec := httptest.NewRecorder()
	handleRuntimeReleaseInfo(rec, httptest.NewRequest(http.MethodGet, "/release-info", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing marker HTTP=%d, want 503", rec.Code)
	}

	t.Setenv("RRS_RUNTIME_SCHEMA", componentrelease.RuntimeReleaseInfoSchema)
	t.Setenv("RRS_COMPONENT_ID", "rrs-store")
	t.Setenv("RRS_GENERATION_ID", "42")
	t.Setenv("RRS_SIDECAR_VERSION", "gen-42-bbbbbbbb")
	t.Setenv("RRS_ARTIFACT_SHA256", strings.Repeat("b", 64))
	rec = httptest.NewRecorder()
	handleRuntimeReleaseInfo(rec, httptest.NewRequest(http.MethodGet, "/release-info", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("valid marker HTTP=%d body=%s", rec.Code, rec.Body.String())
	}
	var got runtimeReleaseInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Schema != componentrelease.RuntimeReleaseInfoSchema || got.PID <= 0 || got.GenerationID != 42 {
		t.Fatalf("wrong runtime response: %+v", got)
	}
	if cache := rec.Header().Get("Cache-Control"); cache != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", cache)
	}

	rec = httptest.NewRecorder()
	handleRuntimeReleaseInfo(rec, httptest.NewRequest(http.MethodPost, "/release-info", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST HTTP=%d, want 405", rec.Code)
	}
}
