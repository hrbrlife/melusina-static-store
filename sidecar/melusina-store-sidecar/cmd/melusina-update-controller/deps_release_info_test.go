package main

import (
	"strings"
	"testing"
)

func TestDecodeReleaseInfoRejectsAmbiguityAndTrailingData(t *testing.T) {
	good := `{"schema":"melusina-runtime-release-info-v1","componentId":"swaprail","generationId":42,"version":"v42","pid":123,"artifactSha256":"` + strings.Repeat("a", 64) + `"}`
	if _, err := decodeReleaseInfo([]byte(good)); err != nil {
		t.Fatalf("valid release-info refused: %v", err)
	}
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"trailing object", good + ` {}`},
		{"unknown field", strings.TrimSuffix(good, `}`) + `,"extra":true}`},
		{"duplicate field", strings.TrimSuffix(good, `}`) + `,"version":"shadow"}`},
		{"case shadow", strings.TrimSuffix(good, `}`) + `,"Version":"shadow"}`},
		{"string generation", strings.Replace(good, `"generationId":42`, `"generationId":"42"`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeReleaseInfo([]byte(tc.raw)); err == nil {
				t.Fatal("ambiguous or malformed release-info accepted")
			}
		})
	}
}
