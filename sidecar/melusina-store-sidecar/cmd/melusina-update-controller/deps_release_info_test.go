package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
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

func TestRuntimeObserverUsesRegistryPinnedLoopbackAndCA(t *testing.T) {
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"schema":"melusina-runtime-release-info-v1","componentId":"fineract-sidecar","generationId":178,"version":"0.2.18-runtime.1","pid":42,"artifactSha256":"` + hash + `"}`))
	}))
	defer server.Close()
	if err := server.Certificate().VerifyHostname("example.com"); err != nil {
		t.Fatalf("httptest certificate must carry example.com for pinned runtime-observer proof: %v", err)
	}
	caPath := filepath.Join(t.TempDir(), "self-report-ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := neturl.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	got, err := newRuntimeObserver()(context.Background(), componentrelease.ComponentRelease{ComponentID: "fineract-sidecar"}, componentrelease.ComponentInstall{
		SelfReportURL:         "https://" + net.JoinHostPort("example.com", parsed.Port()) + "/__release-info",
		SelfReportDialAddress: parsed.Host,
		SelfReportCAFile:      caPath,
		SelfReportCASHA256:    sha256HexForTest(caPEM),
	})
	if err != nil {
		t.Fatalf("runtime observer: %v", err)
	}
	if got.ComponentID != "fineract-sidecar" || got.GenerationID != 178 || got.Version != "0.2.18-runtime.1" || got.PID != 42 || got.ArtifactSHA256 != hash {
		t.Fatalf("runtime evidence = %#v", got)
	}
}

func TestRuntimeObserverUsesBoundedLocalCheckerProof(t *testing.T) {
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	script := filepath.Join(t.TempDir(), "checker-proof")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' '"+
		`{"schema":"melusina-runtime-release-info-v1","componentId":"melusina-update-checker","generationId":179,"version":"2.0.0+bootstrap","pid":0,"artifactSha256":"`+hash+`"}`+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	install := componentrelease.ComponentInstall{
		RuntimeProofCommand: []string{script},
	}
	got, err := newRuntimeObserver()(context.Background(), componentrelease.ComponentRelease{ComponentID: "melusina-update-checker"}, install)
	if err != nil {
		t.Fatalf("command runtime observer: %v", err)
	}
	if got.ComponentID != "melusina-update-checker" || got.GenerationID != 179 || got.Version != "2.0.0+bootstrap" || got.PID != 0 || got.ArtifactSHA256 != hash {
		t.Fatalf("runtime evidence = %#v", got)
	}
}

func TestRuntimeObserverRefusesClaimedPIDFromCommandProof(t *testing.T) {
	script := filepath.Join(t.TempDir(), "checker-proof")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' '"+
		`{"schema":"melusina-runtime-release-info-v1","componentId":"melusina-update-checker","generationId":179,"version":"2.0.0+bootstrap","pid":12,"artifactSha256":"`+strings.Repeat("a", 64)+`"}`+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := newRuntimeObserver()(context.Background(), componentrelease.ComponentRelease{ComponentID: "melusina-update-checker"}, componentrelease.ComponentInstall{
		RuntimeProofCommand: []string{script},
	})
	if err == nil || !strings.Contains(err.Error(), "must report pid 0") {
		t.Fatalf("command proof with a claimed pid was not refused: %v", err)
	}
}

func TestObserveForRefusesSymlinkAtBinaryReplaceInstallRoot(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "checker")
	if err := os.WriteFile(target, []byte("signed bytes"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if got := observeFor(componentrelease.ComponentInstall{InstallRoot: link}); got != "" {
		t.Fatalf("symlinked install root produced delta hash %s", got)
	}
}

func sha256HexForTest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
