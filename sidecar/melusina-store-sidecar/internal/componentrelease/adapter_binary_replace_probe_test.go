package componentrelease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoopbackDialAddressRejectsRemoteResolution(t *testing.T) {
	_, err := loopbackDialAddress("rrs-store-pilot.melusina-os.org", "8443", []net.IPAddr{{IP: net.ParseIP("203.0.113.9")}})
	if err == nil || !strings.Contains(err.Error(), "outside loopback") {
		t.Fatalf("remote resolution must be refused, got %v", err)
	}
}

func TestLoopbackDialAddressPinsVerifiedLoopback(t *testing.T) {
	got, err := loopbackDialAddress("rrs-store-pilot.melusina-os.org", "8443", []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("::1")}})
	if err != nil {
		t.Fatalf("loopback resolution refused: %v", err)
	}
	if got != "127.0.0.1:8443" {
		t.Fatalf("dial address = %q, want loopback pin", got)
	}
}

func TestFetchSelfReportUsesRegistryPinnedLoopbackAndCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/__release-info" {
			t.Fatalf("request path = %q, want /__release-info", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"artifactSha256":"bound"}`)
	}))
	defer server.Close()
	if err := server.Certificate().VerifyHostname("example.com"); err != nil {
		t.Fatalf("httptest certificate must carry example.com for pinned-dial proof: %v", err)
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
	url := "https://" + net.JoinHostPort("example.com", parsed.Port()) + "/__release-info"
	install := ComponentInstall{
		SelfReportURL:         url,
		SelfReportDialAddress: parsed.Host,
		SelfReportCAFile:      caPath,
		SelfReportCASHA256:    sha256Hex(caPEM),
	}
	body, err := FetchSelfReport(context.Background(), install)
	if err != nil {
		t.Fatalf("pinned self-report fetch: %v", err)
	}
	defer body.Close()
	raw, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"artifactSha256":"bound"}` {
		t.Fatalf("self-report body = %q", raw)
	}

	install.SelfReportCASHA256 = strings.Repeat("0", 64)
	if _, err := FetchSelfReport(context.Background(), install); err == nil {
		t.Fatal("self-report with a mismatched pinned CA unexpectedly verified")
	}
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func TestBinaryReplaceProbeWaitsForServiceReadiness(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	oldInterval := binaryReplaceProbeRetryInterval
	binaryReplaceProbeRetryInterval = time.Millisecond
	t.Cleanup(func() { binaryReplaceProbeRetryInterval = oldInterval })

	const wantSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	a := &binaryReplaceAdapter{
		probeGet: func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(`{"artifactSha256":"` + wantSHA + `"}`)), nil
		},
	}
	go func() {
		time.Sleep(12 * time.Millisecond)
		_ = os.WriteFile(ready, []byte("ready"), 0o600)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := a.Probe(ctx, ComponentRelease{ComponentID: "rrs-store", SHA256: wantSHA}, ComponentInstall{
		HealthCommand: []string{"/usr/bin/test", "-f", ready},
		SelfReportURL: "https://localhost/release-info",
	})
	if err != nil {
		t.Fatalf("Probe should wait for readiness, got %v", err)
	}
}
