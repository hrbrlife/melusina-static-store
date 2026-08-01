package componentrelease

import (
	"context"
	"io"
	"net"
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
