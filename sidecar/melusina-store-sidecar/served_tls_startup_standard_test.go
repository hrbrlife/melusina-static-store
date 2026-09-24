//go:build !estatebootstrap

package main

// The estatebootstrap build has no read-only Store: LoadConfig accepts only
// the enrolled release-authority form there, and an enrolled Store's server
// holds a root-owned writer.lock, which an unprivileged test cannot create.
// So the real Store process is run here, in the standard build, from the
// same main.go both builds compile. TestStoreMainServesThroughTheBoundServedCertificate
// checks that main's wiring in both builds.

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type servedTLSChildOutput struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (o *servedTLSChildOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Write(p)
}

func (o *servedTLSChildOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

// The real Store process serves a renewed certificate to new clients without
// a restart, and keeps serving it when the next file is bad. The Store here
// is a read-only one (no boot identity), so its served file is not bound.
func TestStoreStartupServesARotatedCertificateWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	root := newServedTLSTestRoot(t, "served TLS startup root")
	tlsDir := filepath.Join(dir, "tls")
	if err := os.Mkdir(tlsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(tlsDir, "cert.pem"), filepath.Join(tlsDir, "key.pem")
	first := root.validLeaf(t)
	writeServedTLSTestPair(t, certPath, keyPath, first)

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	// A read-only Store: no boot identity, chain reader or enrollment.
	configPath := writeJSONConfig(t, map[string]any{
		"license_nft_mint":  testStoreAuthority,
		"program_id":        testLicenseProgramID,
		"domain":            "store.example.org",
		"listen_addr":       addr,
		"dist_dir":          filepath.Join(dir, "dist"),
		"catalog_repo_root": filepath.Join(dir, "catalog"),
		"tls":               map[string]any{"cert_path": certPath, "key_path": keyPath},
		"release_squads_authority": map[string]any{
			"multisig": testStoreAuthority, "vault": testStoreAuthority, "program_id": testStoreAuthority,
			"threshold": 3, "member_count": 4,
		},
	})
	encoded, err := json.Marshal([]string{"-config", configPath})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStoreStartupChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), storeStartupChildArgs+"="+string(encoded), servedTLSReloadIntervalChildEnv+"=50ms")
	cmd.Dir = dir
	output := &servedTLSChildOutput{}
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(20 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
	}
	t.Cleanup(stop)

	// waitServed polls fresh verifying connections until the process serves want.
	waitServed := func(want servedTLSTestPair, name string) {
		t.Helper()
		deadline := time.Now().Add(60 * time.Second)
		var last [32]byte
		var lastErr error
		for time.Now().Before(deadline) {
			select {
			case err := <-exited:
				stopped = true
				t.Fatalf("%s: Store process exited: %v\n%s", name, err, output)
			default:
			}
			last, lastErr = servedLeafOverTLS(t, addr, root.pool())
			if lastErr == nil && last == want.fingerprint() {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s: served leaf %x (err %v), want %x\n%s", name, last, lastErr, want.fingerprint(), output)
	}

	waitServed(first, "served-tls-startup-not-served")
	if !strings.Contains(output.String(), "listening (TLS) on "+addr+"; served certificate re-read every 50ms") {
		t.Fatalf("served-tls-listener-not-reloading: the Store did not start its listener with the reloading certificate:\n%s", output)
	}

	second := root.validLeaf(t)
	writeServedTLSTestPair(t, certPath, keyPath, second)
	waitServed(second, "served-tls-rotation-not-served")

	now := time.Now()
	writeServedTLSTestPair(t, certPath, keyPath, root.leaf(t, now.Add(-2*time.Hour), now.Add(-time.Hour)))
	deadline := time.Now().Add(60 * time.Second)
	for !strings.Contains(output.String(), "served TLS certificate reload refused: "+servedTLSExpired+":0") {
		if time.Now().After(deadline) {
			t.Fatalf("served-tls-refusal-not-named: the Store did not refuse the expired pair by name:\n%s", output)
		}
		time.Sleep(50 * time.Millisecond)
	}
	requireServedLeaf(t, addr, root.pool(), second, "served-tls-bad-pair-served")

	stop()
	if strings.Contains(output.String(), "serve: ") {
		t.Fatalf("Store listener failed:\n%s", output)
	}
}
