package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

// How long the public listener lets a client take to send a request. Every
// failure names what regressed.

// uploadTestTransfer gives the listener limits of a few seconds: the floor
// rate is so high that every size rounds up to one second, so the read limit
// is 1 s plus half the slack (5 s) and the write limit 1 s plus the slack (9 s).
var uploadTestTransfer = transferPolicy{floorBytesPerSecond: 1 << 40, slack: 8 * time.Second}

// servePublicListener runs handler behind the public listener built with
// policy, on a loopback port, until the test ends.
func servePublicListener(t *testing.T, handler http.Handler, policy transferPolicy) (*http.Server, string) {
	t.Helper()
	srv := publicServerWithTransfer("127.0.0.1:0", handler, policy)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return srv, ln.Addr().String()
}

// installerUploadFixture is an approved installer artifact, a service that
// accepts its publication, and the JSON body that publishes it under name.
func installerUploadFixture(t *testing.T) (*publishService, string, func(name string) []byte) {
	t.Helper()
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.ReleaseMasterNftMint = randPubkeyB58(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	m := newMockChainReader()
	bindTestInstallerReleaseEstate(t, m, &cfg)
	pinRootStoreOperator(t, cfg, m, op)

	artifact := make([]byte, 64<<10)
	if _, err := rand.Read(artifact); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(artifact)
	pda := installerReleasePDA(t, cfg.ReleaseMasterNftMint, hash)
	m.installerEntry[pda] = mockInstallerEntry{installerHash: hash, version: "1.0.0", status: verify.AttestationStatusActive}
	svc := newTestService(t, cfg, m, op)
	pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	body := func(name string) []byte {
		sig := signInstallerPublish(t, pub, op.Public(), artifact)
		return jsonInstallerPublishBody(t, sig, "shell", name, artifact).Bytes()
	}
	return svc, cfg.DistDir, body
}

// uploadResult is what the client saw of one upload.
type uploadResult struct {
	status  int
	body    string
	err     error
	elapsed time.Duration
	sent    int64
}

// uploadInPieces sends a POST /publish/installer whose body goes out as
// pieces with gap between them, reading the response concurrently, and stops
// sending when the response arrives. It waits at most wait for the response.
func uploadInPieces(t *testing.T, addr string, body []byte, pieces [][2]int, gap, wait time.Duration) uploadResult {
	t.Helper()
	// Taken before the dial, so it precedes the moment the server starts
	// reading the request and the read limit starts counting.
	started := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	responded := make(chan struct{})
	var sent atomic.Int64
	go func() {
		header := fmt.Sprintf("POST /publish/installer HTTP/1.1\r\nHost: store.test\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", len(body))
		if _, err := io.WriteString(conn, header); err != nil {
			return
		}
		for i, piece := range pieces {
			if i > 0 {
				select {
				case <-responded:
					return
				case <-time.After(gap):
				}
			}
			n, err := conn.Write(body[piece[0]:piece[1]])
			sent.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	_ = conn.SetReadDeadline(started.Add(wait))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	close(responded)
	result := uploadResult{elapsed: time.Since(started), sent: sent.Load(), err: err}
	if err != nil {
		return result
	}
	defer resp.Body.Close()
	text, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	result.status, result.body = resp.StatusCode, string(text)
	return result
}

// TestPublicServerBoundsATrickledUpload publishes an approved installer
// artifact through the public listener, built with limits of a few seconds.
// An upload that arrives in pieces within the read limit is accepted, the
// positive control. An upload that trickles past the read limit is cut off:
// its handler's body read fails with a timeout, the client is answered with
// the refusal before the write limit, nothing is published, and the client
// never finished sending. A request whose body arrived in time is still
// handled, with a live context, after the read limit has passed.
func TestPublicServerBoundsATrickledUpload(t *testing.T) {
	svc, distDir, body := installerUploadFixture(t)
	srv, addr := servePublicListener(t, http.HandlerFunc(svc.handlePublishInstaller), uploadTestTransfer)
	// The intended read limit. The legs below measure what the listener
	// does; TestPublicServerReadLimitFitsTheLargestUpload checks the value.
	limit := uploadTestTransfer.readLimitFor(maxPublicRequestBody)
	// Generous: the host running the suite may be heavily loaded.
	const margin = 20 * time.Second

	t.Run("timely_upload_is_accepted", func(t *testing.T) {
		payload := body("timely.tar.xz")
		quarter := len(payload) / 4
		pieces := [][2]int{{0, quarter}, {quarter, 2 * quarter}, {2 * quarter, 3 * quarter}, {3 * quarter, len(payload)}}
		// Three gaps of 400 ms: the upload finishes well inside the limit.
		got := uploadInPieces(t, addr, payload, pieces, 400*time.Millisecond, limit+margin)
		if got.err != nil || got.status != http.StatusOK {
			t.Fatalf("public-timely-upload-cut-off: an upload that finished in %s under a %s read limit got status %d err %v: %s", got.elapsed.Round(time.Millisecond), limit, got.status, got.err, got.body)
		}
		if _, err := os.Stat(filepath.Join(distDir, "releases", "shell", "timely.tar.xz")); err != nil {
			t.Fatalf("public-timely-upload-not-published: %v", err)
		}
	})

	t.Run("trickled_upload_is_cut_off", func(t *testing.T) {
		payload := body("trickled.tar.xz")
		// Half at once, then one byte every 200 ms: the body cannot finish
		// for minutes.
		pieces := [][2]int{{0, len(payload) / 2}}
		for i := len(payload) / 2; i < len(payload); i++ {
			pieces = append(pieces, [2]int{i, i + 1})
		}
		got := uploadInPieces(t, addr, payload, pieces, 200*time.Millisecond, limit+margin)
		var netErr net.Error
		if errors.As(got.err, &netErr) && netErr.Timeout() {
			t.Fatalf("public-upload-read-unbounded: no response %s after a client began trickling a %d-byte body (read limit %s; it had sent %d bytes): %v", got.elapsed.Round(time.Millisecond), len(payload), limit, got.sent, got.err)
		}
		if got.err != nil {
			t.Fatalf("public-upload-refusal-not-answered: the connection ended %s after the upload began without a response (read limit %s, write limit %s): %v", got.elapsed.Round(time.Millisecond), limit, srv.WriteTimeout, got.err)
		}
		t.Logf("refused after %s with %d of %d bytes sent: %d %s", got.elapsed.Round(time.Millisecond), got.sent, len(payload), got.status, strings.TrimSpace(got.body))
		if got.status != http.StatusBadRequest || !strings.Contains(got.body, "check=request: read body:") || !strings.Contains(got.body, "i/o timeout") {
			t.Fatalf("public-trickled-upload-not-refused-by-read-deadline: status %d: %s", got.status, got.body)
		}
		if got.elapsed < limit {
			t.Fatalf("public-upload-cut-off-before-read-limit: refused after %s, read limit %s", got.elapsed, limit)
		}
		if got.sent >= int64(len(payload)) {
			t.Fatalf("public-trickle-test-did-not-trickle: the client sent all %d bytes", len(payload))
		}
		if _, err := os.Stat(filepath.Join(distDir, "releases", "shell", "trickled.tar.xz")); !os.IsNotExist(err) {
			t.Fatalf("public-trickled-upload-published: stat err %v", err)
		}
	})

	t.Run("handling_outlives_the_read_limit", func(t *testing.T) {
		// The body arrives at once; the handler then works past the read
		// limit. Its context must still be live and its answer delivered.
		_, handlingAddr := servePublicListener(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started := time.Now()
			if _, err := io.ReadAll(r.Body); err != nil {
				http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
				return
			}
			time.Sleep(time.Until(started.Add(limit + time.Second)))
			if err := r.Context().Err(); err != nil {
				http.Error(w, "context ended: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
			fmt.Fprintf(w, "handled %s after the request began", time.Since(started).Round(time.Millisecond))
		}), uploadTestTransfer)
		payload := []byte(`{"a":"b"}`)
		got := uploadInPieces(t, handlingAddr, payload, [][2]int{{0, len(payload)}}, 0, limit+margin)
		if got.err != nil || got.status != http.StatusOK {
			t.Fatalf("public-handling-cut-short-by-read-limit: a request whose body arrived at once was not answered when its handler worked until %s after it began (read limit %s): status %d err %v: %s", limit+time.Second, limit, got.status, got.err, got.body)
		}
	})
}

// TestPublicServerReadLimitFitsTheLargestUpload proves the public listener
// has a read limit, derived from the largest request body any route accepts,
// long enough for that body to arrive at the floor rate after the longest
// header read, and that no route may accept a larger body than the limit was
// derived from.
func TestPublicServerReadLimitFitsTheLargestUpload(t *testing.T) {
	srv := newPublicServer(":0", http.NotFoundHandler())
	if srv.ReadTimeout <= 0 {
		t.Fatal("public-listener-has-no-read-timeout: a client that trickles an upload holds its handler and the body read so far for as long as it keeps sending")
	}
	if srv.ReadTimeout != publicTransfer.readLimitFor(maxPublicRequestBody) {
		t.Fatalf("public-read-timeout-not-derived-from-largest-body: %s, want %s", srv.ReadTimeout, publicTransfer.readLimitFor(maxPublicRequestBody))
	}
	if got, want := srv.ReadTimeout, 1024*time.Second+publicTransferSlack/2; got != want {
		t.Fatalf("public-read-timeout-changed: %s, want %s for 512 MiB at 512 KiB/s plus half the slack", got, want)
	}
	if publicTransferSlack/2 < publicReadHeaderTimeout {
		t.Fatalf("public-read-slack-shorter-than-header-limit: half the slack %s < %s", publicTransferSlack/2, publicReadHeaderTimeout)
	}
	// WriteTimeout counts from the end of the headers, ReadTimeout from
	// before them, so this difference is the least time left to answer a
	// request after its read limit.
	if maxServedArtifactBytes < maxPublicRequestBody || srv.WriteTimeout-srv.ReadTimeout < publicTransferSlack/2 {
		t.Fatalf("public-no-time-to-answer-after-read-limit: write %s, read %s, want at least %s between them", srv.WriteTimeout, srv.ReadTimeout, publicTransferSlack/2)
	}
	floorSeconds := time.Duration(maxPublicRequestBody/publicTransferFloorBytesPerSecond) * time.Second
	if srv.ReadTimeout < srv.ReadHeaderTimeout+floorSeconds {
		t.Fatalf("public-read-timeout-shorter-than-largest-upload: %s < %s of headers plus %s to move %d bytes at %d bytes/s", srv.ReadTimeout, srv.ReadHeaderTimeout, floorSeconds, int64(maxPublicRequestBody), publicTransferFloorBytesPerSecond)
	}
	for name, limit := range map[string]int64{
		"maxAppPublishBody":        maxAppPublishBody,
		"maxInstallerPublishBody":  maxInstallerPublishBody,
		"maxGenerationPromoteBody": maxGenerationPromoteBody,
		"maxHostApplyIssueBody":    maxHostApplyIssueBody,
	} {
		if limit > maxPublicRequestBody {
			t.Fatalf("route-body-limit-above-read-bound: %s is %d, the read limit is derived from %d", name, limit, int64(maxPublicRequestBody))
		}
	}
	// Positive control: a route limit at the bound is applied.
	atBound := httptest.NewRequest(http.MethodPost, "/publish/installer", bytes.NewReader([]byte("{}")))
	if err := limitPublishBody(atBound, maxPublicRequestBody); err != nil {
		t.Fatalf("public-body-limit-at-read-bound-refused: %v", err)
	}
	above := httptest.NewRequest(http.MethodPost, "/publish/installer", bytes.NewReader([]byte("{}")))
	if err := limitPublishBody(above, maxPublicRequestBody+1); err == nil || !strings.Contains(err.Error(), "public-body-limit-above-read-bound") {
		t.Fatalf("public-body-limit-above-read-bound-accepted: a route limit of %d bytes was applied though the read limit is derived from %d: %v", int64(maxPublicRequestBody)+1, int64(maxPublicRequestBody), err)
	}
}

// TestStoreConfigExamplesNameTheServedSnapshotDir proves both config
// examples an operator may copy name the rendered snapshot directory, which
// main() requires before it opens a listener, and keep it apart from every
// Store root.
func TestStoreConfigExamplesNameTheServedSnapshotDir(t *testing.T) {
	for _, path := range []string{
		"store.config.example.json",
		filepath.Join("..", "..", "deploy", "store-generation", "store.config.template.json"),
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var cfg Config
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if cfg.ServedSnapshotDir != storeConfigRenderServedSnapshotDir {
			t.Fatalf("store-config-example-served-snapshot-dir-missing: %s names served_snapshot_dir %q, want the rendered %q; a Store started from it stops with %s", path, cfg.ServedSnapshotDir, storeConfigRenderServedSnapshotDir, refusalServedSnapshotDirUnconfigured)
		}
		if err := validateCatalogStorageRoots(cfg); err != nil {
			t.Fatalf("store-config-example-served-snapshot-dir-overlaps: %s: %v", path, err)
		}
	}
}
