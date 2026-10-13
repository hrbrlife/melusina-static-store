package publishclient

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testLeaf(t *testing.T, server *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "leaf.pem")
	raw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPublisherPinnedTLSAndReadback(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "", testLeaf(t, server), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("status=%d", response.StatusCode)
	}
	private, err := NewClient(server.URL, "10.88.180.29:18443", testLeaf(t, server), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if private.Transport.(*http.Transport).TLSClientConfig.ServerName != "127.0.0.1" {
		t.Fatal("private routing changed HTTPS SNI")
	}
}

func TestPublisherForeignTLSLeafRefused(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	if _, err := NewClient("https://store.rehearsal.invalid", "", testLeaf(t, server), time.Minute); err == nil || err.Error() != "publisher_tls_pin_invalid" {
		t.Fatalf("PUBLISHER_FOREIGN_TLS_LEAF_ACCEPTED: %v", err)
	}
}

func TestPublisherPrivateConnectRequiresPin(t *testing.T) {
	for _, address := range []string{"159.195.5.142:18443", "0.0.0.0:18443", "127.0.0.1:18443", "10.88.180.29:443"} {
		if _, err := NewClient("https://store.rehearsal.invalid", address, "", time.Minute); err == nil || err.Error() != "publisher_private_connect_refused" {
			t.Fatalf("PUBLISHER_FOREIGN_CONNECT_ACCEPTED %q: %v", address, err)
		}
	}
	if _, err := NewClient("https://store.rehearsal.invalid", "10.88.180.29:18443", "", time.Minute); err == nil || err.Error() != "publisher_tls_pin_required" {
		t.Fatalf("PUBLISHER_UNPINNED_PRIVATE_CONNECT_ACCEPTED: %v", err)
	}
}

func TestPublisherOriginAndRedirectRefused(t *testing.T) {
	for _, origin := range []string{"http://store.rehearsal.invalid", "https://store.rehearsal.invalid/publish/installer", "https://user@store.rehearsal.invalid"} {
		if _, err := NewClient(origin, "", "", time.Minute); err == nil || err.Error() != "publisher_store_origin_invalid" {
			t.Fatalf("PUBLISHER_FOREIGN_ORIGIN_ACCEPTED %q: %v", origin, err)
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusFound)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "", testLeaf(t, server), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(server.URL); err == nil || !strings.Contains(err.Error(), "publisher_redirect_refused") {
		t.Fatalf("PUBLISHER_REDIRECT_ACCEPTED: %v", err)
	}
}
