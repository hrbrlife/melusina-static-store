package main

import (
	"bytes"
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testPublicLeafPairPaths(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	return root, filepath.Join(root, "current", "cert.pem"), filepath.Join(root, "current", "key.pem")
}

func testPublicLeafVersion(t *testing.T, root, name string, pair servedTLSTestPair, cert, key bool) {
	t.Helper()
	dir := filepath.Join(root, "versions", name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if key {
		if err := os.WriteFile(filepath.Join(dir, "key.pem"), pair.keyPEM(t), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if cert {
		if err := os.WriteFile(filepath.Join(dir, "cert.pem"), pair.certPEM(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// The full responder path publishes one link, retains the former version and
// lets the running listener load the renewed pair on its next tick.
func TestPublicLeafPairRenewalSwapsOneSymlinkAndRetainsPrevious(t *testing.T) {
	fixture := newPublicLeafResponderFixture(t)
	opts := fixture.options(t)
	if _, err := fixture.renew(opts); err != nil {
		t.Fatalf("PUBLIC_LEAF_PAIR_INITIAL_RENEWAL_REFUSED: %v", err)
	}
	root := filepath.Dir(filepath.Dir(opts.certPath))
	firstLink, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || !strings.HasPrefix(firstLink, "versions/v-") {
		t.Fatalf("PUBLIC_LEAF_PAIR_NOT_ONE_SYMLINK: current = %q, %v", firstLink, err)
	}
	firstCert, firstKey, err := readServedTLSFiles(opts.certPath, opts.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	served, err := newServedTLSCertificate(Config{TLS: TLSConfig{CertPath: opts.certPath, KeyPath: opts.keyPath}}, nil, time.Now, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.renew(opts); err != nil {
		t.Fatalf("PUBLIC_LEAF_PAIR_SECOND_RENEWAL_REFUSED: %v", err)
	}
	secondLink, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || secondLink == firstLink || !strings.HasPrefix(secondLink, "versions/v-") {
		t.Fatalf("PUBLIC_LEAF_PAIR_SWAP_NOT_ATOMIC: current = %q after %q, %v", secondLink, firstLink, err)
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(root, firstLink, "cert.pem"), filepath.Join(root, firstLink, "key.pem")); err != nil {
		t.Fatalf("PUBLIC_LEAF_PAIR_PREVIOUS_VERSION_LOST: %v", err)
	}
	if !served.reload() {
		t.Fatal("PUBLIC_LEAF_PAIR_RENEWED_PAIR_NOT_LOADED")
	}
	secondCert, secondKey, err := readServedTLSFiles(opts.certPath, opts.keyPath)
	if err != nil || bytes.Equal(firstCert, secondCert) || bytes.Equal(firstKey, secondKey) {
		t.Fatalf("PUBLIC_LEAF_PAIR_PATHS_NOT_SWAPPED_TOGETHER: %v", err)
	}
}

// A crash after only the key is written cannot alter current. On restart a
// later complete version is promoted, while the incomplete one is skipped.
func TestPublicLeafPairCrashAfterKeyKeepsPreviousAndStartupRecoversNewestComplete(t *testing.T) {
	issuer := newServedTLSTestRoot(t, "public leaf pair crash test root")
	root, certPath, keyPath := testPublicLeafPairPaths(t)
	first := issuer.validLeaf(t)
	if err := publishPublicLeafPair(certPath, keyPath, first.certPEM(), first.keyPEM(t)); err != nil {
		t.Fatal(err)
	}
	firstLink, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil {
		t.Fatal(err)
	}
	incomplete := issuer.validLeaf(t)
	testPublicLeafVersion(t, root, "v-99991231T235959.000000000Z-incomplete", incomplete, false, true)
	if link, err := os.Readlink(filepath.Join(root, "current")); err != nil || link != firstLink {
		t.Fatalf("PUBLIC_LEAF_PAIR_KEY_ONLY_BECAME_LIVE: current = %q, %v", link, err)
	}
	cert, key, err := readServedTLSFiles(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if pair, err := tls.X509KeyPair(cert, key); err != nil || !bytes.Equal(pair.Certificate[0], first.chain[0]) {
		t.Fatalf("PUBLIC_LEAF_PAIR_CRASH_WINDOW_MIXED_PAIR: %v", err)
	}
	cfg := Config{TLS: TLSConfig{CertPath: certPath, KeyPath: keyPath}}
	if _, err := newServedTLSCertificate(cfg, nil, time.Now, t.Logf); err != nil {
		t.Fatalf("PUBLIC_LEAF_PAIR_KEY_ONLY_STOPPED_RESTART: %v", err)
	}
	complete := issuer.validLeaf(t)
	testPublicLeafVersion(t, root, "v-99991231T235959.000000000Z-complete", complete, true, true)
	served, err := newServedTLSCertificate(cfg, nil, time.Now, t.Logf)
	if err != nil {
		t.Fatalf("PUBLIC_LEAF_PAIR_COMPLETE_VERSION_NOT_RECOVERED: %v", err)
	}
	if got := served.current.Load().Leaf.Raw; !bytes.Equal(got, complete.chain[0]) {
		t.Fatal("PUBLIC_LEAF_PAIR_STARTUP_DID_NOT_SELECT_NEWEST_COMPLETE")
	}
}

func TestPublicLeafPairStartupRecoversBeforeFirstLinkSwap(t *testing.T) {
	issuer := newServedTLSTestRoot(t, "public leaf pair first link crash root")
	root, certPath, keyPath := testPublicLeafPairPaths(t)
	pair := issuer.validLeaf(t)
	const name = "v-99991231T235959.000000000Z-complete"
	testPublicLeafVersion(t, root, name, pair, true, true)
	served, err := newServedTLSCertificate(Config{TLS: TLSConfig{CertPath: certPath, KeyPath: keyPath}}, nil, time.Now, t.Logf)
	if err != nil || !bytes.Equal(served.current.Load().Leaf.Raw, pair.chain[0]) {
		t.Fatalf("PUBLIC_LEAF_PAIR_FIRST_LINK_NOT_RECOVERED: %v", err)
	}
	if target, err := os.Readlink(filepath.Join(root, "current")); err != nil || target != filepath.Join("versions", name) {
		t.Fatalf("PUBLIC_LEAF_PAIR_FIRST_LINK_NOT_PUBLISHED: %q, %v", target, err)
	}
}

func TestPublicLeafPairMismatchedDirectoryRefusedByNameAndRecovered(t *testing.T) {
	issuer := newServedTLSTestRoot(t, "public leaf pair mismatch test root")
	root, certPath, keyPath := testPublicLeafPairPaths(t)
	good := issuer.validLeaf(t)
	if err := publishPublicLeafPair(certPath, keyPath, good.certPEM(), good.keyPEM(t)); err != nil {
		t.Fatal(err)
	}
	bad := issuer.validLeaf(t)
	const badName = "v-99991231T235959.000000000Z-mismatch"
	testPublicLeafVersion(t, root, badName, bad, true, false)
	if err := os.WriteFile(filepath.Join(root, "versions", badName, "key.pem"), good.keyPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := swapPublicLeafLink(root, badName); err != nil {
		t.Fatal(err)
	}
	cert, key, err := readServedTLSFiles(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateServedTLSPair(cert, key, time.Now(), nil); err == nil || !strings.HasPrefix(err.Error(), servedTLSKeyPairRefused) {
		t.Fatalf("PUBLIC_LEAF_PAIR_MISMATCH_NOT_REFUSED_BY_NAME: %v", err)
	}
	logs := &servedTLSTestLog{}
	served, err := newServedTLSCertificate(Config{TLS: TLSConfig{CertPath: certPath, KeyPath: keyPath}}, nil, time.Now, logs.logf)
	if err != nil || !bytes.Equal(served.current.Load().Leaf.Raw, good.chain[0]) {
		t.Fatalf("PUBLIC_LEAF_PAIR_MISMATCH_STOPPED_RECOVERY: %v", err)
	}
	if logs.count("startup skipped version "+badName+": "+servedTLSKeyPairRefused) != 1 {
		t.Fatalf("PUBLIC_LEAF_PAIR_MISMATCH_RECOVERY_NOT_NAMED: %s", logs)
	}
	if current, err := os.Readlink(filepath.Join(root, "current")); err != nil || current == filepath.Join("versions", badName) {
		t.Fatalf("PUBLIC_LEAF_PAIR_MISMATCH_REMAINED_LIVE: %q, %v", current, err)
	}
	// Without a complete matching version, startup must retain the named
	// mismatch as the reason beneath the recovery refusal.
	onlyRoot, onlyCert, onlyKey := testPublicLeafPairPaths(t)
	testPublicLeafVersion(t, onlyRoot, badName, bad, true, false)
	if err := os.WriteFile(filepath.Join(onlyRoot, "versions", badName, "key.pem"), good.keyPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newServedTLSCertificate(Config{TLS: TLSConfig{CertPath: onlyCert, KeyPath: onlyKey}}, nil, time.Now, t.Logf); err == nil ||
		!strings.Contains(err.Error(), publicLeafPairNoVersion) || !strings.Contains(err.Error(), servedTLSKeyPairRefused) {
		t.Fatalf("PUBLIC_LEAF_PAIR_ONLY_MISMATCH_NOT_REFUSED_BY_NAME: %v", err)
	}
}

// Mutation control for the loader's single directory handle: replacing the
// link between reads must still return the first version's matching files.
func TestPublicLeafPairReaderPinsOneVersionAcrossLinkSwap(t *testing.T) {
	issuer := newServedTLSTestRoot(t, "public leaf pair read test root")
	_, certPath, keyPath := testPublicLeafPairPaths(t)
	first, second := issuer.validLeaf(t), issuer.validLeaf(t)
	if err := publishPublicLeafPair(certPath, keyPath, first.certPEM(), first.keyPEM(t)); err != nil {
		t.Fatal(err)
	}
	var swapErr error
	cert, key, err := readPublishedPublicLeafPairWithHook(certPath, keyPath, func() {
		swapErr = publishPublicLeafPair(certPath, keyPath, second.certPEM(), second.keyPEM(t))
	})
	if err != nil || swapErr != nil || !bytes.Equal(cert, first.certPEM()) || !bytes.Equal(key, first.keyPEM(t)) {
		t.Fatalf("PUBLIC_LEAF_PAIR_READER_CROSSED_SWAP: read %v, swap %v", err, swapErr)
	}
	currentCert, currentKey, err := readServedTLSFiles(certPath, keyPath)
	if err != nil || !bytes.Equal(currentCert, second.certPEM()) || !bytes.Equal(currentKey, second.keyPEM(t)) {
		t.Fatalf("PUBLIC_LEAF_PAIR_SWAP_DID_NOT_BECOME_LIVE: %v", err)
	}
}

func TestPublicLeafPairRenewalRefusesOrdinaryAndSplitPathsByName(t *testing.T) {
	issuer := newServedTLSTestRoot(t, "public leaf pair layout test root")
	root, certPath, keyPath := testPublicLeafPairPaths(t)
	for _, tc := range []struct{ name, cert, key string }{
		{"ordinary files", filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem")},
		{"split directories", certPath, filepath.Join(root, "other", "key.pem")},
		{"wrong filename", certPath, filepath.Join(root, "current", "private.pem")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := publishPublicLeafPair(tc.cert, tc.key, issuer.validLeaf(t).certPEM(), issuer.validLeaf(t).keyPEM(t)); err == nil ||
				!strings.HasPrefix(err.Error(), publicLeafPairLayoutRefused) {
				t.Fatalf("PUBLIC_LEAF_PAIR_UNPAIRED_PATH_ACCEPTED: %v", err)
			}
		})
	}
	if _, _, err := readServedTLSFiles(certPath, filepath.Join(root, "other", "key.pem")); err == nil ||
		!strings.HasPrefix(err.Error(), publicLeafPairLayoutRefused) {
		t.Fatalf("PUBLIC_LEAF_PAIR_LOADER_ACCEPTED_SPLIT_PATHS: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "current"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readServedTLSFiles(certPath, keyPath); err == nil ||
		!strings.HasPrefix(err.Error(), publicLeafPairLayoutRefused) {
		t.Fatalf("PUBLIC_LEAF_PAIR_LOADER_ACCEPTED_REAL_DIRECTORY: %v", err)
	}
}
