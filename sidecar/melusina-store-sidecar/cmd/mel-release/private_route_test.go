package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/publishclient"
)

func testPrivateLeaf(t *testing.T, host string, now time.Time, isCA bool) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), hex.EncodeToString(spki[:])
}

func signTestPrivateRoute(t *testing.T, route *publishclient.PrivateRoute, policy estateprofile.OwnerPolicyV1) {
	t.Helper()
	route.Signatures = nil
	raw, err := json.Marshal(route)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append([]byte("MELUSINA_ESTATE_PRIVATE_STORE_ROUTE_V1\n"), raw...))
	digest := hex.EncodeToString(sum[:])
	for _, keyID := range []string{"owner-a", "owner-b"} {
		seed := sha256.Sum256([]byte("melusina-estate-profile-vector-key:" + policy.PolicyID + "/" + keyID))
		route.Signatures = append(route.Signatures, estateprofile.SignatureV1{KeyID: keyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), []byte(digest)))})
	}
}

func TestFrozenPublisherPrivateRouteWrongLeafAddressAndExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	profilePath, profilePin := writeEstateProfile(t, nil)
	raw, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := estateprofile.DecodeProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	leaf, spki := testPrivateLeaf(t, profile.Store.RootDomain, now, false)
	base := publishclient.PrivateRoute{Schema: "melusina.estate.private-store-route.v1", EstateID: profile.EstateID, ProfileSHA256: profilePin, StoreID: profile.Store.StoreID, StoreHostname: profile.Store.RootDomain, ConnectAddress: "10.88.180.29:18443", TLSLeafPEM: leaf, LeafSPKISHA256: spki, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	for _, tc := range []struct {
		name, want string
		change     func(*publishclient.PrivateRoute)
	}{
		{"valid", "", func(*publishclient.PrivateRoute) {}},
		{"wrong-leaf", "publisher_tls_pin_invalid", func(r *publishclient.PrivateRoute) {
			r.TLSLeafPEM, _ = testPrivateLeaf(t, profile.Store.RootDomain, now, false)
		}},
		{"wrong-address", "publisher_private_connect_refused", func(r *publishclient.PrivateRoute) { r.ConnectAddress = "159.195.5.142:18443" }},
		{"CA-leaf", "publisher_tls_pin_invalid", func(r *publishclient.PrivateRoute) {
			r.TLSLeafPEM, r.LeafSPKISHA256 = testPrivateLeaf(t, profile.Store.RootDomain, now, true)
		}},
		{"expired", "publisher_private_route_expired", func(r *publishclient.PrivateRoute) {
			r.IssuedAt = now.Add(-2 * time.Hour)
			r.ExpiresAt = now.Add(-time.Hour)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.change(&r)
			signTestPrivateRoute(t, &r, profile.OwnerPolicy)
			path := filepath.Join(t.TempDir(), "route.json")
			body, err := json.Marshal(struct {
				PrivateRoute publishclient.PrivateRoute `json:"privateRoute"`
			}{r})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = publishclient.LoadPrivateRoute(path, profilePath, profilePin, testStoreOrigin, now)
			if tc.want == "" && err != nil {
				t.Fatalf("valid signed private route refused: %v", err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("%s: got %v, want %s", tc.name, err, tc.want)
			}
		})
	}
}

func TestFrozenPublisherPrivateRouteRejectsStoreURLWithAlternatePort(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	profilePath, profilePin := writeEstateProfile(t, nil)
	raw, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := estateprofile.DecodeProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	leaf, spki := testPrivateLeaf(t, profile.Store.RootDomain, now, false)
	route := publishclient.PrivateRoute{Schema: "melusina.estate.private-store-route.v1", EstateID: profile.EstateID,
		ProfileSHA256: profilePin, StoreID: profile.Store.StoreID, StoreHostname: profile.Store.RootDomain,
		ConnectAddress: "10.88.180.29:18443", TLSLeafPEM: leaf, LeafSPKISHA256: spki,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	signTestPrivateRoute(t, &route, profile.OwnerPolicy)
	path := filepath.Join(t.TempDir(), "route.json")
	body, err := json.Marshal(struct {
		PrivateRoute publishclient.PrivateRoute `json:"privateRoute"`
	}{route})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = publishclient.LoadPrivateRoute(path, profilePath, profilePin,
		"https://"+profile.Store.RootDomain+":8443", now)
	if err == nil || !strings.Contains(err.Error(), "publisher_private_route_estate_refused") {
		t.Fatalf("alternate Store URL port must refuse by name, got %v", err)
	}
}
