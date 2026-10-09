package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/controltlsissue"
	"time"
)

func TestIssueControlTLSProducesPinnedMutualTLSIdentity(t *testing.T) {
	b, pin, err := controltlsissue.Issue("127.0.0.1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if b.Schema != "melusina.store-control-tls-bundle.v1" {
		t.Fatal("control-tls-bundle-schema")
	}
	if _, err := tls.X509KeyPair([]byte(b.ServerCertPEM), []byte(b.ServerKeyPEM)); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair([]byte(b.ClientCertPEM), []byte(b.ClientKeyPEM)); err != nil {
		t.Fatal(err)
	}
	clientBlock, _ := pem.Decode([]byte(b.ClientCertPEM))
	if clientBlock == nil {
		t.Fatal("client cert missing")
	}
	sum := sha256.Sum256(clientBlock.Bytes)
	if pin != hex.EncodeToString(sum[:]) {
		t.Fatal("control-tls-client-pin-mismatch")
	}
	client, err := x509.ParseCertificate(clientBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(b.ClientCAPEM)) {
		t.Fatal("control-tls-ca-missing")
	}
	if _, err := client.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
}
