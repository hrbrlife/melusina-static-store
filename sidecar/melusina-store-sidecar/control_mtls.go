package main

// Dedicated Bazaar Control listener.
//
// The public catalog listener cannot require a client certificate because
// browsers and tenant shells use it. Pearl commands therefore live on a
// separate listener with both normal PKIX mutual TLS and a pinned Pearl leaf.
// The command and offline-approval signatures remain mandatory defence in
// depth; TLS is the network boundary that keeps this route off the public
// surface altogether.

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

func newPearlControlTLSConfig(config PearlControlMTLSConfig) (*tls.Config, error) {
	if !config.configured() {
		return nil, errors.New("Pearl control mTLS is not configured")
	}
	certificate, err := tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("load Pearl control serving certificate: %w", err)
	}
	pemBytes, err := os.ReadFile(config.ClientCAPath)
	if err != nil {
		return nil, fmt.Errorf("read Pearl control client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("Pearl control client CA contains no certificates")
	}
	pinnedLeaf, err := hex.DecodeString(config.PearlClientCertSHA256)
	if err != nil || len(pinnedLeaf) != sha256.Size {
		return nil, errors.New("Pearl control client certificate digest is invalid")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("Pearl control requires a verified client certificate")
			}
			actual := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(actual[:], pinnedLeaf) != 1 {
				return errors.New("Pearl control client certificate is not the pinned Pearl identity")
			}
			return nil
		},
	}, nil
}

func newPearlControlServer(config PearlControlMTLSConfig, handler http.Handler) (*http.Server, error) {
	tlsConfig, err := newPearlControlTLSConfig(config)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              config.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsConfig,
	}, nil
}
