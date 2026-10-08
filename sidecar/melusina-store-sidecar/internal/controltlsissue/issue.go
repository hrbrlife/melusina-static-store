// Package controltlsissue creates fresh Store Link control identities for
// the Store installer and the standalone owner-facing issuer command.
package controltlsissue

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"time"
)

type Bundle struct {
	Schema        string `json:"schema"`
	ServerCertPEM string `json:"serverCertPem"`
	ServerKeyPEM  string `json:"serverKeyPem"`
	ClientCAPEM   string `json:"clientCaPem"`
	ClientCertPEM string `json:"clientCertPem"`
	ClientKeyPEM  string `json:"clientKeyPem"`
}

func serial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	if n.Sign() == 0 {
		n.SetInt64(1)
	}
	return n, nil
}
func keyPEM(key *ecdsa.PrivateKey) (string, error) {
	raw, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: raw})), nil
}
func Issue(serverName string, now time.Time) (Bundle, string, error) {
	if serverName == "" || strings.TrimSpace(serverName) != serverName {
		return Bundle{}, "", errors.New("control-tls-server-name-required")
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Bundle{}, "", err
	}
	caSerial, err := serial()
	if err != nil {
		return Bundle{}, "", err
	}
	caTemplate := &x509.Certificate{SerialNumber: caSerial, Subject: pkix.Name{CommonName: "Melusina Store Link control CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return Bundle{}, "", err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return Bundle{}, "", err
	}
	leaf := func(name string, usage x509.ExtKeyUsage) (string, string, []byte, error) {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return "", "", nil, e
		}
		sn, e := serial()
		if e != nil {
			return "", "", nil, e
		}
		tpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(0, 3, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if ip := net.ParseIP(name); ip != nil {
			tpl.IPAddresses = []net.IP{ip}
		} else {
			tpl.DNSNames = []string{name}
		}
		der, e := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
		if e != nil {
			return "", "", nil, e
		}
		keyText, e := keyPEM(key)
		if e != nil {
			return "", "", nil, e
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), keyText, der, nil
	}
	serverCert, serverKey, _, err := leaf(serverName, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return Bundle{}, "", err
	}
	clientCert, clientKey, clientDER, err := leaf("store-link", x509.ExtKeyUsageClientAuth)
	if err != nil {
		return Bundle{}, "", err
	}
	sum := sha256.Sum256(clientDER)
	return Bundle{Schema: "melusina.store-control-tls-bundle.v1", ServerCertPEM: serverCert, ServerKeyPEM: serverKey, ClientCAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), ClientCertPEM: clientCert, ClientKeyPEM: clientKey}, hex.EncodeToString(sum[:]), nil
}
