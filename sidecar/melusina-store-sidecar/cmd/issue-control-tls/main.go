package main

// issue-control-tls creates one fresh, local Store control transport bundle.
// The owner signs the printed client pin with sign-store-security; the
// installer later checks that pin before placing the serving material.
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type bundle struct {
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
func issue(serverName string, now time.Time) (bundle, string, error) {
	if serverName == "" || strings.TrimSpace(serverName) != serverName {
		return bundle{}, "", errors.New("control-tls-server-name-required")
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return bundle{}, "", err
	}
	caSerial, err := serial()
	if err != nil {
		return bundle{}, "", err
	}
	caTemplate := &x509.Certificate{SerialNumber: caSerial, Subject: pkix.Name{CommonName: "Melusina Store Link control CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return bundle{}, "", err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return bundle{}, "", err
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
		return bundle{}, "", err
	}
	clientCert, clientKey, clientDER, err := leaf("store-link.invalid", x509.ExtKeyUsageClientAuth)
	if err != nil {
		return bundle{}, "", err
	}
	sum := sha256.Sum256(clientDER)
	return bundle{Schema: "melusina.store-control-tls-bundle.v1", ServerCertPEM: serverCert, ServerKeyPEM: serverKey, ClientCAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), ClientCertPEM: clientCert, ClientKeyPEM: clientKey}, hex.EncodeToString(sum[:]), nil
}
func run(args []string) error {
	fs := flag.NewFlagSet("issue-control-tls", flag.ContinueOnError)
	name := fs.String("server-name", "", "Store control listener DNS name or IP")
	out := fs.String("out", "", "new private bundle JSON path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *out == "" || !filepath.IsAbs(*out) {
		return errors.New("control-tls-output-absolute-path-required")
	}
	material, pin, err := issue(*name, time.Now())
	if err != nil {
		return err
	}
	raw, err := json.Marshal(material)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(raw, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	fmt.Printf("store-link-client-cert-sha256=%s\n", pin)
	return nil
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
