package publishclient

// A private publishing route is the exact output of the deployer's
// --finalize-private-store-route producer. Recheck its authority and expiry at
// every Store operation, including resumed publication.

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

const routeDomain = "MELUSINA_ESTATE_PRIVATE_STORE_ROUTE_V1\n"

type PrivateRoute struct {
	Schema         string                      `json:"schema"`
	EstateID       string                      `json:"estateId"`
	ProfileSHA256  string                      `json:"profileSha256"`
	StoreID        string                      `json:"storeId"`
	StoreHostname  string                      `json:"storeHostname"`
	ConnectAddress string                      `json:"connectAddress"`
	TLSLeafPEM     string                      `json:"tlsLeafPem"`
	LeafSPKISHA256 string                      `json:"leafSpkiSha256"`
	IssuedAt       time.Time                   `json:"issuedAt"`
	ExpiresAt      time.Time                   `json:"expiresAt"`
	Signatures     []estateprofile.SignatureV1 `json:"signatures"`
}

func readOne(path string, limit int64, value any) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return errors.New("publisher_private_route_file_refused")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return errors.New("publisher_private_route_file_refused")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(value) != nil || dec.Decode(new(any)) != io.EOF {
		return errors.New("publisher_private_route_json_refused")
	}
	return nil
}

func LoadPrivateRoute(routePath, profilePath, profilePin, storeURL string, now time.Time) (PrivateRoute, error) {
	var zero PrivateRoute
	var profile estateprofile.EstateProfileV1
	if err := readOne(profilePath, estateprofile.MaxProfileJSONBytes, &profile); err != nil {
		return zero, err
	}
	digest, err := estateprofile.VerifyProfile(profile)
	if err != nil || digest != profilePin {
		return zero, errors.New("publisher_private_route_profile_refused")
	}
	var transport struct {
		PrivateRoute PrivateRoute `json:"privateRoute"`
	}
	if err := readOne(routePath, 128<<10, &transport); err != nil {
		return zero, err
	}
	r := transport.PrivateRoute
	origin, err := url.Parse(storeURL)
	if err != nil || storeURL != "https://"+profile.Store.RootDomain || origin.Scheme != "https" || origin.Hostname() != profile.Store.RootDomain || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" ||
		r.Schema != "melusina.estate.private-store-route.v1" || r.EstateID != profile.EstateID || r.ProfileSHA256 != digest || r.StoreID != profile.Store.StoreID || r.StoreHostname != profile.Store.RootDomain {
		return zero, errors.New("publisher_private_route_estate_refused")
	}
	host, port, err := net.SplitHostPort(r.ConnectAddress)
	ip, ipErr := netip.ParseAddr(host)
	if err != nil || ipErr != nil || !ip.Is4() || !ip.IsPrivate() || ip.String() != host || port != "18443" {
		return zero, errors.New("publisher_private_connect_refused")
	}
	if r.IssuedAt.IsZero() || r.IssuedAt.Nanosecond() != 0 || r.ExpiresAt.Nanosecond() != 0 || !r.ExpiresAt.After(r.IssuedAt) || r.ExpiresAt.After(r.IssuedAt.Add(24*time.Hour)) || now.Before(r.IssuedAt) || !now.Before(r.ExpiresAt) {
		return zero, errors.New("publisher_private_route_expired")
	}
	block, rest := pem.Decode([]byte(r.TLSLeafPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return zero, errors.New("publisher_tls_pin_invalid")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || leaf.IsCA || leaf.VerifyHostname(r.StoreHostname) != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return zero, errors.New("publisher_tls_pin_invalid")
	}
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if hex.EncodeToString(spki[:]) != r.LeafSPKISHA256 {
		return zero, errors.New("publisher_tls_pin_invalid")
	}
	signatures := r.Signatures
	r.Signatures = nil
	raw, err := json.Marshal(r)
	if err != nil {
		return zero, errors.New("publisher_private_route_json_refused")
	}
	sum := sha256.Sum256(append([]byte(routeDomain), raw...))
	if err := estateprofile.VerifyOwnerThreshold(profile.OwnerPolicy, hex.EncodeToString(sum[:]), signatures); err != nil {
		return zero, errors.New("publisher_private_route_signature_refused")
	}
	r.Signatures = signatures
	if strings.TrimSpace(r.TLSLeafPEM) == "" {
		return zero, errors.New("publisher_tls_pin_invalid")
	}
	return r, nil
}
