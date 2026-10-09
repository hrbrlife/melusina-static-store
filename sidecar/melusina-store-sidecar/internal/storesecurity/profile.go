package storesecurity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

const Schema = "melusina.store-security-profile.v1"

// Profile binds the Store Link transport and scanner authorities to one
// owner-signed estate profile. It is separate from the locked C1 profile.
type Profile struct {
	Schema                    string                      `json:"schema"`
	EstateProfileSHA256       string                      `json:"estateProfileSha256"`
	StoreID                   string                      `json:"storeId"`
	ControlListenAddr         string                      `json:"controlListenAddr"`
	StoreLinkClientCertSHA256 string                      `json:"storeLinkClientCertSha256"`
	ScannerEd25519PublicKey   string                      `json:"scannerEd25519PublicKey"`
	Signatures                []estateprofile.SignatureV1 `json:"signatures"`
}

type signedFields struct {
	Schema                    string `json:"schema"`
	EstateProfileSHA256       string `json:"estateProfileSha256"`
	StoreID                   string `json:"storeId"`
	ControlListenAddr         string `json:"controlListenAddr"`
	StoreLinkClientCertSHA256 string `json:"storeLinkClientCertSha256"`
	ScannerEd25519PublicKey   string `json:"scannerEd25519PublicKey"`
}

func (p Profile) Digest() (string, error) {
	if p.Schema != Schema || p.StoreID == "" || strings.TrimSpace(p.StoreID) != p.StoreID {
		return "", errors.New("store-security-profile-invalid-identity")
	}
	for _, value := range []string{p.EstateProfileSHA256, p.StoreLinkClientCertSHA256} {
		b, err := hex.DecodeString(value)
		if err != nil || len(b) != sha256.Size || hex.EncodeToString(b) != value {
			return "", errors.New("store-security-profile-invalid-digest")
		}
	}
	key, err := hex.DecodeString(p.ScannerEd25519PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || hex.EncodeToString(key) != p.ScannerEd25519PublicKey {
		return "", errors.New("store-security-profile-invalid-scanner-key")
	}
	if host, port, err := net.SplitHostPort(p.ControlListenAddr); err != nil || host == "" || port == "" || strings.HasPrefix(host, ":") {
		return "", errors.New("store-security-profile-invalid-control-listen")
	}
	raw, err := json.Marshal(signedFields{p.Schema, p.EstateProfileSHA256, p.StoreID, p.ControlListenAddr, p.StoreLinkClientCertSHA256, p.ScannerEd25519PublicKey})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("melusina.store-security-profile.v1\x00"), raw...))
	return hex.EncodeToString(digest[:]), nil
}

func Verify(p Profile, estate estateprofile.EstateProfileV1, estateSHA256 string) error {
	if p.EstateProfileSHA256 != estateSHA256 || p.StoreID != estate.Store.StoreID {
		return errors.New("store-security-profile-estate-mismatch")
	}
	digest, err := p.Digest()
	if err != nil {
		return err
	}
	if err := estateprofile.VerifyOwnerThreshold(estate.OwnerPolicy, digest, p.Signatures); err != nil {
		return fmt.Errorf("store-security-profile-owner-signature: %w", err)
	}
	return nil
}

// SignOwnerThreshold is the producer used by the owner-key CLI. It refuses
// keys outside the verified estate owner policy before producing signatures.
func SignOwnerThreshold(p Profile, estate estateprofile.EstateProfileV1, estateSHA256 string, keys map[string]ed25519.PrivateKey) (Profile, error) {
	if len(p.Signatures) != 0 {
		return Profile{}, errors.New("store-security-profile-already-signed")
	}
	if p.EstateProfileSHA256 != estateSHA256 || p.StoreID != estate.Store.StoreID {
		return Profile{}, errors.New("store-security-profile-estate-mismatch")
	}
	digest, err := p.Digest()
	if err != nil {
		return Profile{}, err
	}
	for keyID, private := range keys {
		if len(private) != ed25519.PrivateKeySize {
			return Profile{}, errors.New("store-security-profile-owner-key-invalid")
		}
		matched := false
		for _, signer := range estate.OwnerPolicy.Signers {
			if signer.KeyID == keyID && signer.Ed25519PublicKey == hex.EncodeToString(private.Public().(ed25519.PublicKey)) {
				matched = true
				break
			}
		}
		if !matched {
			return Profile{}, errors.New("store-security-profile-owner-key-not-pinned")
		}
		p.Signatures = append(p.Signatures, estateprofile.SignatureV1{KeyID: keyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(digest)))})
	}
	sort.Slice(p.Signatures, func(i, j int) bool { return p.Signatures[i].KeyID < p.Signatures[j].KeyID })
	if err := Verify(p, estate, estateSHA256); err != nil {
		return Profile{}, err
	}
	return p, nil
}

func Decode(raw []byte) (Profile, error) {
	var p Profile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Profile{}, fmt.Errorf("store-security-profile-json: %w", err)
	}
	if dec.Decode(new(any)) == nil {
		return Profile{}, errors.New("store-security-profile-trailing-json")
	}
	return p, nil
}
