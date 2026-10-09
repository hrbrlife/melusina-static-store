package appscan

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const Schema = "melusina.app-scan-report.v1"
const MaxAge = 10 * time.Minute

type Report struct {
	Schema                string `json:"schema"`
	Method                string `json:"method"`
	Target                string `json:"target"`
	SPKSHA256             string `json:"spkSha256"`
	MetadataSHA256        string `json:"metadataSha256"`
	ReleaseSHA256         string `json:"releaseSha256"`
	RuntimeContractSHA256 string `json:"runtimeContractSha256"`
	ScannedAtUnix         int64  `json:"scannedAtUnix"`
	ScannerVersion        string `json:"scannerVersion"`
	DatabaseVersion       string `json:"databaseVersion"`
	Clean                 bool   `json:"clean"`
	Signature             string `json:"signature"`
}

func Hash(raw []byte) string { digest := sha256.Sum256(raw); return hex.EncodeToString(digest[:]) }

func (r Report) payload() ([]byte, error) {
	if r.Schema != Schema || r.Method != "POST" || r.Target == "" || !r.Clean || r.ScannerVersion == "" || r.DatabaseVersion == "" || r.ScannedAtUnix <= 0 {
		return nil, errors.New("scan-report-invalid-status")
	}
	for _, value := range []string{r.SPKSHA256, r.MetadataSHA256, r.ReleaseSHA256, r.RuntimeContractSHA256} {
		b, err := hex.DecodeString(value)
		if err != nil || len(b) != sha256.Size || hex.EncodeToString(b) != value {
			return nil, errors.New("scan-report-invalid-content-digest")
		}
	}
	r.Signature = ""
	return json.Marshal(r)
}

func (r Report) Digest() (string, error) {
	payload, err := r.payload()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("melusina.app-scan-report.v1\x00"), payload...))
	return hex.EncodeToString(digest[:]), nil
}

func (r *Report) Sign(private ed25519.PrivateKey) error {
	if len(private) != ed25519.PrivateKeySize {
		return errors.New("scan-report-invalid-signing-key")
	}
	digest, err := r.Digest()
	if err != nil {
		return err
	}
	r.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(digest)))
	return nil
}

func Verify(r Report, publicKeyHex, method, target string, spk, metadata, release, runtimeContract []byte, now time.Time) error {
	if r.Schema == "" {
		return errors.New("scan-report-missing")
	}
	if r.Method != method || r.Target != target {
		return errors.New("scan-report-wrong-purpose")
	}
	if r.SPKSHA256 != Hash(spk) || r.MetadataSHA256 != Hash(metadata) || r.ReleaseSHA256 != Hash(release) || r.RuntimeContractSHA256 != Hash(runtimeContract) {
		return errors.New("scan-report-wrong-artifact")
	}
	if r.ScannedAtUnix > now.Unix() || now.Sub(time.Unix(r.ScannedAtUnix, 0)) > MaxAge {
		return errors.New("scan-report-expired")
	}
	key, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize || hex.EncodeToString(key) != publicKeyHex {
		return errors.New("scan-report-authority-unconfigured")
	}
	sig, err := base64.RawURLEncoding.DecodeString(r.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("scan-report-wrong-signer")
	}
	digest, err := r.Digest()
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, []byte(digest), sig) {
		return fmt.Errorf("scan-report-wrong-signer")
	}
	return nil
}
