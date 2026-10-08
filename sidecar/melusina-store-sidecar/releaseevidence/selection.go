package releaseevidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/catalogselection"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// SelectionTrust is independently installed Store/operator scope. Neither
// a transport snapshot nor the pointer may supply these values.
type SelectionTrust struct {
	AppID             string
	Domain            string
	OperatorPublicKey ed25519.PublicKey
}

// Artifacts carries original public bytes. Verification never rewrites them.
type Artifacts struct {
	Index, Pointer, Metadata, Release, RuntimeContract, SPK []byte
}

// Selection reports authenticated operator selection and mechanical artifact
// bindings only. CoreVerifier and the actual SPK verifier remain mandatory.
type Selection struct {
	Pointer   catalogselection.Pointer
	Release   ReleaseClaims
	SPKSHA256 string
}

func VerifySelectedArtifacts(trust SelectionTrust, artifacts Artifacts, now time.Time) (Selection, error) {
	var result Selection
	if len(trust.AppID) != 52 || len(trust.OperatorPublicKey) != ed25519.PublicKeySize || trust.Domain == "" || trust.Domain != strings.ToLower(trust.Domain) || strings.ContainsAny(trust.Domain, "/:\\?#@ \r\n\t") || now.IsZero() {
		return result, errors.New("selected artifact verifier requires independent Store scope")
	}
	for _, raw := range [][]byte{artifacts.Index, artifacts.Pointer, artifacts.Metadata, artifacts.Release} {
		if len(raw) == 0 || len(raw) > 1<<20 {
			return result, errors.New("selected artifact JSON exceeds its bound")
		}
	}
	if len(artifacts.SPK) == 0 || len(artifacts.SPK) > 64<<20 || len(artifacts.RuntimeContract) > 1<<20 {
		return result, errors.New("selected package or runtime exceeds its bound")
	}
	p := &result.Pointer
	if err := catalogselection.DecodeExact(artifacts.Pointer, p); err != nil {
		return result, err
	}
	for _, value := range []string{p.AppHash, p.ReleaseHash, p.StageID, p.CatalogSHA256, p.ServingDomainHash} {
		if !selectionLowerHex(value, 64) {
			return result, errors.New("selected pointer hash is noncanonical")
		}
	}
	if p.PreviousAppHash != "" && !selectionLowerHex(p.PreviousAppHash, 64) {
		return result, errors.New("selected predecessor hash is noncanonical")
	}
	indexSHA := sha256.Sum256(artifacts.Index)
	domainSHA := primitives.StoreDomainHash(trust.Domain)
	if p.AppID != trust.AppID || !selectionLowerHex(p.PackageID, 32) || p.CatalogSHA256 != hex.EncodeToString(indexSHA[:]) || p.ServingDomainHash != hex.EncodeToString(domainSHA[:]) || p.PublishedAt <= 0 || p.PublishedAt > now.Unix() || p.PreviousValidUntil < 0 {
		return result, errors.New("selected pointer identity, catalog, domain or time differs")
	}
	if err := catalogselection.Verify(trust.OperatorPublicKey, *p); err != nil {
		return result, err
	}
	for _, raw := range [][]byte{artifacts.Index, artifacts.Metadata} {
		if err := catalogselection.ValidateJSON(raw, nil, 0); err != nil {
			return result, err
		}
	}
	var index struct {
		Apps []struct {
			AppID     string `json:"appId"`
			PackageID string `json:"packageId"`
		} `json:"apps"`
	}
	if json.Unmarshal(artifacts.Index, &index) != nil {
		return result, errors.New("selected index is malformed")
	}
	seen := make(map[string]bool)
	selectedPackage := ""
	for _, row := range index.Apps {
		if row.AppID == "" || seen[row.AppID] || !selectionLowerHex(row.PackageID, 32) {
			return result, errors.New("selected index has duplicate or invalid identities")
		}
		seen[row.AppID] = true
		if row.AppID == trust.AppID {
			selectedPackage = row.PackageID
		}
	}
	if selectedPackage != p.PackageID {
		return result, errors.New("selected pointer does not name its indexed package")
	}
	var metadata struct {
		AppID     string `json:"appId"`
		Version   string `json:"version"`
		PackageID string `json:"packageId"`
		SHA256    string `json:"sha256"`
	}
	if json.Unmarshal(artifacts.Metadata, &metadata) != nil {
		return result, errors.New("selected metadata is malformed")
	}
	spkSHA := sha256.Sum256(artifacts.SPK)
	result.SPKSHA256 = hex.EncodeToString(spkSHA[:])
	if metadata.AppID != trust.AppID || metadata.Version != p.Version || metadata.PackageID != p.PackageID || p.PackageID != result.SPKSHA256[:32] || metadata.SHA256 != result.SPKSHA256 {
		return result, errors.New("selected metadata or package identity differs")
	}
	appHash, err := apphash.Canonical(bytes.NewReader(artifacts.SPK), artifacts.Metadata)
	if err != nil || appHash != p.AppHash {
		return result, errors.New("selected canonical app hash differs")
	}
	claims, err := DecodeReleaseDescriptor(artifacts.Release)
	if err != nil {
		return result, err
	}
	if claims.AppHash != p.AppHash || claims.ReleaseHash != p.ReleaseHash || claims.Version != p.Version {
		return result, errors.New("selected original RELEASE differs from operator selection")
	}
	result.Release = claims
	binding := runtimecontract.Binding{SPK: artifacts.SPK, Metadata: artifacts.Metadata, AppHash: claims.AppHash, Version: claims.Version, ReleaseContractSHA256: claims.RuntimeContractSHA256, ReleaseContractSchema: claims.RuntimeContractSchema}
	if runtimecontract.RequiresContract(binding) {
		var contract runtimecontract.Contract
		if err := catalogselection.DecodeExact(artifacts.RuntimeContract, &contract); err != nil {
			return result, err
		}
		if _, err := runtimecontract.Validate(artifacts.RuntimeContract, binding); err != nil {
			return result, err
		}
	} else if len(artifacts.RuntimeContract) != 0 {
		return result, errors.New("unbound runtime artifact cannot acquire release authority")
	}
	return result, nil
}

func selectionLowerHex(text string, size int) bool {
	if len(text) != size || strings.ToLower(text) != text {
		return false
	}
	_, err := hex.DecodeString(text)
	return err == nil
}
