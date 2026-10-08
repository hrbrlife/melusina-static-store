// Package finalizationinput defines the preparation-produced immutable record
// a Bazaar Control finalizer loads from its configured artifact vault. It is a
// deliberately small bridge between source-to-package build output and the
// post-approval RELEASE.json; it has no HTTP client, chain client, signer, or
// catalog authority.
package finalizationinput

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/artifactvault"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const Schema = "bazaar-control-finalization-input-v1"

// Input is written by the restricted preparation worker after it creates the
// governed release/proposal. The signed preparation result commits the vault
// descriptor of these bytes. Candidate identifies the pre-review build object;
// RELEASE.json supplies only the post-review release facts that candidate
// intentionally lacks.
type Input struct {
	Schema      string                   `json:"schema"`
	DossierID   string                   `json:"dossierId"`
	StoreID     string                   `json:"storeId"`
	AppID       string                   `json:"appId"`
	Version     string                   `json:"version"`
	Candidate   artifactvault.Descriptor `json:"candidate"`
	ArtifactSHA string                   `json:"artifactSha256"`
	MetadataSHA string                   `json:"metadataSha256"`
	RuntimeSHA  string                   `json:"runtimeContractSha256,omitempty"`
	PackageID   string                   `json:"packageId"`
	AppHash     string                   `json:"appHash"`
	ReleaseHash string                   `json:"releaseHash"`
	StageID     string                   `json:"stageId"`
	ReleaseB64  string                   `json:"releaseB64"`
	Developer   string                   `json:"developer,omitempty"`
	Repo        string                   `json:"repo,omitempty"`
	Slug        string                   `json:"slug,omitempty"`
}

// CandidateWire is the exact source-to-package candidate written by the
// trusted builder. These snake-case names intentionally match the worker and
// sidecar wire contracts, not a local implementation detail.
type CandidateWire struct {
	SPKB64             string `json:"spk_b64"`
	MetadataB64        string `json:"metadata_b64"`
	RuntimeContractB64 string `json:"runtime_contract_b64,omitempty"`
}

// Package is a decoded, validated candidate prepared for final envelope
// materialization. Its bytes are never selected by an HTTP caller.
type Package struct {
	SPK             []byte
	Metadata        []byte
	RuntimeContract []byte
}

// ReleaseClaims is the bounded set of RELEASE.json facts a finalizer passes to
// its constrained envelope signer after a separate observer verifies chain
// state. It intentionally omits mutable catalog and publisher authority.
type ReleaseClaims struct {
	Schema          string `json:"$schema"`
	AppHash         string `json:"appHash"`
	ReleaseHash     string `json:"releaseHash"`
	Version         string `json:"version"`
	ReleaseEntryPDA string `json:"releaseEntryPda"`
}

// Validate checks the complete immutable preparation record before a
// finalizer dereferences Candidate. It deliberately does not verify the
// ReleaseEntry's live chain state; the finalizer's fixed governance observer
// performs that immediately before requesting a publisher envelope.
func (i Input) Validate(maxCandidateBytes int64) error {
	if i.Schema != Schema || !lowerHex(i.DossierID, 24) || !safeText(i.StoreID, 256) || !appID(i.AppID) || !safeText(i.Version, 256) || !lowerHex(i.ArtifactSHA, 64) || !lowerHex(i.MetadataSHA, 64) || (i.RuntimeSHA != "" && !lowerHex(i.RuntimeSHA, 64)) || !safeText(i.PackageID, 256) || !lowerHex(i.AppHash, 64) || !lowerHex(i.ReleaseHash, 64) || !lowerHex(i.StageID, 64) {
		return errors.New("finalization input is incomplete or malformed")
	}
	if err := i.Candidate.Validate(maxCandidateBytes); err != nil {
		return fmt.Errorf("finalization input candidate: %w", err)
	}
	if (i.Developer == "") != (i.Repo == "") || (i.Repo == "") != (i.Slug == "") || (i.Developer != "" && (!segment(i.Developer) || !segment(i.Repo) || !segment(i.Slug))) {
		return errors.New("finalization input catalog locator is invalid")
	}
	release, err := base64.StdEncoding.DecodeString(strings.TrimSpace(i.ReleaseB64))
	if err != nil || len(release) == 0 || len(release) > 128<<10 || !json.Valid(release) {
		return errors.New("finalization input release is invalid")
	}
	var claims ReleaseClaims
	decoder := json.NewDecoder(bytes.NewReader(release))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("finalization input release is malformed")
	}
	if claims.Schema != "melusina-release-v1" || claims.AppHash != i.AppHash || claims.ReleaseHash != i.ReleaseHash || claims.Version != i.Version {
		return errors.New("finalization input release does not bind the approved facts")
	}
	if _, err := primitives.PubkeyFromBase58(claims.ReleaseEntryPDA); err != nil {
		return errors.New("finalization input release has an invalid release entry")
	}
	return nil
}

// DecodeCandidate revalidates raw candidate bytes against the exact input
// claims. It lets a finalizer refuse a valid-looking vault object that does not
// actually match the approval's source-to-package facts.
func (i Input) DecodeCandidate(body []byte, maxCandidateBytes int64) (Package, error) {
	if err := i.Validate(maxCandidateBytes); err != nil {
		return Package{}, err
	}
	if int64(len(body)) != i.Candidate.Bytes || int64(len(body)) > maxCandidateBytes || len(body) == 0 {
		return Package{}, errors.New("finalization input candidate size does not match its descriptor")
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != i.Candidate.SHA256 {
		return Package{}, errors.New("finalization input candidate digest does not match its descriptor")
	}
	var wire CandidateWire
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Package{}, errors.New("finalization input candidate is not exact JSON")
	}
	spk, err := base64.StdEncoding.DecodeString(wire.SPKB64)
	if err != nil || len(spk) == 0 {
		return Package{}, errors.New("finalization input candidate package is invalid")
	}
	metadata, err := base64.StdEncoding.DecodeString(wire.MetadataB64)
	if err != nil || len(metadata) == 0 {
		return Package{}, errors.New("finalization input candidate metadata is invalid")
	}
	runtime, err := base64.StdEncoding.DecodeString(wire.RuntimeContractB64)
	if err != nil || (i.RuntimeSHA == "" && len(runtime) != 0) || (i.RuntimeSHA != "" && len(runtime) == 0) {
		return Package{}, errors.New("finalization input candidate runtime contract is invalid")
	}
	pkg := Package{SPK: spk, Metadata: metadata, RuntimeContract: runtime}
	if err := i.validatePackage(pkg); err != nil {
		return Package{}, err
	}
	return pkg, nil
}

// Release returns the exact, validated RELEASE.json bytes for the restricted
// envelope signer. The caller must separately verify its live chain evidence.
func (i Input) Release(maxCandidateBytes int64) ([]byte, ReleaseClaims, error) {
	if err := i.Validate(maxCandidateBytes); err != nil {
		return nil, ReleaseClaims{}, err
	}
	release, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(i.ReleaseB64))
	var claims ReleaseClaims
	_ = json.Unmarshal(release, &claims)
	return release, claims, nil
}

// SidecarPublishBody materializes the one exact JSON shape accepted by the
// sidecar after a separate constrained signer has supplied EnvelopeJSON. The
// method has no sidecar client and cannot send or select the resulting body.
func (i Input) SidecarPublishBody(candidate Package, envelopeJSON json.RawMessage, maxCandidateBytes int64) ([]byte, error) {
	if err := i.Validate(maxCandidateBytes); err != nil || !json.Valid(envelopeJSON) {
		return nil, errors.New("finalization input cannot materialize a sidecar publish body")
	}
	if err := i.validatePackage(candidate); err != nil {
		return nil, errors.New("finalization input cannot materialize an unbound package")
	}
	release, _, err := i.Release(maxCandidateBytes)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Envelope           json.RawMessage `json:"envelope"`
		ReleaseB64         string          `json:"release_b64"`
		SPKB64             string          `json:"spk_b64"`
		MetadataB64        string          `json:"metadata_b64"`
		RuntimeContractB64 string          `json:"runtime_contract_b64,omitempty"`
		Developer          string          `json:"developer,omitempty"`
		Repo               string          `json:"repo,omitempty"`
		Slug               string          `json:"slug,omitempty"`
	}{
		Envelope: envelopeJSON, ReleaseB64: base64.StdEncoding.EncodeToString(release),
		SPKB64: base64.StdEncoding.EncodeToString(candidate.SPK), MetadataB64: base64.StdEncoding.EncodeToString(candidate.Metadata),
		RuntimeContractB64: base64.StdEncoding.EncodeToString(candidate.RuntimeContract), Developer: i.Developer, Repo: i.Repo, Slug: i.Slug,
	})
}

func (i Input) validatePackage(candidate Package) error {
	if len(candidate.SPK) == 0 || len(candidate.Metadata) == 0 || digest(candidate.SPK) != i.ArtifactSHA || digest(candidate.Metadata) != i.MetadataSHA || (i.RuntimeSHA == "" && len(candidate.RuntimeContract) != 0) || (i.RuntimeSHA != "" && (len(candidate.RuntimeContract) == 0 || digest(candidate.RuntimeContract) != i.RuntimeSHA)) || canonicalAppHash(candidate.SPK, candidate.Metadata) != i.AppHash {
		return errors.New("package bytes do not bind the finalization input")
	}
	var metadataFacts struct {
		AppID     string `json:"appId"`
		PackageID string `json:"packageId"`
		Version   string `json:"version"`
	}
	if err := json.Unmarshal(candidate.Metadata, &metadataFacts); err != nil || metadataFacts.AppID != i.AppID || metadataFacts.PackageID != i.PackageID || metadataFacts.Version != i.Version {
		return errors.New("package metadata does not bind the finalization input")
	}
	return nil
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func canonicalAppHash(spk, metadata []byte) string {
	outer := sha256.New()
	for _, file := range [][2][]byte{{[]byte("app.spk"), spk}, {[]byte("metadata.json"), metadata}} {
		inner := sha256.New()
		_, _ = inner.Write([]byte("F "))
		_, _ = inner.Write(file[0])
		_, _ = inner.Write([]byte{0})
		_, _ = inner.Write(file[1])
		_, _ = outer.Write(inner.Sum(nil))
	}
	return hex.EncodeToString(outer.Sum(nil))
}

func lowerHex(value string, length int) bool {
	if len(value) != length || strings.ToLower(value) != value {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func safeText(value string, max int) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > max {
		return false
	}
	for _, r := range value {
		if r < ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

func appID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}
	return true
}

func segment(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
