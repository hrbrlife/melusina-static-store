package main

// The D33 typed release-tools front door. Three operator-supplied documents —
// the owner-signed estate profile, the publisher-signed deployable release
// set, and the publisher-device reference — are the ONLY input a typed
// preflight needs: every estate fact, tool-tree pin and provider decision is
// derived from them, and a legacy MEL_RELEASE_* override that contradicts the
// profile is refused by name instead of steering the release.
//
// Refusal order is load-bearing and is asserted by the locked C3/C1 D33 tests:
//
//   1. the estate profile decodes and verifies (estate-profile-owner-signature-invalid …);
//   2. the release set's publisher signatures verify over the canonical
//      preimage (release_signature_invalid);
//   3. the publisher-device reference must name a key the signed profile
//      enrolled (PUBLISHER_DEVICE_UNTRUSTED);
//   4. only then does provider selection run, and while the signed release set
//      carries no release-tools member it refuses RELEASE_PROVIDER_UNPINNED —
//      even when an operator-chosen helper is configured. Provider selection
//      never trusts an operator fallback.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"filippo.io/edwards25519"
	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

const (
	// releaseSetSchema is the only release-set schema the front door accepts;
	// it is the schema the deployer's releaseset verifier signs.
	releaseSetSchema = "melusina.bootstrap-release-set.v2"
	// releaseSetDigestDomain is the deployer's canonical digest domain prefix.
	releaseSetDigestDomain = "MELUSINA_BOOTSTRAP_RELEASE_SET_V2\n"
	// releaseToolsRole is the closed-vocabulary role a signed release set
	// carries when the governed provider execution path is pinned. No campaign
	// task adds it yet (K-REL-55), so the derived role is "absent".
	releaseToolsRole = "release-tools"
	// publisherDeviceReferenceSchema is the only device-reference schema the
	// front door accepts.
	publisherDeviceReferenceSchema = "melusina.publisher-device-reference.v1"
)

// publisherDeviceReference is the operator's device pointer. It carries no key
// beyond the reference itself: trust comes from the signed profile's enrolled
// publisher keyset, never from the reference document.
type publisherDeviceReference struct {
	Schema           string `json:"schema"`
	KeyID            string `json:"keyId"`
	DeviceID         string `json:"deviceId"`
	Ed25519PublicKey string `json:"ed25519PublicKey"`
	PublicKey        string `json:"publicKey"`
}

// deviceKeyID and deviceKey normalize the two fixture spellings of the device
// reference: the C3 vector names keyId + ed25519PublicKey; the C1 estate
// fixture names deviceId + publicKey. Both must resolve to the same
// publisher-member fact: a key the signed profile enrolled.
func (device publisherDeviceReference) normalized() (string, string, bool) {
	keyID, key := device.KeyID, device.Ed25519PublicKey
	if keyID == "" {
		keyID = device.DeviceID
	}
	if key == "" {
		key = device.PublicKey
	}
	if strings.TrimSpace(keyID) == "" || strings.TrimSpace(key) == "" {
		return "", "", false
	}
	return keyID, key, true
}

// releaseSetDocument is the subset of the deployer's signed ReleaseSetV2 the
// front door reads. Field names and JSON spelling match
// deploy-ui/internal/releaseset/releaseset.go so one file verifies under both.
type releaseSetDocument struct {
	Schema     string `json:"schema"`
	Stage      string `json:"stage"`
	Sequence   uint64 `json:"sequence"`
	CreatedAt  string `json:"createdAt"`
	Foundation struct {
		Sequence uint64 `json:"sequence"`
		SHA256   string `json:"sha256"`
	} `json:"foundation"`
	PublisherKeyset struct {
		Threshold uint8 `json:"threshold"`
		Keys      []struct {
			KeyID            string `json:"keyId"`
			Ed25519PublicKey string `json:"ed25519PublicKey"`
		} `json:"keys"`
	} `json:"publisherKeyset"`
	Recalls        []json.RawMessage    `json:"recalls"`
	PhaseEndpoints map[string][]string  `json:"phaseEndpoints"`
	Artifacts      []releaseSetArtifact `json:"artifacts"`
	Completeness   string               `json:"completeness"`
	DeclaredAbsent []json.RawMessage    `json:"declaredAbsent"`
	Signatures     []struct {
		KeyID     string `json:"keyId"`
		Signature string `json:"signature"`
	} `json:"signatures"`
}

// releaseSetArtifact is one artifact pin as the release set carries it; the
// derived inputs replay it verbatim (the locked C3 trace compares every field,
// including origins order).
type releaseSetArtifact struct {
	Role         string   `json:"role"`
	Name         string   `json:"name"`
	SHA256       string   `json:"sha256"`
	SizeBytes    int64    `json:"sizeBytes"`
	SourceRepo   string   `json:"sourceRepo"`
	SourceCommit string   `json:"sourceCommit"`
	Toolchain    string   `json:"toolchain"`
	Origins      []string `json:"origins"`
	Phase        string   `json:"phase"`
}

// releaseSetDigest encodes the deployer's canonicalPreimageUnchecked byte for
// byte (the C3 vector canonicalPreimageHex is the cross-language normative
// pin, and TestC3D33CrossLanguageCanonicalPreimage holds this function to it):
// every string and the domain line are big-endian uint32 length-prefixed;
// sequence, createdAt (Unix seconds), sizes and foundation sequence are uint64;
// the keyset threshold is uint8; counts are uint32; arrays are in document
// order; signatures do not participate.
func releaseSetDigest(document releaseSetDocument) ([]byte, string, error) {
	var preimage []byte
	appendString := func(value string) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		preimage = append(preimage, length[:]...)
		preimage = append(preimage, value...)
	}
	appendUint64 := func(value uint64) {
		var raw [8]byte
		binary.BigEndian.PutUint64(raw[:], value)
		preimage = append(preimage, raw[:]...)
	}
	appendUint32 := func(value uint32) {
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], value)
		preimage = append(preimage, raw[:]...)
	}
	appendUint8 := func(value uint8) { preimage = append(preimage, value) }

	createdAt, err := time.Parse(time.RFC3339, document.CreatedAt)
	if err != nil {
		return nil, "", fmt.Errorf("release set createdAt is not RFC 3339: %w", err)
	}
	appendString(releaseSetDigestDomain)
	appendString(document.Schema)
	appendString(document.Stage)
	appendUint64(document.Sequence)
	appendUint64(uint64(createdAt.Unix()))
	appendUint64(document.Foundation.Sequence)
	appendString(document.Foundation.SHA256)
	appendUint8(document.PublisherKeyset.Threshold)
	appendUint32(uint32(len(document.PublisherKeyset.Keys)))
	for _, key := range document.PublisherKeyset.Keys {
		appendString(key.KeyID)
		appendString(key.Ed25519PublicKey)
	}
	appendUint32(uint32(len(document.Recalls)))
	for _, recall := range document.Recalls {
		appendString(string(recall))
	}
	for _, phase := range []string{"p0-verify", "p1-host-prep", "p2-enroll", "p3-foundation", "p4-after-closure"} {
		endpoints := document.PhaseEndpoints[phase]
		appendString(phase)
		appendUint32(uint32(len(endpoints)))
		for _, endpoint := range endpoints {
			appendString(endpoint)
		}
	}
	appendUint32(uint32(len(document.Artifacts)))
	for _, artifact := range document.Artifacts {
		appendString(artifact.Role)
		appendString(artifact.Name)
		appendString(artifact.SHA256)
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(artifact.SizeBytes))
		preimage = append(preimage, size[:]...)
		appendString(artifact.SourceRepo)
		appendString(artifact.SourceCommit)
		appendString(artifact.Toolchain)
		appendUint32(uint32(len(artifact.Origins)))
		for _, origin := range artifact.Origins {
			appendString(origin)
		}
		appendString(artifact.Phase)
	}
	appendString(document.Completeness)
	appendUint32(uint32(len(document.DeclaredAbsent)))
	for _, absence := range document.DeclaredAbsent {
		appendString(string(absence))
	}
	sum := sha256.Sum256(preimage)
	return preimage, hex.EncodeToString(sum[:]), nil
}

// isLowerHex64 reports whether value is exactly 64 lowercase hex characters.
func isLowerHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// decodeHex64 decodes a 64-character lowercase-hex 32-byte value.
func decodeHex64(value string) ([]byte, bool) {
	if !isLowerHex64(value) {
		return nil, false
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, false
	}
	return raw, true
}

// ed25519GroupOrder is the prime order L of the Ed25519 base-point subgroup,
// little-endian: publisher points outside the subgroup are refused rather than
// verified (the deployer's verifier applies the same check).
var ed25519GroupOrder = [32]byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

// pointHasPrimeOrder accepts only a nonidentity point in the base point's
// prime-order subgroup. SetBytes checks curve membership but accepts
// mixed-order points, which would weaken the threshold under the standard
// verifier. The order is public and fixed, so a plain double-and-add is
// preferable to an unchecked scalar encoding of L.
func pointHasPrimeOrder(point *edwards25519.Point) bool {
	identity := edwards25519.NewIdentityPoint()
	if point.Equal(identity) == 1 {
		return false
	}
	product := edwards25519.NewIdentityPoint()
	for byteIndex := len(ed25519GroupOrder) - 1; byteIndex >= 0; byteIndex-- {
		for bit := 7; bit >= 0; bit-- {
			product = new(edwards25519.Point).Double(product)
			if ed25519GroupOrder[byteIndex]&(1<<uint(bit)) != 0 {
				product = new(edwards25519.Point).Add(product, point)
			}
		}
	}
	return product.Equal(identity) == 1
}

// publisherKeyInGroup rejects a publisher point that is not canonical and in
// the base point's prime-order subgroup.
func publisherKeyInGroup(publicKey []byte) bool {
	point, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil || !bytes.Equal(point.Bytes(), publicKey) || !pointHasPrimeOrder(point) {
		return false
	}
	return true
}

// verifyReleaseSetSignatures is the deployer's threshold rule: every carried
// signature must be a member of the keyset the signed profile enrolled, every
// one must verify over the ASCII canonical digest, and a threshold of them
// must be present. One bad signature refuses the whole set; a key outside the
// keyset refuses by name.
func verifyReleaseSetSignatures(document releaseSetDocument, trusted map[string]string) (string, error) {
	if document.PublisherKeyset.Threshold == 0 || int(document.PublisherKeyset.Threshold) > len(trusted) {
		return "", errors.New("release_publisher_threshold_invalid")
	}
	_, digest, err := releaseSetDigest(document)
	if err != nil {
		return "", err
	}
	message := []byte(digest)
	valid := 0
	seen := make(map[string]bool, len(document.Signatures))
	for _, signature := range document.Signatures {
		if seen[signature.KeyID] {
			return "", fmt.Errorf("release_signature_duplicate:%s", signature.KeyID)
		}
		seen[signature.KeyID] = true
		publicKeyHex, member := trusted[signature.KeyID]
		if !member {
			return "", fmt.Errorf("release_signature_unknown_key:%s", signature.KeyID)
		}
		publicKey, ok := decodeHex64(publicKeyHex)
		if !ok || len(publicKey) != ed25519.PublicKeySize || !publisherKeyInGroup(publicKey) {
			return "", fmt.Errorf("release_publisher_keyset_invalid:%s", signature.KeyID)
		}
		raw, err := hex.DecodeString(signature.Signature)
		if err != nil || len(raw) != ed25519.SignatureSize || signature.Signature != hex.EncodeToString(raw) || !ed25519.Verify(publicKey, message, raw) {
			return "", fmt.Errorf("release_signature_invalid:%s", signature.KeyID)
		}
		valid++
	}
	if valid < int(document.PublisherKeyset.Threshold) {
		return "", fmt.Errorf("release_signature_threshold_unmet: %d valid of %d required", valid, document.PublisherKeyset.Threshold)
	}
	return digest, nil
}

// deriveReleaseDocumentInputs verifies the three typed release documents and
// returns the path-free derived inputs. Refusal order is part of the
// contract: profile signature, release-set signature, publisher device, and
// only then the absent release-tools role.
func deriveReleaseDocumentInputs(profilePath, releaseSetPath, publisherDevicePath string) (releaseDocumentInputs, error) {
	for _, item := range []struct {
		name, path string
	}{
		{"--estate-profile", profilePath},
		{"--release-set", releaseSetPath},
		{"--publisher-device", publisherDevicePath},
	} {
		if strings.TrimSpace(item.path) == "" {
			return releaseDocumentInputs{}, fmt.Errorf("%s is required", item.name)
		}
		if !filepath.IsAbs(item.path) || filepath.Clean(item.path) != item.path {
			return releaseDocumentInputs{}, fmt.Errorf("%s must be an absolute clean path", item.name)
		}
	}

	profileRaw, err := readEstateProfile(profilePath)
	if err != nil {
		return releaseDocumentInputs{}, err
	}
	profile, err := estateprofile.DecodeProfile(profileRaw)
	if err != nil {
		return releaseDocumentInputs{}, fmt.Errorf("estate profile: %w", err)
	}
	digest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		return releaseDocumentInputs{}, fmt.Errorf("estate profile: %w", err)
	}
	if _, err := estateBindingOf(profile, digest); err != nil {
		return releaseDocumentInputs{}, fmt.Errorf("estate profile: %w", err)
	}

	releaseRaw, err := readRegularFile(releaseSetPath, 8<<20)
	if err != nil {
		return releaseDocumentInputs{}, fmt.Errorf("--release-set: %w", err)
	}
	var document releaseSetDocument
	decoder := json.NewDecoder(bytes.NewReader(releaseRaw))
	if err := decoder.Decode(&document); err != nil {
		return releaseDocumentInputs{}, fmt.Errorf("--release-set: %w", err)
	}
	if document.Schema != releaseSetSchema {
		return releaseDocumentInputs{}, fmt.Errorf("--release-set schema %q is not %q", document.Schema, releaseSetSchema)
	}
	trusted := make(map[string]string, len(profile.ReleaseTrust.PublisherKeys))
	for _, key := range profile.ReleaseTrust.PublisherKeys {
		trusted[key] = key
	}
	// The release set's own keyset is a claim; the profile's enrolled keyset is
	// the authority. The deployer signs with the embedded keyset's members, so
	// verify against the keyset the document carries, then require every used
	// key to be one the owners signed into the profile.
	embedded := make(map[string]string, len(document.PublisherKeyset.Keys))
	for _, key := range document.PublisherKeyset.Keys {
		if _, duplicate := embedded[key.KeyID]; duplicate {
			return releaseDocumentInputs{}, fmt.Errorf("--release-set has a duplicate publisher keyId %q", key.KeyID)
		}
		embedded[key.KeyID] = key.Ed25519PublicKey
	}
	if uint32(document.PublisherKeyset.Threshold) != profile.ReleaseTrust.Threshold {
		return releaseDocumentInputs{}, errors.New("release_publisher_threshold_mismatch: signed estate profile")
	}
	releaseSetSHA256, err := verifyReleaseSetSignatures(document, embedded)
	if err != nil {
		return releaseDocumentInputs{}, fmt.Errorf("--release-set: %w", err)
	}
	for keyID := range embedded {
		enrolled := false
		for _, key := range profile.ReleaseTrust.PublisherKeys {
			if strings.EqualFold(embedded[keyID], key) {
				enrolled = true
				break
			}
		}
		if !enrolled {
			return releaseDocumentInputs{}, fmt.Errorf("--release-set publisher key %q is not in the estate profile's signed releaseTrust", keyID)
		}
	}

	deviceRaw, err := readRegularFile(publisherDevicePath, 1<<20)
	if err != nil {
		return releaseDocumentInputs{}, fmt.Errorf("--publisher-device: %w", err)
	}
	var device publisherDeviceReference
	if err := json.Unmarshal(deviceRaw, &device); err != nil {
		return releaseDocumentInputs{}, fmt.Errorf("--publisher-device: %w", err)
	}
	if device.Schema != publisherDeviceReferenceSchema {
		return releaseDocumentInputs{}, fmt.Errorf("--publisher-device schema %q is not %q", device.Schema, publisherDeviceReferenceSchema)
	}
	deviceKeyID, deviceKey, ok := device.normalized()
	if !ok {
		return releaseDocumentInputs{}, errors.New("PUBLISHER_DEVICE_UNTRUSTED: the device reference carries no key reference")
	}
	enrolled := false
	if member, isMember := embedded[deviceKeyID]; isMember && member == deviceKey {
		enrolled = true
	} else if device.KeyID == "" {
		// The C1 spelling carries no keyId: the key itself must be a member
		// of the keyset the signed release set embeds and the profile enrolled.
		for _, member := range embedded {
			if member == deviceKey {
				enrolled = true
				break
			}
		}
	}
	if !enrolled {
		return releaseDocumentInputs{}, errors.New("PUBLISHER_DEVICE_UNTRUSTED: the device reference does not name an enrolled publisher key")
	}

	// The signed release set must not carry a release-tools member today (no
	// campaign task adds one; K-REL-55): the derived role is "absent" and the
	// caller refuses provider selection by name.
	for _, artifact := range document.Artifacts {
		if artifact.Role == releaseToolsRole {
			return releaseDocumentInputs{}, fmt.Errorf("--release-set carries a %s member; governed provider execution is not wired through it yet", releaseToolsRole)
		}
	}
	pins, err := json.Marshal(document.Artifacts)
	if err != nil {
		return releaseDocumentInputs{}, err
	}
	return releaseDocumentInputs{
		Schema:               "melusina.release-inputs-preflight.v1",
		EstateID:             profile.EstateID,
		ProfileSHA256:        digest,
		ReleaseSetSHA256:     releaseSetSHA256,
		PublisherDeviceKeyID: device.KeyID,
		ReleaseToolsRole:     "absent",
		ArtifactPins:         pins,
	}, nil
}

// loadTypedPreflightConfig is the typed front door: the three documents are
// the only estate source, every legacy override is refused, and provider
// selection refuses RELEASE_PROVIDER_UNPINNED while the signed release set
// carries no release-tools member.
func loadTypedPreflightConfig(profilePath, releaseSetPath, publisherDevicePath string) (Config, releaseDocumentInputs, error) {
	inputs, err := deriveReleaseDocumentInputs(profilePath, releaseSetPath, publisherDevicePath)
	if err != nil {
		return Config{}, releaseDocumentInputs{}, err
	}
	profileRaw, err := readEstateProfile(profilePath)
	if err != nil {
		return Config{}, releaseDocumentInputs{}, err
	}
	profile, err := estateprofile.DecodeProfile(profileRaw)
	if err != nil {
		return Config{}, releaseDocumentInputs{}, fmt.Errorf("estate profile: %w", err)
	}
	estate, err := estateBindingOf(profile, inputs.ProfileSHA256)
	if err != nil {
		return Config{}, releaseDocumentInputs{}, fmt.Errorf("estate profile: %w", err)
	}
	if err := refuseEstateOverrides(estate); err != nil {
		return Config{}, releaseDocumentInputs{}, fmt.Errorf("PROFILE_PROJECTION_MISMATCH: %w", err)
	}
	c := Config{}
	c.ConfigPath = os.Getenv("MEL_RELEASE_CONFIG")
	c.RPCURL = os.Getenv("MEL_RELEASE_RPC_URL")
	c.EstateProfile = profilePath
	c.EstateProfileSHA256 = inputs.ProfileSHA256
	c.Channel = envOr("MEL_RELEASE_CHANNEL", "dev")
	c.OpTimeoutSecs = defaultReleaseOpTimeoutSecs
	if raw := strings.TrimSpace(os.Getenv("MEL_RELEASE_OP_TIMEOUT_SECS")); raw != "" {
		value, convErr := funcAtoi(raw)
		if convErr != nil || value < defaultReleaseOpTimeoutSecs || value > maxReleaseOpTimeoutSecs {
			return Config{}, releaseDocumentInputs{}, fmt.Errorf("MEL_RELEASE_OP_TIMEOUT_SECS must be an integer in %d..%d when set", defaultReleaseOpTimeoutSecs, maxReleaseOpTimeoutSecs)
		}
		c.OpTimeoutSecs = value
	}
	dir := os.Getenv("MEL_RELEASE_STATE_DIR")
	if strings.TrimSpace(dir) == "" {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil || home == "" {
			dir = filepath.Join(os.TempDir(), "mel-release")
		} else {
			dir = filepath.Join(home, ".mel-release")
		}
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return Config{}, releaseDocumentInputs{}, errors.New("MEL_RELEASE_STATE_DIR must be an absolute clean path")
	}
	c.StateDir = dir
	c.estate = estate
	c.StoreURL = estate.StoreOrigin
	c.BundleOrigin = estate.StoreOrigin
	c.StoreDomain = estate.StoreDomain
	c.StoreID = estate.StoreID
	c.ProgramID = estate.ProgramID
	c.MasterNftMint = estate.MasterNftMint
	c.ReleasePublisherKeys = estate.PublisherKeys
	c.ReleasePublisherThreshold = estate.PublisherThreshold
	c.SignerProvider = os.Getenv("MEL_RELEASE_SIGNER_PROVIDER")

	// Provider selection: while the signed release set carries no release-tools
	// member, governed provider execution refuses by name and never falls back
	// to an operator-chosen helper.
	return c, inputs, errors.New("RELEASE_PROVIDER_UNPINNED: the signed release set carries no " + releaseToolsRole + " member")
}

// funcAtoi is strconv.Atoi under a non-colliding name (strconv is already
// imported by config.go in this package).
func funcAtoi(value string) (int, error) { return strconv.Atoi(value) }
