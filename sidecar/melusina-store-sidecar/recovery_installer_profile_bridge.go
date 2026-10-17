package main

// The immutable on-chain InstallerReleaseTrust still names the signed old
// building profile. This file admits only the three F1 hashes authorized by
// the dual-quorum recovery admission and the separately owner/council-signed
// bridge. Ordinary installer trust remains successor-profile-bound.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	recoveryBridgeDomain      = "MELUSINA_RECOVERY_INSTALLER_PROFILE_BRIDGE_V1\n"
	recoveryAdmissionDomain   = "MELUSINA_LOST_PREDECESSOR_FORWARD_ADMISSION_V1\n"
	recoveryBridgeStateSchema = "melusina.store-recovery-installer-profile-bridge-state.v1"
)

var errRecoveryBridge = errors.New("recovery-installer-profile-bridge-refused")

type recoveryCouncilSignature struct {
	Member    string `json:"member"`
	Signature string `json:"signature"`
}

// Field order is the deployer's canonical, domain-separated Go preimage.
type recoveryInstallerBridge struct {
	Schema                    string                      `json:"schema"`
	AdmissionNonce            string                      `json:"admissionNonce"`
	EstateID                  string                      `json:"estateId"`
	Genesis                   string                      `json:"genesis"`
	MasterMint                string                      `json:"masterMint"`
	RegistryProgram           string                      `json:"registryProgram"`
	CoreVault                 string                      `json:"coreVault"`
	OldProfileRawSHA256       string                      `json:"oldProfileRawSha256"`
	OldProfileDigest          string                      `json:"oldProfileDigest"`
	SuccessorProfileRawSHA256 string                      `json:"successorProfileRawSha256"`
	SuccessorProfileDigest    string                      `json:"successorProfileDigest"`
	ReleaseTrustRawSHA256     string                      `json:"releaseTrustRawSha256"`
	ReleaseTrustThreshold     uint32                      `json:"releaseTrustThreshold"`
	ReleaseTrustKeys          []string                    `json:"releaseTrustKeys"`
	OldOperator               string                      `json:"oldOperator"`
	NewOperator               string                      `json:"newOperator"`
	OwnerChoiceSHA256         string                      `json:"ownerChoiceSha256"`
	RotationApprovalSHA256    string                      `json:"rotationApprovalSha256"`
	FoundationSequence        uint64                      `json:"foundationSequence"`
	F1Sequence                uint64                      `json:"f1Sequence"`
	InstallerSHA256           string                      `json:"installerSha256"`
	InstallerPDA              string                      `json:"installerPda"`
	ShellSHA256               string                      `json:"shellSha256"`
	ShellPDA                  string                      `json:"shellPda"`
	UpdateControllerSHA256    string                      `json:"updateControllerSha256"`
	UpdateControllerPDA       string                      `json:"updateControllerPda"`
	StoreArchiveSHA256        string                      `json:"storeArchiveSha256"`
	StoreBinarySHA256         string                      `json:"storeBinarySha256"`
	DeployerCommit            string                      `json:"deployerCommit"`
	ContractsCommit           string                      `json:"contractsCommit"`
	StoreCommit               string                      `json:"storeCommit"`
	IssuedAt                  time.Time                   `json:"issuedAt"`
	ExpiresAt                 time.Time                   `json:"expiresAt"`
	Nonce                     string                      `json:"nonce"`
	OwnerSignatures           []estateprofile.SignatureV1 `json:"ownerSignatures"`
	CouncilSignatures         []recoveryCouncilSignature  `json:"councilSignatures"`
}

type recoveryBridgeState struct {
	Schema              string `json:"schema"`
	BridgeRaw           []byte `json:"bridgeRaw"`
	AdmissionRaw        []byte `json:"admissionRaw"`
	AdmissionRawSHA256  string `json:"admissionRawSha256"`
	OldProfileRaw       []byte `json:"oldProfileRaw"`
	SuccessorProfileRaw []byte `json:"successorProfileRaw"`
	F0Raw               []byte `json:"f0Raw"`
	F1Raw               []byte `json:"f1Raw"`
	BridgeSHA256        string `json:"bridgeSha256"`
	F0RawSHA256         string `json:"f0RawSha256"`
	F0Digest            string `json:"f0Digest"`
	F1RawSHA256         string `json:"f1RawSha256"`
	F1Digest            string `json:"f1Digest"`
}

type recoveryAdmissionClaim struct {
	Statement           json.RawMessage            `json:"statement"`
	CouncilSignatures   []recoveryCouncilSignature `json:"councilSignatures"`
	PublisherSignatures []struct {
		KeyID     string `json:"keyId"`
		Signature string `json:"signature"`
	} `json:"publisherSignatures"`
}

type recoveryAdmissionStatement struct {
	Schema                    string   `json:"schema"`
	Genesis                   string   `json:"genesis"`
	EstateID                  string   `json:"estateId"`
	MasterMint                string   `json:"masterMint"`
	RegistryProgram           string   `json:"registryProgram"`
	CoreVault                 string   `json:"coreVault"`
	CoreMembers               []string `json:"coreMembers"`
	CoreThreshold             uint8    `json:"coreThreshold"`
	OldEstateProfileRawSHA256 string   `json:"oldEstateProfileRawSha256"`
	OldEstateProfileDigest    string   `json:"oldEstateProfileDigest"`
	ProfileBridgeSHA256       string   `json:"profileBridgeSha256"`
	ReleaseTrustSHA256        string   `json:"releaseTrustSha256"`
	LivePublisherKeyset       struct {
		Threshold uint8 `json:"threshold"`
		Keys      []struct {
			KeyID            string `json:"keyId"`
			Ed25519PublicKey string `json:"ed25519PublicKey"`
		} `json:"keys"`
	} `json:"livePublisherKeyset"`
	FoundationSequence     uint64    `json:"foundationSequence"`
	OwnerChoiceSHA256      string    `json:"ownerChoiceSha256"`
	RotationApprovalSHA256 string    `json:"rotationApprovalSha256"`
	NewOperator            string    `json:"newOperator"`
	StoreBinarySHA256      string    `json:"storeBinarySha256"`
	StoreArchiveSHA256     string    `json:"storeArchiveSha256"`
	InstallerSHA256        string    `json:"installerSha256"`
	ShellSHA256            string    `json:"shellSha256"`
	DeployerCommit         string    `json:"deployerCommit"`
	ContractsCommit        string    `json:"contractsCommit"`
	StoreCommit            string    `json:"storeCommit"`
	IssuedAt               time.Time `json:"issuedAt"`
	ExpiresAt              time.Time `json:"expiresAt"`
	Nonce                  string    `json:"nonce"`
}

func recoveryDigest(domain string, raw []byte) string {
	sum := sha256.Sum256(append([]byte(domain), raw...))
	return hex.EncodeToString(sum[:])
}

func recoverySHA(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func recoveryExecutableSHA() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w:binary-file", errRecoveryBridge)
	}
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func verifyRecoveryCouncil(sigs []recoveryCouncilSignature, members []string, digest string) error {
	if len(sigs) != 3 || len(members) != 4 || !sort.StringsAreSorted(members) {
		return fmt.Errorf("%w:council-threshold", errRecoveryBridge)
	}
	for i := 1; i < len(members); i++ {
		if members[i-1] >= members[i] {
			return fmt.Errorf("%w:council-members", errRecoveryBridge)
		}
	}
	seen := map[string]bool{}
	for _, sig := range sigs {
		key, keyErr := primitives.PubkeyFromBase58(sig.Member)
		proof, proofErr := base64.RawURLEncoding.DecodeString(sig.Signature)
		if seen[sig.Member] || !recoveryMember(members, sig.Member) ||
			keyErr != nil || proofErr != nil || len(proof) != ed25519.SignatureSize ||
			!ed25519.Verify(key[:], []byte(digest), proof) {
			return fmt.Errorf("%w:council-signatures", errRecoveryBridge)
		}
		seen[sig.Member] = true
	}
	return nil
}

func recoveryMember(members []string, member string) bool {
	i := sort.SearchStrings(members, member)
	return i < len(members) && members[i] == member
}

// The admission signers use the deployer's typed LostPredecessorStatement
// preimage. JSON object order on the wire is immaterial: a producer may add
// profileBridgeSha256 after the other fields while the typed preimage places
// it beside the old profile. Rebuild that field order before checking either
// quorum. The signed F0 separately fixes the complete transported raw bytes.
func recoveryAdmissionPreimage(raw []byte) ([]byte, error) {
	order := []string{
		"schema", "genesis", "estateId", "masterMint", "licenseMint", "registryProgram",
		"squadsProgram", "coreMultisig", "coreVault", "coreMembers", "coreThreshold",
		"noConfigAuthority", "oldEstateProfileRawSha256", "oldEstateProfileDigest",
		"continuityProfileRawSha256", "profileBridgeSha256", "releaseTrustSha256",
		"livePublisherKeyset", "signedFoundationHighWater", "signedDeployableHighWater",
		"highWaterLedgerSha256", "foundationSequence", "setProjectionSha256", "snapshot",
		"reportSha256", "ownerChoiceSha256", "rotationApprovalSha256", "newOperator",
		"storeVersion", "storePda", "storeBinarySha256", "storeArchiveSha256",
		"chainLeafSha256", "installerSha256", "shellSha256", "deployerCommit",
		"contractsCommit", "storeCommit", "issuedAt", "expiresAt", "nonce",
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, fmt.Errorf("%w:admission-json", errRecoveryBridge)
	}
	var preimage bytes.Buffer
	preimage.WriteByte('{')
	count := 0
	for _, name := range order {
		value, exists := fields[name]
		if !exists && name == "profileBridgeSha256" {
			continue // the V1 field is optional for admissions without a bridge
		}
		if !exists || len(value) == 0 {
			return nil, fmt.Errorf("%w:admission-json", errRecoveryBridge)
		}
		if count != 0 {
			preimage.WriteByte(',')
		}
		key, _ := json.Marshal(name)
		canonicalValue, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("%w:admission-json", errRecoveryBridge)
		}
		preimage.Write(key)
		preimage.WriteByte(':')
		preimage.Write(canonicalValue)
		count++
	}
	if count != len(fields) {
		return nil, fmt.Errorf("%w:admission-json", errRecoveryBridge)
	}
	preimage.WriteByte('}')
	return preimage.Bytes(), nil
}

func verifyRecoveryAdmission(raw []byte, now time.Time) (recoveryAdmissionStatement, string, error) {
	var admission recoveryAdmissionClaim
	var statement recoveryAdmissionStatement
	if len(raw) == 0 || len(raw) > 2<<20 || assertNoDuplicateJSONKeys(raw) != nil ||
		json.Unmarshal(raw, &admission) != nil || assertNoDuplicateJSONKeys(admission.Statement) != nil ||
		json.Unmarshal(admission.Statement, &statement) != nil {
		return statement, "", fmt.Errorf("%w:admission-json", errRecoveryBridge)
	}
	preimage, preimageErr := recoveryAdmissionPreimage(admission.Statement)
	if preimageErr != nil {
		return statement, "", preimageErr
	}
	if statement.Schema != "melusina.lost-predecessor-forward-admission.v1" ||
		statement.CoreThreshold != 3 || now.Before(statement.IssuedAt) || now.After(statement.ExpiresAt) ||
		statement.ExpiresAt.Sub(statement.IssuedAt) > 24*time.Hour {
		return statement, "", fmt.Errorf("%w:admission-window", errRecoveryBridge)
	}
	digest := recoveryDigest(recoveryAdmissionDomain, preimage)
	if err := verifyRecoveryCouncil(admission.CouncilSignatures, statement.CoreMembers, digest); err != nil {
		return statement, "", err
	}
	if len(admission.PublisherSignatures) != 2 || statement.LivePublisherKeyset.Threshold != 2 ||
		len(statement.LivePublisherKeyset.Keys) < 2 || len(statement.LivePublisherKeyset.Keys) > 16 {
		return statement, "", fmt.Errorf("%w:publisher-threshold", errRecoveryBridge)
	}
	seenKeys, seenPublic := map[string]bool{}, map[string]bool{}
	for _, key := range statement.LivePublisherKeyset.Keys {
		if key.KeyID == "" || seenKeys[key.KeyID] || seenPublic[key.Ed25519PublicKey] {
			return statement, "", fmt.Errorf("%w:publisher-keyset", errRecoveryBridge)
		}
		decoded, err := hex.DecodeString(key.Ed25519PublicKey)
		if err != nil || len(decoded) != ed25519.PublicKeySize || hex.EncodeToString(decoded) != key.Ed25519PublicKey {
			return statement, "", fmt.Errorf("%w:publisher-keyset", errRecoveryBridge)
		}
		seenKeys[key.KeyID], seenPublic[key.Ed25519PublicKey] = true, true
	}
	seen := map[string]bool{}
	for _, sig := range admission.PublisherSignatures {
		var keyHex string
		for _, key := range statement.LivePublisherKeyset.Keys {
			if key.KeyID == sig.KeyID {
				keyHex = key.Ed25519PublicKey
			}
		}
		key, keyErr := hex.DecodeString(keyHex)
		proof, proofErr := hex.DecodeString(sig.Signature)
		if seen[sig.KeyID] || keyHex == "" || keyErr != nil || len(key) != ed25519.PublicKeySize ||
			proofErr != nil || len(proof) != ed25519.SignatureSize || !ed25519.Verify(key, []byte(digest), proof) {
			return statement, "", fmt.Errorf("%w:publisher-signatures", errRecoveryBridge)
		}
		seen[sig.KeyID] = true
	}
	return statement, digest, nil
}

func recoveryBridgePath(cfg Config) string {
	if cfg.EstateEnrollmentStatePath == "" {
		return ""
	}
	return cfg.EstateEnrollmentStatePath + ".recovery-installer-profile-bridge.json"
}

func recoveryProfileAnchors(profile estateprofile.EstateProfileV1) (string, string) {
	var registry, vault string
	for _, program := range profile.Programs {
		if program.Role == estateprofile.ProgramRoleLicenseRegistry {
			registry = program.ProgramID
		}
	}
	for _, role := range profile.Roles {
		if role.Role == estateprofile.AuthorityRoleCore {
			vault = role.Vault
		}
	}
	return registry, vault
}

func recoveryEntryPDA(programB58, mintB58, hashHex string) string {
	program, e1 := primitives.PubkeyFromBase58(programB58)
	mint, e2 := primitives.PubkeyFromBase58(mintB58)
	raw, e3 := hex.DecodeString(hashHex)
	if e1 != nil || e2 != nil || e3 != nil || len(raw) != 32 {
		return ""
	}
	var hash [32]byte
	copy(hash[:], raw)
	pda, _, err := primitives.DeriveInstallerRelease(mint, hash, program)
	if err != nil {
		return ""
	}
	return pda.Base58()
}

func verifyRecoveryBridgeQuorums(bridge recoveryInstallerBridge, owner estateprofile.OwnerPolicyV1,
	members []string, digest string) error {
	if len(bridge.OwnerSignatures) != int(owner.Threshold) ||
		estateprofile.VerifyOwnerThreshold(owner, digest, bridge.OwnerSignatures) != nil {
		return fmt.Errorf("%w:owner-signatures", errRecoveryBridge)
	}
	if err := verifyRecoveryCouncil(bridge.CouncilSignatures, members, digest); err != nil {
		return err
	}
	return nil
}

func decodeRecoveryBridgeState(raw []byte, enrolled *storeEnrollmentState, now time.Time) (recoveryBridgeState, recoveryInstallerBridge, servedReleaseSet, error) {
	var state recoveryBridgeState
	var bridge recoveryInstallerBridge
	var f1 servedReleaseSet
	if enrolled == nil || assertNoDuplicateJSONKeys(raw) != nil || decodeCatalogStrictJSON(raw, &state) != nil ||
		state.Schema != recoveryBridgeStateSchema || len(state.BridgeRaw) == 0 || len(state.AdmissionRaw) == 0 ||
		len(state.OldProfileRaw) == 0 || len(state.SuccessorProfileRaw) == 0 || len(state.F0Raw) == 0 || len(state.F1Raw) == 0 {
		return state, bridge, f1, fmt.Errorf("%w:state", errRecoveryBridge)
	}
	if assertNoDuplicateJSONKeys(state.BridgeRaw) != nil || decodeCatalogStrictJSON(state.BridgeRaw, &bridge) != nil ||
		bridge.Schema != "melusina.recovery-installer-profile-bridge.v1" ||
		recoverySHA(state.AdmissionRaw) != state.AdmissionRawSHA256 ||
		recoverySHA(state.F0Raw) != state.F0RawSHA256 || recoverySHA(state.F1Raw) != state.F1RawSHA256 {
		return state, bridge, f1, fmt.Errorf("%w:bridge-json", errRecoveryBridge)
	}
	unsigned := bridge
	unsigned.OwnerSignatures, unsigned.CouncilSignatures = nil, nil
	preimage, err := json.Marshal(unsigned)
	if err != nil {
		return state, bridge, f1, err
	}
	digest := recoveryDigest(recoveryBridgeDomain, preimage)
	if digest != state.BridgeSHA256 || bridge.FoundationSequence < 106 || bridge.F1Sequence <= bridge.FoundationSequence ||
		bridge.Nonce == "" || bridge.ExpiresAt.Sub(bridge.IssuedAt) > 24*time.Hour ||
		!now.IsZero() && (now.Before(bridge.IssuedAt) || now.After(bridge.ExpiresAt)) {
		return state, bridge, f1, fmt.Errorf("%w:bridge-digest", errRecoveryBridge)
	}
	statement, admissionDigest, err := verifyRecoveryAdmission(state.AdmissionRaw, bridge.IssuedAt)
	if err != nil {
		return state, bridge, f1, err
	}
	if statement.ProfileBridgeSHA256 != digest || statement.Nonce != bridge.AdmissionNonce ||
		statement.EstateID != bridge.EstateID || statement.Genesis != bridge.Genesis ||
		statement.MasterMint != bridge.MasterMint || statement.RegistryProgram != bridge.RegistryProgram ||
		statement.CoreVault != bridge.CoreVault || statement.OldEstateProfileRawSHA256 != bridge.OldProfileRawSHA256 ||
		statement.OldEstateProfileDigest != bridge.OldProfileDigest || statement.ReleaseTrustSHA256 != bridge.ReleaseTrustRawSHA256 ||
		statement.NewOperator != bridge.NewOperator || statement.OwnerChoiceSHA256 != bridge.OwnerChoiceSHA256 ||
		statement.RotationApprovalSHA256 != bridge.RotationApprovalSHA256 || statement.FoundationSequence != bridge.FoundationSequence ||
		statement.InstallerSHA256 != bridge.InstallerSHA256 || statement.ShellSHA256 != bridge.ShellSHA256 ||
		statement.StoreArchiveSHA256 != bridge.StoreArchiveSHA256 || statement.StoreBinarySHA256 != bridge.StoreBinarySHA256 ||
		statement.DeployerCommit != bridge.DeployerCommit || statement.ContractsCommit != bridge.ContractsCommit || statement.StoreCommit != bridge.StoreCommit {
		return state, bridge, f1, fmt.Errorf("%w:admission-binding", errRecoveryBridge)
	}
	oldProfile, oldErr := estateprofile.DecodeProfile(state.OldProfileRaw)
	newProfile, newErr := estateprofile.DecodeProfile(state.SuccessorProfileRaw)
	oldRegistry, oldVault := recoveryProfileAnchors(oldProfile)
	newRegistry, newVault := recoveryProfileAnchors(newProfile)
	var liveKeys []string
	for _, key := range statement.LivePublisherKeyset.Keys {
		liveKeys = append(liveKeys, key.Ed25519PublicKey)
	}
	sort.Strings(liveKeys)
	oldTrust, oldDigest, oldTrustErr := installerrelease.TrustFromProfile(oldProfile)
	_, newDigest, newTrustErr := installerrelease.TrustFromProfile(newProfile)
	if oldErr != nil || newErr != nil || oldTrustErr != nil || newTrustErr != nil || oldTrust == nil ||
		recoverySHA(state.OldProfileRaw) != bridge.OldProfileRawSHA256 || recoverySHA(state.SuccessorProfileRaw) != bridge.SuccessorProfileRawSHA256 ||
		oldDigest != bridge.OldProfileDigest || newDigest != bridge.SuccessorProfileDigest || newDigest != enrolled.ProfilePin.ProfileSHA256 ||
		!reflect.DeepEqual(newProfile, enrolled.Profile) || oldProfile.EstateID != bridge.EstateID || newProfile.EstateID != bridge.EstateID ||
		oldProfile.Network.GenesisHash != bridge.Genesis || newProfile.Network.GenesisHash != bridge.Genesis ||
		oldProfile.Anchors.MasterMint != bridge.MasterMint || newProfile.Anchors.MasterMint != bridge.MasterMint ||
		oldRegistry != bridge.RegistryProgram || newRegistry != bridge.RegistryProgram ||
		oldVault != bridge.CoreVault || newVault != bridge.CoreVault ||
		oldProfile.Store.OperatorKey != bridge.OldOperator || newProfile.Store.OperatorKey != bridge.NewOperator ||
		oldProfile.Revision+1 != newProfile.Revision || newProfile.Prev.SHA256 != oldDigest ||
		!reflect.DeepEqual(oldProfile.OwnerPolicy, newProfile.OwnerPolicy) ||
		!reflect.DeepEqual(oldProfile.GenesisOwnerPolicy, newProfile.GenesisOwnerPolicy) ||
		!reflect.DeepEqual(oldProfile.ReleaseTrust, newProfile.ReleaseTrust) ||
		oldProfile.ReleaseTrust.Threshold != bridge.ReleaseTrustThreshold ||
		uint32(statement.LivePublisherKeyset.Threshold) != bridge.ReleaseTrustThreshold ||
		!reflect.DeepEqual(oldProfile.ReleaseTrust.PublisherKeys, bridge.ReleaseTrustKeys) ||
		!reflect.DeepEqual(liveKeys, bridge.ReleaseTrustKeys) {
		return state, bridge, f1, fmt.Errorf("%w:profile-transition", errRecoveryBridge)
	}
	if err := verifyRecoveryBridgeQuorums(bridge, newProfile.OwnerPolicy, statement.CoreMembers, digest); err != nil {
		return state, bridge, f1, err
	}
	if recoveryEntryPDA(bridge.RegistryProgram, bridge.MasterMint, bridge.InstallerSHA256) != bridge.InstallerPDA ||
		recoveryEntryPDA(bridge.RegistryProgram, bridge.MasterMint, bridge.ShellSHA256) != bridge.ShellPDA ||
		recoveryEntryPDA(bridge.RegistryProgram, bridge.MasterMint, bridge.UpdateControllerSHA256) != bridge.UpdateControllerPDA {
		return state, bridge, f1, fmt.Errorf("%w:entry-pda", errRecoveryBridge)
	}
	f0, f0Digest, f0Err := verifySignedReleaseSet(state.F0Raw, newProfile.ReleaseTrust.PublisherKeys, newProfile.ReleaseTrust.Threshold)
	if f0Err != nil || f0Digest != state.F0Digest || f0.Sequence != bridge.FoundationSequence || f0.Stage != "foundation" ||
		f0.Continuity == nil || f0.Continuity.Kind != "lost-predecessor" || f0.Continuity.AdmissionSHA256 != admissionDigest {
		return state, bridge, f1, fmt.Errorf("%w:f0-signature", errRecoveryBridge)
	}
	transport := map[string]string{
		"runbook-recovery-installer-profile-bridge.json": recoverySHA(state.BridgeRaw),
		"runbook-recovery-old-estate-profile.json":       recoverySHA(state.OldProfileRaw),
		"runbook-recovery-successor-estate-profile.json": recoverySHA(state.SuccessorProfileRaw),
	}
	seenTransport := map[string]bool{}
	seenOldFacts := false
	for _, artifact := range f0.Artifacts {
		if want, yes := transport[artifact.Name]; yes {
			if seenTransport[artifact.Name] || artifact.Role != "runbook" || artifact.SHA256 != want || artifact.SizeBytes > 64<<10 {
				return state, bridge, f1, fmt.Errorf("%w:f0-transport", errRecoveryBridge)
			}
			seenTransport[artifact.Name] = true
		}
		if artifact.Name == "runbook-recovery-old-store-host-facts.json" {
			if seenOldFacts || artifact.Role != "runbook" || artifact.SizeBytes > 64<<10 {
				return state, bridge, f1, fmt.Errorf("%w:f0-transport", errRecoveryBridge)
			}
			seenOldFacts = true
		}
	}
	if len(seenTransport) != 3 || !seenOldFacts {
		return state, bridge, f1, fmt.Errorf("%w:f0-transport", errRecoveryBridge)
	}
	f1, f1Digest, err := verifySignedReleaseSet(state.F1Raw, newProfile.ReleaseTrust.PublisherKeys, newProfile.ReleaseTrust.Threshold)
	if err != nil || f1Digest != state.F1Digest || f1.Sequence != bridge.F1Sequence || f1.Stage != "foundation" ||
		f1.Continuity != nil || f1.Sequence <= f0.Sequence {
		return state, bridge, f1, fmt.Errorf("%w:f1-signature", errRecoveryBridge)
	}
	wants := map[string]string{"installer": bridge.InstallerSHA256, "shell-bundle": bridge.ShellSHA256, "update-controller": bridge.UpdateControllerSHA256}
	seen := map[string]bool{}
	for _, artifact := range f1.Artifacts {
		if want, ok := wants[artifact.Role]; ok {
			if seen[artifact.Role] || artifact.SHA256 != want {
				return state, bridge, f1, fmt.Errorf("%w:f1-member", errRecoveryBridge)
			}
			seen[artifact.Role] = true
		}
	}
	if len(seen) != 3 {
		return state, bridge, f1, fmt.Errorf("%w:f1-member", errRecoveryBridge)
	}
	return state, bridge, f1, nil
}

func readRecoveryBridgeState(cfg Config, enrolled *storeEnrollmentState) (recoveryBridgeState, recoveryInstallerBridge, servedReleaseSet, error) {
	var empty recoveryBridgeState
	var bridge recoveryInstallerBridge
	var f1 servedReleaseSet
	path := recoveryBridgePath(cfg)
	if path == "" {
		return empty, bridge, f1, os.ErrNotExist
	}
	raw, err := readOwnedRegular(path, 0o600, uint32(os.Geteuid()), 3<<20)
	if err != nil {
		return empty, bridge, f1, err
	}
	return decodeRecoveryBridgeState(raw, enrolled, time.Time{})
}

func recoveryBridgeHash(bridge recoveryInstallerBridge, hash string) (string, string, bool) {
	switch hash {
	case bridge.InstallerSHA256:
		return "installer", bridge.InstallerPDA, true
	case bridge.ShellSHA256:
		return "shell-bundle", bridge.ShellPDA, true
	case bridge.UpdateControllerSHA256:
		return "update-controller", bridge.UpdateControllerPDA, true
	default:
		return "", "", false
	}
}

func verifyRecoveryTrustRaw(ctx context.Context, reader rawAccountReader, bridge recoveryInstallerBridge) error {
	master, masterErr := primitives.PubkeyFromBase58(bridge.MasterMint)
	program, programErr := primitives.PubkeyFromBase58(bridge.RegistryProgram)
	if masterErr != nil || programErr != nil || [32]byte(program) != [32]byte(licenseRegistryProgramID()) {
		return fmt.Errorf("%w:chain-anchors", errRecoveryBridge)
	}
	trustPDA, _, err := primitives.FindProgramAddress([][]byte{[]byte("installer_release_trust"), master[:]}, program, nil)
	if err != nil {
		return fmt.Errorf("%w:trust-pda", errRecoveryBridge)
	}
	raw, owner, err := reader.fetchRawAccount(ctx, trustPDA.Base58())
	if err != nil || owner != bridge.RegistryProgram || recoverySHA(raw) != bridge.ReleaseTrustRawSHA256 {
		return fmt.Errorf("%w:trust-raw-drift", errRecoveryBridge)
	}
	return nil
}

// Called only after the ordinary successor-profile trust refuses. Every call
// re-reads the root-owned bridge state, highest signed set, raw trust account
// and Active entry; no prior guest evidence or verdict cache is used.
func verifyRecoveryInstallerReleaseHash(ctx context.Context, cr chainReader, cfg Config, meta installerReleaseMeta, hash [32]byte) error {
	if cfg.EstateEnrollmentStatePath == "" {
		return fmt.Errorf("%w:ordinary-path", errRecoveryBridge)
	}
	enrolled, err := readStoreEnrollmentState(cfg.EstateEnrollmentStatePath, uint32(os.Geteuid()))
	if err != nil {
		return fmt.Errorf("%w:enrollment-state", errRecoveryBridge)
	}
	bridgeState, bridge, f1, err := readRecoveryBridgeState(cfg, &enrolled)
	if err != nil {
		return fmt.Errorf("%w:state", errRecoveryBridge)
	}
	hashHex := hex.EncodeToString(hash[:])
	role, pda, okay := recoveryBridgeHash(bridge, hashHex)
	if !okay || meta.PDA != pda {
		return fmt.Errorf("%w:member-pda", errRecoveryBridge)
	}
	var artifactName string
	var artifactSize int64
	for _, artifact := range f1.Artifacts {
		if artifact.Role == role && artifact.SHA256 == hashHex {
			artifactName, artifactSize = artifact.Name, artifact.SizeBytes
		}
	}
	if artifactName == "" || verifyServedReleaseSet(cfg, "shell", hashHex+"-"+artifactName, hashHex, artifactSize) != nil {
		return fmt.Errorf("%w:highest-signed-set", errRecoveryBridge)
	}
	rawReader, ok := cr.(rawAccountReader)
	if !ok {
		return fmt.Errorf("%w:raw-chain-reader", errRecoveryBridge)
	}
	if err := verifyRecoveryTrustRaw(ctx, rawReader, bridge); err != nil {
		return err
	}
	oldProfile, err := estateprofile.DecodeProfile(bridgeState.OldProfileRaw)
	if err != nil {
		return fmt.Errorf("%w:old-profile", errRecoveryBridge)
	}
	oldTrust, oldDigest, err := installerrelease.TrustFromProfile(oldProfile)
	if err != nil || oldDigest != bridge.OldProfileDigest || oldTrust.Admit(meta.Entry, hash) != nil {
		return fmt.Errorf("%w:entry-old-trust", errRecoveryBridge)
	}
	return nil
}
