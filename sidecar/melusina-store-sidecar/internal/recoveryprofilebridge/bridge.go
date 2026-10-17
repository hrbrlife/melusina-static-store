// Package recoveryprofilebridge verifies the one-estate, one-generation
// transition from the occupied InstallerReleaseTrust profile to its signed
// successor. It never changes the on-chain trust or authorizes registration.
package recoveryprofilebridge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	Schema = "melusina.recovery-installer-profile-bridge.v1"
	domain = "MELUSINA_RECOVERY_INSTALLER_PROFILE_BRIDGE_V1\n"
)

var (
	ErrMalformed  = errors.New("recovery-profile-bridge-malformed")
	ErrAdmission  = errors.New("recovery-profile-bridge-admission-or-set-mismatch")
	ErrSignature  = errors.New("recovery-profile-bridge-signature-refused")
	ErrProfile    = errors.New("recovery-profile-bridge-profile-refused")
	ErrChainDrift = errors.New("recovery-profile-bridge-chain-drift")
	ErrMember     = errors.New("recovery-profile-bridge-member-refused")
	ErrScope      = errors.New("recovery-profile-bridge-scope-refused")
)

// Member is one exact F1 installer artifact and its observed Active entry.
// The three roles are fixed; the signed bridge cannot admit a fourth hash.
type Member struct {
	Role               string `json:"role"`
	ArtifactSHA256     string `json:"artifactSha256"`
	ArtifactSize       uint64 `json:"artifactSize"`
	EntryPDA           string `json:"entryPda"`
	EntryRawSHA256     string `json:"entryRawSha256"`
	EntryProfileDigest string `json:"entryProfileDigest"`
	EntryStatus        string `json:"entryStatus"`
}

type Statement struct {
	Schema                    string   `json:"schema"`
	AdmissionSHA256           string   `json:"admissionSha256"`
	AdmissionNonce            string   `json:"admissionNonce"`
	EstateID                  string   `json:"estateId"`
	Genesis                   string   `json:"genesis"`
	MasterMint                string   `json:"masterMint"`
	RegistryProgram           string   `json:"registryProgram"`
	CoreMultisig              string   `json:"coreMultisig"`
	CoreVault                 string   `json:"coreVault"`
	OldProfileRawSHA256       string   `json:"oldProfileRawSha256"`
	OldProfileDigest          string   `json:"oldProfileDigest"`
	SuccessorProfileRawSHA256 string   `json:"successorProfileRawSha256"`
	SuccessorProfileDigest    string   `json:"successorProfileDigest"`
	LiveTrustRawSHA256        string   `json:"liveTrustRawSha256"`
	FoundationSequence        uint64   `json:"foundationSequence"`
	DeployableSequence        uint64   `json:"deployableSequence"`
	InstallerSHA256           string   `json:"installerSha256"`
	ShellSHA256               string   `json:"shellSha256"`
	StoreArchiveSHA256        string   `json:"storeArchiveSha256"`
	StoreBinarySHA256         string   `json:"storeBinarySha256"`
	DeployerCommit            string   `json:"deployerCommit"`
	StoreCommit               string   `json:"storeCommit"`
	NewOperator               string   `json:"newOperator"`
	RotationApprovalSHA256    string   `json:"rotationApprovalSha256"`
	Members                   []Member `json:"members"`
}

type CouncilSignature struct {
	Member    string `json:"member"`
	Signature string `json:"signature"`
}

type Signed struct {
	Statement         Statement                   `json:"statement"`
	OwnerSignatures   []estateprofile.SignatureV1 `json:"ownerSignatures"`
	CouncilSignatures []CouncilSignature          `json:"councilSignatures"`
}

type Observation struct {
	AdmissionSHA256                 string
	AdmissionNonce                  string
	FoundationBridgeIntentSHA256    string
	AdmissionOldProfileRawSHA256    string
	AdmissionOldProfileDigest       string
	AdmissionNewOperator            string
	AdmissionRotationApprovalSHA256 string
	AdmissionInstallerSHA256        string
	AdmissionShellSHA256            string
	AdmissionStoreArchiveSHA256     string
	AdmissionStoreBinarySHA256      string
	AdmissionDeployerCommit         string
	AdmissionStoreCommit            string
	FoundationSequence              uint64
	DeployableSequence              uint64
	TrustRawSHA256                  string
	TrustProfileDigest              string
	TrustPublisherKeys              []string
	TrustThreshold                  uint32
	Members                         []Member
	CoreMembers                     []string
	CoreThreshold                   uint32
}

func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && hex.EncodeToString(b) == s && s != string(bytes.Repeat([]byte{'0'}, 64))
}

func validAddress(s string) bool { _, err := primitives.PubkeyFromBase58(s); return err == nil }

func validCommit(s string) bool {
	if len(s) != 40 {
		return false
	}
	raw, err := hex.DecodeString(s)
	return err == nil && hex.EncodeToString(raw) == s
}

func validateStatement(s Statement, completed bool) error {
	if s.Schema != Schema || !validHash(s.AdmissionSHA256) || !validHash(s.AdmissionNonce) ||
		!validHash(s.OldProfileRawSHA256) || !validHash(s.OldProfileDigest) ||
		!validHash(s.SuccessorProfileRawSHA256) || !validHash(s.SuccessorProfileDigest) ||
		!validHash(s.LiveTrustRawSHA256) || !validHash(s.InstallerSHA256) ||
		!validHash(s.ShellSHA256) || !validHash(s.StoreArchiveSHA256) ||
		!validHash(s.StoreBinarySHA256) || !validHash(s.RotationApprovalSHA256) ||
		!validAddress(s.MasterMint) || !validAddress(s.RegistryProgram) ||
		!validAddress(s.CoreMultisig) || !validAddress(s.CoreVault) || !validAddress(s.NewOperator) ||
		s.EstateID == "" || s.Genesis == "" || !validCommit(s.DeployerCommit) || !validCommit(s.StoreCommit) ||
		s.FoundationSequence < 106 || s.DeployableSequence <= s.FoundationSequence {
		return ErrMalformed
	}
	if len(s.Members) != 3 {
		return ErrMember
	}
	roles := []string{"installer", "shell-bundle", "update-controller"}
	sort.Strings(roles)
	seen := map[string]bool{}
	for _, m := range s.Members {
		idx := sort.SearchStrings(roles, m.Role)
		if idx == len(roles) || roles[idx] != m.Role || seen[m.Role] ||
			!validHash(m.ArtifactSHA256) ||
			!validAddress(m.EntryPDA) || m.ArtifactSize == 0 {
			return ErrMember
		}
		if completed && (!validHash(m.EntryRawSHA256) || !validHash(m.EntryProfileDigest) || m.EntryStatus != "Active") {
			return ErrMember
		}
		seen[m.Role] = true
		master, masterErr := primitives.PubkeyFromBase58(s.MasterMint)
		program, programErr := primitives.PubkeyFromBase58(s.RegistryProgram)
		artifact, artifactErr := hex.DecodeString(m.ArtifactSHA256)
		if masterErr != nil || programErr != nil || artifactErr != nil || len(artifact) != 32 {
			return ErrMember
		}
		pda, _, pdaErr := primitives.DeriveInstallerRelease(master, *(*[32]byte)(artifact), program)
		if pdaErr != nil || m.EntryPDA != pda.Base58() {
			return ErrMember
		}
	}
	if s.InstallerSHA256 != memberHash(s.Members, "installer") ||
		s.ShellSHA256 != memberHash(s.Members, "shell-bundle") {
		return ErrMember
	}
	return nil
}

func memberHash(members []Member, role string) string {
	for _, m := range members {
		if m.Role == role {
			return m.ArtifactSHA256
		}
	}
	return ""
}

// Digest is the common owner and council message: ASCII lowercase SHA-256 of
// a domain-separated, ordered JSON statement. Signatures are excluded.
func Digest(s Statement) (string, error) {
	if err := validateStatement(s, true); err != nil {
		return "", err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// IntentDigest is what the publisher-signed F0 references. It omits only the
// entry readbacks that cannot exist until after F0/F1 and registration. The
// later owner/council signatures cover the completed Digest, including those
// raw account hashes. This breaks the signing cycle without leaving an
// unsigned choice of artifact, entry PDA, profile or operator.
func IntentDigest(s Statement) (string, error) {
	if err := validateStatement(s, false); err != nil {
		return "", err
	}
	projection := s
	projection.Members = append([]Member(nil), s.Members...)
	for index := range projection.Members {
		projection.Members[index].EntryRawSHA256 = ""
		projection.Members[index].EntryProfileDigest = ""
		projection.Members[index].EntryStatus = ""
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte("MELUSINA_RECOVERY_INSTALLER_PROFILE_BRIDGE_INTENT_V1\n"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func Decode(raw []byte) (Signed, error) {
	var value Signed
	if len(raw) == 0 || len(raw) > 256<<10 {
		return value, ErrMalformed
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&value); err != nil {
		return Signed{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return Signed{}, ErrMalformed
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return Signed{}, ErrMalformed
	}
	if _, err := Digest(value.Statement); err != nil {
		return Signed{}, err
	}
	return value, nil
}

// DecodeIntent reads the unsigned bridge projection before the F0 publishers
// sign its digest. Entry raw hashes/status/profile fields must be empty at
// this phase; the completed signed bridge is decoded with Decode instead.
func DecodeIntent(raw []byte) (Statement, error) {
	var value Statement
	if len(raw) == 0 || len(raw) > 64<<10 {
		return value, ErrMalformed
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&value); err != nil {
		return Statement{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return Statement{}, ErrMalformed
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return Statement{}, ErrMalformed
	}
	for _, member := range value.Members {
		if member.EntryRawSHA256 != "" || member.EntryProfileDigest != "" || member.EntryStatus != "" {
			return Statement{}, ErrScope
		}
	}
	if _, err := IntentDigest(value); err != nil {
		return Statement{}, err
	}
	return value, nil
}

// VerifyIntent is the pre-registration gate. The admission and intended F1
// members are caller-verified inputs; this gate proves that the F0 reference
// can only describe the same signed estate profile lineage and artifacts.
// It neither substitutes for the five bridge signatures nor admits an entry.
func VerifyIntent(s Statement, oldRaw, successorRaw []byte, observed Observation) (string, error) {
	intent, err := IntentDigest(s)
	if err != nil {
		return "", err
	}
	if observed.FoundationBridgeIntentSHA256 != "" && intent != observed.FoundationBridgeIntentSHA256 {
		return "", ErrAdmission
	}
	if s.AdmissionSHA256 != observed.AdmissionSHA256 || s.AdmissionNonce != observed.AdmissionNonce ||
		s.OldProfileRawSHA256 != observed.AdmissionOldProfileRawSHA256 ||
		s.OldProfileDigest != observed.AdmissionOldProfileDigest ||
		s.NewOperator != observed.AdmissionNewOperator ||
		s.RotationApprovalSHA256 != observed.AdmissionRotationApprovalSHA256 ||
		s.InstallerSHA256 != observed.AdmissionInstallerSHA256 ||
		s.ShellSHA256 != observed.AdmissionShellSHA256 ||
		s.StoreArchiveSHA256 != observed.AdmissionStoreArchiveSHA256 ||
		s.StoreBinarySHA256 != observed.AdmissionStoreBinarySHA256 ||
		(observed.AdmissionDeployerCommit != "" && s.DeployerCommit != observed.AdmissionDeployerCommit) ||
		(observed.AdmissionStoreCommit != "" && s.StoreCommit != observed.AdmissionStoreCommit) ||
		s.FoundationSequence != observed.FoundationSequence ||
		(observed.DeployableSequence != 0 && s.DeployableSequence != observed.DeployableSequence) {
		return "", ErrAdmission
	}
	if observed.TrustRawSHA256 != "" && s.LiveTrustRawSHA256 != observed.TrustRawSHA256 {
		return "", ErrChainDrift
	}
	oldHash, newHash := sha256.Sum256(oldRaw), sha256.Sum256(successorRaw)
	if s.OldProfileRawSHA256 != hex.EncodeToString(oldHash[:]) ||
		s.SuccessorProfileRawSHA256 != hex.EncodeToString(newHash[:]) {
		return "", ErrProfile
	}
	old, err := estateprofile.DecodeProfile(oldRaw)
	if err != nil {
		return "", fmt.Errorf("%w: old decode: %v", ErrProfile, err)
	}
	newProfile, err := estateprofile.DecodeProfile(successorRaw)
	if err != nil {
		return "", fmt.Errorf("%w: successor decode: %v", ErrProfile, err)
	}
	oldDigest, err := estateprofile.VerifyProfile(old)
	if err != nil {
		return "", fmt.Errorf("%w: old signature: %v", ErrProfile, err)
	}
	newDigest, err := estateprofile.VerifyProfile(newProfile)
	if err != nil {
		return "", fmt.Errorf("%w: successor signature: %v", ErrProfile, err)
	}
	if oldDigest != s.OldProfileDigest || newDigest != s.SuccessorProfileDigest ||
		old.EstateID != s.EstateID || newProfile.EstateID != s.EstateID ||
		old.Network.GenesisHash != s.Genesis || newProfile.Network.GenesisHash != s.Genesis ||
		old.Anchors.MasterMint != s.MasterMint || newProfile.Anchors.MasterMint != s.MasterMint ||
		old.Revision != 1 || newProfile.Revision != 2 || newProfile.Prev.Revision != 1 ||
		newProfile.Prev.SHA256 != oldDigest || old.Store.OperatorKey == newProfile.Store.OperatorKey ||
		newProfile.Store.OperatorKey != s.NewOperator ||
		!reflect.DeepEqual(old.OwnerPolicy, newProfile.OwnerPolicy) ||
		!reflect.DeepEqual(old.GenesisOwnerPolicy, newProfile.GenesisOwnerPolicy) ||
		!reflect.DeepEqual(old.ReleaseTrust, newProfile.ReleaseTrust) ||
		!reflect.DeepEqual(old.Anchors, newProfile.Anchors) ||
		!reflect.DeepEqual(old.Programs, newProfile.Programs) ||
		!reflect.DeepEqual(old.Roles, newProfile.Roles) {
		return "", ErrProfile
	}
	oldStore, newStore := old.Store, newProfile.Store
	oldStore.OperatorKey, newStore.OperatorKey = "", ""
	if !reflect.DeepEqual(oldStore, newStore) {
		return "", ErrProfile
	}
	program, coreMultisig, coreVault := "", "", ""
	for _, p := range old.Programs {
		if p.Role == estateprofile.ProgramRoleLicenseRegistry {
			program = p.ProgramID
		}
	}
	for _, r := range old.Roles {
		if r.Role == estateprofile.AuthorityRoleCore {
			coreMultisig, coreVault = r.Multisig, r.Vault
		}
	}
	if program != s.RegistryProgram || coreMultisig != s.CoreMultisig || coreVault != s.CoreVault {
		return "", ErrProfile
	}
	if len(observed.Members) != 0 {
		if len(observed.Members) != len(s.Members) {
			return "", ErrMember
		}
		for index, member := range s.Members {
			got := observed.Members[index]
			if member.Role != got.Role || member.ArtifactSHA256 != got.ArtifactSHA256 ||
				member.ArtifactSize != got.ArtifactSize || member.EntryPDA != got.EntryPDA {
				return "", ErrMember
			}
		}
	}
	return intent, nil
}

// Verify accepts only a signed revision-one to revision-two transition of the
// same estate and the exact observed three Active entry records. Observation
// must come from a fresh slot-pinned read, never from the signed document.
func Verify(b Signed, oldRaw, successorRaw []byte, observed Observation) (string, error) {
	digest, err := Digest(b.Statement)
	if err != nil {
		return "", err
	}
	if _, err := VerifyIntent(b.Statement, oldRaw, successorRaw, observed); err != nil {
		return "", err
	}
	s := b.Statement
	intent, err := IntentDigest(s)
	if err != nil {
		return "", err
	}
	if intent != observed.FoundationBridgeIntentSHA256 {
		return "", ErrAdmission
	}
	if s.AdmissionSHA256 != observed.AdmissionSHA256 || s.AdmissionNonce != observed.AdmissionNonce ||
		s.OldProfileRawSHA256 != observed.AdmissionOldProfileRawSHA256 ||
		s.OldProfileDigest != observed.AdmissionOldProfileDigest ||
		s.NewOperator != observed.AdmissionNewOperator ||
		s.RotationApprovalSHA256 != observed.AdmissionRotationApprovalSHA256 ||
		s.InstallerSHA256 != observed.AdmissionInstallerSHA256 ||
		s.ShellSHA256 != observed.AdmissionShellSHA256 ||
		s.StoreArchiveSHA256 != observed.AdmissionStoreArchiveSHA256 ||
		s.StoreBinarySHA256 != observed.AdmissionStoreBinarySHA256 ||
		s.FoundationSequence != observed.FoundationSequence || s.DeployableSequence != observed.DeployableSequence {
		return "", ErrAdmission
	}
	oldHash := sha256.Sum256(oldRaw)
	newHash := sha256.Sum256(successorRaw)
	if s.OldProfileRawSHA256 != hex.EncodeToString(oldHash[:]) ||
		s.SuccessorProfileRawSHA256 != hex.EncodeToString(newHash[:]) {
		return "", ErrProfile
	}
	old, err := estateprofile.DecodeProfile(oldRaw)
	if err != nil {
		return "", fmt.Errorf("%w: old decode: %v", ErrProfile, err)
	}
	newProfile, err := estateprofile.DecodeProfile(successorRaw)
	if err != nil {
		return "", fmt.Errorf("%w: successor decode: %v", ErrProfile, err)
	}
	oldDigest, err := estateprofile.VerifyProfile(old)
	if err != nil {
		return "", fmt.Errorf("%w: old signature: %v", ErrProfile, err)
	}
	newDigest, err := estateprofile.VerifyProfile(newProfile)
	if err != nil {
		return "", fmt.Errorf("%w: successor signature: %v", ErrProfile, err)
	}
	if oldDigest != s.OldProfileDigest || newDigest != s.SuccessorProfileDigest ||
		old.EstateID != s.EstateID || newProfile.EstateID != s.EstateID ||
		old.Network.GenesisHash != s.Genesis || newProfile.Network.GenesisHash != s.Genesis ||
		old.Anchors.MasterMint != s.MasterMint || newProfile.Anchors.MasterMint != s.MasterMint ||
		old.Revision != 1 || newProfile.Revision != 2 || newProfile.Prev.Revision != old.Revision ||
		newProfile.Prev.SHA256 != oldDigest || old.Store.OperatorKey == newProfile.Store.OperatorKey ||
		newProfile.Store.OperatorKey != s.NewOperator ||
		!reflect.DeepEqual(old.OwnerPolicy, newProfile.OwnerPolicy) ||
		!reflect.DeepEqual(old.GenesisOwnerPolicy, newProfile.GenesisOwnerPolicy) ||
		!reflect.DeepEqual(old.ReleaseTrust, newProfile.ReleaseTrust) ||
		!reflect.DeepEqual(old.Anchors, newProfile.Anchors) ||
		!reflect.DeepEqual(old.Programs, newProfile.Programs) ||
		!reflect.DeepEqual(old.Roles, newProfile.Roles) {
		return "", ErrProfile
	}
	oldStore, newStore := old.Store, newProfile.Store
	oldStore.OperatorKey, newStore.OperatorKey = "", ""
	if !reflect.DeepEqual(oldStore, newStore) {
		return "", ErrProfile
	}
	program := ""
	for _, p := range old.Programs {
		if p.Role == estateprofile.ProgramRoleLicenseRegistry {
			program = p.ProgramID
		}
	}
	coreMultisig, coreVault := "", ""
	for _, r := range old.Roles {
		if r.Role == estateprofile.AuthorityRoleCore {
			coreMultisig, coreVault = r.Multisig, r.Vault
		}
	}
	if program != s.RegistryProgram || coreMultisig != s.CoreMultisig || coreVault != s.CoreVault {
		return "", ErrProfile
	}
	if s.LiveTrustRawSHA256 != observed.TrustRawSHA256 ||
		observed.TrustProfileDigest != oldDigest ||
		observed.TrustThreshold != old.ReleaseTrust.Threshold ||
		!reflect.DeepEqual(observed.TrustPublisherKeys, old.ReleaseTrust.PublisherKeys) ||
		!reflect.DeepEqual(s.Members, observed.Members) {
		return "", ErrChainDrift
	}
	for _, member := range s.Members {
		if member.EntryProfileDigest != oldDigest {
			return "", ErrChainDrift
		}
	}
	if len(b.OwnerSignatures) != int(old.OwnerPolicy.Threshold) ||
		estateprofile.VerifyOwnerThreshold(old.OwnerPolicy, digest, b.OwnerSignatures) != nil {
		return "", ErrSignature
	}
	if observed.CoreThreshold != 3 || len(b.CouncilSignatures) != 3 || len(observed.CoreMembers) < 3 {
		return "", ErrSignature
	}
	allowed, seen := map[string]bool{}, map[string]bool{}
	for _, key := range observed.CoreMembers {
		allowed[key] = true
	}
	for _, sig := range b.CouncilSignatures {
		if !allowed[sig.Member] || seen[sig.Member] {
			return "", ErrSignature
		}
		key, keyErr := primitives.PubkeyFromBase58(sig.Member)
		raw, sigErr := base64.RawURLEncoding.DecodeString(sig.Signature)
		if keyErr != nil || sigErr != nil || len(raw) != ed25519.SignatureSize ||
			!ed25519.Verify(ed25519.PublicKey(key[:]), []byte(digest), raw) {
			return "", ErrSignature
		}
		seen[sig.Member] = true
	}
	return digest, nil
}
