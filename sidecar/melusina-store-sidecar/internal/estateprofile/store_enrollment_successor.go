package estateprofile

import "time"

// StoreEnrollmentSuccessorV1 is the day-two companion of StoreEnrollmentV1.
// An enrolled root Store re-derives its executable hash, TLS leaf and
// SidecarIdentityEntry binding on every start and refuses any value its
// enrollment did not bind. A rebuilt executable, a renewed certificate or a
// rotated binding therefore needs a new owner authorization, and this document
// is the only one: a Store never accepts a changed bound value because it
// observed it.
//
// The current profile owners sign it through the same review, owner-sign and
// assemble ceremony as the initial enrollment. Its digest domain is distinct,
// so a signature over one document can never stand for the other.
//
// Acceptance is signature validity, strict forward monotonicity and explicit
// recall, never continuity:
//
//   - enrollmentSequence must be strictly greater than the sequence the Store
//     holds (the initial enrollment is StoreEnrollmentInitialSequence), so a
//     replayed older or equal document refuses by name;
//   - recalls names, with a reason, every enrollment digest the owners revoke.
//     It must include predecessorEnrollmentSha256, so the supersession of the
//     prior enrollment is itself signed, and a Store refuses any enrollment
//     that a successor it accepted has recalled;
//   - predecessorEnrollmentSha256 is the enrollment the Store held when it
//     emitted the request. It is signed and reviewed but never compared with
//     what a Store holds at acceptance: a missing intermediate record is not a
//     defect, only a signed recall is;
//   - initialEnrollmentSha256 anchors the document to one Store's initial
//     enrollment, as estateId anchors a profile, so a successor issued for one
//     enrolled Store cannot advance another.
//
// A successor never changes the Store's identity. The estate, profile,
// network, root domain, Store ID, operator and box keys, licence, registry,
// sidecar id, operator key version and operator domain must equal the initial
// enrollment's; a change to any of them is a new profile or a new estate. What
// it may change is the binding: bindingKeyVersion (never backwards), the
// SidecarIdentityEntry that version selects, tlsCertFingerprint and
// binarySha256. A successor that changes none of them is refused.
const (
	StoreEnrollmentSuccessorSchema  = "melusina.estate.store-enrollment-successor.v1"
	StoreEnrollmentSuccessorKind    = "estate-store-enrollment-successor"
	StoreEnrollmentSuccessorPurpose = "root-store-enrollment-successor"

	// StoreEnrollmentInitialSequence is the sequence of a Store's initial
	// StoreEnrollmentV1. Every successor carries a strictly greater one.
	StoreEnrollmentInitialSequence = uint64(1)

	MaxStoreEnrollmentSuccessorRecalls = 16

	storeEnrollmentSuccessorDigestDomain = "MELUSINA_ESTATE_STORE_ENROLLMENT_SUCCESSOR_V1\n"
)

// Successor refusal names. Transport, time, profile, owner-signature, facts
// and genesis refusals reuse the StoreEnrollment names, so an owner-side tool
// treats an unsigned successor exactly as it treats an unsigned enrollment.
const (
	RefusalStoreEnrollmentSuccessorSchemaUnsupported      = "store-enrollment-successor-schema-unsupported"
	RefusalStoreEnrollmentSuccessorFieldMalformed         = "store-enrollment-successor-field-malformed"
	RefusalStoreEnrollmentSuccessorPredecessorNotRecalled = "store-enrollment-successor-predecessor-not-recalled"
	RefusalStoreEnrollmentSuccessorAnchorMismatch         = "store-enrollment-successor-anchor-mismatch"
	RefusalStoreEnrollmentSuccessorIdentityChanged        = "store-enrollment-successor-identity-changed"
	RefusalStoreEnrollmentSuccessorNotForward             = "store-enrollment-successor-not-forward"
	RefusalStoreEnrollmentSuccessorBindingNotForward      = "store-enrollment-successor-binding-not-forward"
	RefusalStoreEnrollmentSuccessorUnchanged              = "store-enrollment-successor-unchanged"
	RefusalStoreEnrollmentRecalled                        = "store-enrollment-recalled"
)

// StoreEnrollmentSuccessorV1 carries every StoreEnrollmentV1 fact, so review
// and the Store's local comparison need no other document, plus its place in
// the Store's enrollment sequence. Field order is preimage order.
type StoreEnrollmentSuccessorV1 struct {
	Schema                      string        `json:"schema"`
	Kind                        string        `json:"kind"`
	Purpose                     string        `json:"purpose"`
	EstateID                    string        `json:"estateId"`
	ProfileSHA256               string        `json:"profileSha256"`
	ProfileRevision             uint64        `json:"profileRevision"`
	NetworkGenesisHash          string        `json:"networkGenesisHash"`
	InitialEnrollmentSHA256     string        `json:"initialEnrollmentSha256"`
	EnrollmentSequence          uint64        `json:"enrollmentSequence"`
	PredecessorEnrollmentSHA256 string        `json:"predecessorEnrollmentSha256"`
	Recalls                     []RecallV1    `json:"recalls"`
	RootDomain                  string        `json:"rootDomain"`
	RootDomainSHA256            string        `json:"rootDomainSha256"`
	StoreID                     string        `json:"storeId"`
	StoreOperatorKey            string        `json:"storeOperatorKey"`
	StoreBoxKey                 string        `json:"storeBoxKey"`
	LicenseNFTMint              string        `json:"licenseNftMint"`
	LicenseRegistryID           string        `json:"licenseRegistryProgramId"`
	SidecarID                   string        `json:"sidecarId"`
	BindingKeyVersion           uint32        `json:"bindingKeyVersion"`
	OperatorKeyVersion          uint32        `json:"operatorKeyVersion"`
	OperatorDomain              string        `json:"operatorDomain"`
	SidecarIdentityPDA          string        `json:"sidecarIdentityPda"`
	TLSCertFingerprint          string        `json:"tlsCertFingerprint"`
	BinarySHA256                string        `json:"binarySha256"`
	IssuedAt                    string        `json:"issuedAt"`
	ExpiresAt                   string        `json:"expiresAt"`
	EnrollmentNonce             string        `json:"enrollmentNonce"`
	Signatures                  []SignatureV1 `json:"signatures"`
}

// StoreEnrollmentHeld is what an enrolled Store holds when a successor
// arrives: its verified initial enrollment, the successor it currently runs
// under (nil until the first), and every enrollment digest that a successor it
// accepted has recalled. Callers establish owner authority for Initial and
// Current before they build it; RequireStoreEnrollmentSuccessorAdvance checks
// only how a candidate relates to it.
type StoreEnrollmentHeld struct {
	Initial  StoreEnrollmentV1
	Current  *StoreEnrollmentSuccessorV1
	Recalled []string
}

// DecodeStoreEnrollmentSuccessor strictly decodes one complete successor. An
// initial enrollment, a profile or any other document is refused as the wrong
// kind rather than coerced because its fields happen to overlap.
func DecodeStoreEnrollmentSuccessor(raw []byte) (StoreEnrollmentSuccessorV1, error) {
	var value StoreEnrollmentSuccessorV1
	err := decodeStrict(raw, MaxStoreEnrollmentJSONBytes, &value, func(tree any) error {
		schema, kind := peekStrictJSONKind(tree)
		if schema != StoreEnrollmentSuccessorSchema || kind != StoreEnrollmentSuccessorKind {
			return refuse(RefusalStoreEnrollmentSuccessorSchemaUnsupported)
		}
		return nil
	})
	if err != nil {
		return StoreEnrollmentSuccessorV1{}, err
	}
	if err := ValidateStoreEnrollmentSuccessor(value); err != nil {
		return StoreEnrollmentSuccessorV1{}, err
	}
	return value, nil
}

// ValidateStoreEnrollmentSuccessor checks public structure that needs no
// profile, clock, Store state, signature verification or I/O. It accepts an
// unsigned value so owners can compute its digest.
func ValidateStoreEnrollmentSuccessor(value StoreEnrollmentSuccessorV1) error {
	if value.Schema != StoreEnrollmentSuccessorSchema || value.Kind != StoreEnrollmentSuccessorKind || value.Purpose != StoreEnrollmentSuccessorPurpose {
		return refuse(RefusalStoreEnrollmentSuccessorSchemaUnsupported)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"initialEnrollmentSha256", value.InitialEnrollmentSHA256},
		{"predecessorEnrollmentSha256", value.PredecessorEnrollmentSHA256},
	} {
		if !validDigest(field.value) {
			return refuseSubject(RefusalStoreEnrollmentSuccessorFieldMalformed, field.name)
		}
	}
	if value.EnrollmentSequence <= StoreEnrollmentInitialSequence || value.EnrollmentSequence > MaxSafeInteger {
		return refuseSubject(RefusalStoreEnrollmentSuccessorFieldMalformed, "enrollmentSequence")
	}
	if len(value.Recalls) == 0 || len(value.Recalls) > MaxStoreEnrollmentSuccessorRecalls || validateRecalls(value.Recalls, "recalls") != nil {
		return refuseSubject(RefusalStoreEnrollmentSuccessorFieldMalformed, "recalls")
	}
	if !recalled(value.Recalls, value.PredecessorEnrollmentSHA256) {
		return refuse(RefusalStoreEnrollmentSuccessorPredecessorNotRecalled)
	}
	// Every fact a successor shares with an initial enrollment obeys exactly
	// the initial enrollment's rules.
	return ValidateStoreEnrollment(value.bindingView())
}

// bindingView is the successor's facts in StoreEnrollmentV1 form, used only
// to apply the initial enrollment's field rules and comparisons. It is never
// a document: its digest is not the successor's and its signatures never
// verify as a StoreEnrollmentV1.
func (value StoreEnrollmentSuccessorV1) bindingView() StoreEnrollmentV1 {
	return StoreEnrollmentV1{
		Schema:             StoreEnrollmentSchema,
		Kind:               StoreEnrollmentKind,
		Purpose:            StoreEnrollmentPurpose,
		EstateID:           value.EstateID,
		ProfileSHA256:      value.ProfileSHA256,
		ProfileRevision:    value.ProfileRevision,
		NetworkGenesisHash: value.NetworkGenesisHash,
		RootDomain:         value.RootDomain,
		RootDomainSHA256:   value.RootDomainSHA256,
		StoreID:            value.StoreID,
		StoreOperatorKey:   value.StoreOperatorKey,
		StoreBoxKey:        value.StoreBoxKey,
		LicenseNFTMint:     value.LicenseNFTMint,
		LicenseRegistryID:  value.LicenseRegistryID,
		SidecarID:          value.SidecarID,
		BindingKeyVersion:  value.BindingKeyVersion,
		OperatorKeyVersion: value.OperatorKeyVersion,
		OperatorDomain:     value.OperatorDomain,
		SidecarIdentityPDA: value.SidecarIdentityPDA,
		TLSCertFingerprint: value.TLSCertFingerprint,
		BinarySHA256:       value.BinarySHA256,
		IssuedAt:           value.IssuedAt,
		ExpiresAt:          value.ExpiresAt,
		EnrollmentNonce:    value.EnrollmentNonce,
		Signatures:         value.Signatures,
	}
}

// StoreEnrollmentSuccessorPreimage returns the canonical owner-signing bytes.
// The signatures are excluded exactly once; every other field is bound.
func StoreEnrollmentSuccessorPreimage(value StoreEnrollmentSuccessorV1) ([]byte, error) {
	if err := ValidateStoreEnrollmentSuccessor(value); err != nil {
		return nil, err
	}
	return storeEnrollmentSuccessorPreimage(value), nil
}

func storeEnrollmentSuccessorPreimage(value StoreEnrollmentSuccessorV1) []byte {
	issuedAt, _ := parseIssuedAt(value.IssuedAt)
	expiresAt, _ := parseIssuedAt(value.ExpiresAt)
	var writer binaryWriter
	writer.bytes([]byte(storeEnrollmentSuccessorDigestDomain))
	writer.string(value.Schema)
	writer.string(value.Kind)
	writer.string(value.Purpose)
	writer.string(value.EstateID)
	writer.string(value.ProfileSHA256)
	writer.uint64(value.ProfileRevision)
	writer.string(value.NetworkGenesisHash)
	writer.string(value.InitialEnrollmentSHA256)
	writer.uint64(value.EnrollmentSequence)
	writer.string(value.PredecessorEnrollmentSHA256)
	writer.uint32(uint32(len(value.Recalls)))
	for _, recall := range value.Recalls {
		writer.string(recall.SHA256)
		writer.string(recall.Reason)
	}
	writer.string(value.RootDomain)
	writer.string(value.RootDomainSHA256)
	writer.string(value.StoreID)
	writer.string(value.StoreOperatorKey)
	writer.string(value.StoreBoxKey)
	writer.string(value.LicenseNFTMint)
	writer.string(value.LicenseRegistryID)
	writer.string(value.SidecarID)
	writer.uint32(value.BindingKeyVersion)
	writer.uint32(value.OperatorKeyVersion)
	writer.string(value.OperatorDomain)
	writer.string(value.SidecarIdentityPDA)
	writer.string(value.TLSCertFingerprint)
	writer.string(value.BinarySHA256)
	writer.time(issuedAt)
	writer.time(expiresAt)
	writer.string(value.EnrollmentNonce)
	return writer.Bytes()
}

// StoreEnrollmentSuccessorSHA256 is the digest the profile owners sign.
func StoreEnrollmentSuccessorSHA256(value StoreEnrollmentSuccessorV1) (string, error) {
	preimage, err := StoreEnrollmentSuccessorPreimage(value)
	if err != nil {
		return "", err
	}
	return sha256Hex(preimage), nil
}

// VerifyStoreEnrollmentSuccessorAuthorization establishes that a threshold of
// the verified profile's current owners signed exactly this successor for this
// profile's root Store. Like VerifyStoreEnrollmentAuthorization it applies no
// clock, so a persisted successor still proves its authority after its short
// signing window; VerifyStoreEnrollmentSuccessor is the live ceremony check.
func VerifyStoreEnrollmentSuccessorAuthorization(profile EstateProfileV1, value StoreEnrollmentSuccessorV1) (string, error) {
	profileDigest, err := VerifyProfile(profile)
	if err != nil {
		return "", err
	}
	if err := ValidateStoreEnrollmentSuccessor(value); err != nil {
		return "", err
	}
	if err := requireStoreEnrollmentProfile(profile, profileDigest, value.bindingView()); err != nil {
		return "", err
	}
	digest := sha256Hex(storeEnrollmentSuccessorPreimage(value))
	if err := verifyThresholdSignatures(profile.OwnerPolicy, digest, value.Signatures); err != nil {
		return "", storeEnrollmentRefusal(err)
	}
	return digest, nil
}

// VerifyStoreEnrollmentSuccessor adds the live signing window to the
// authorization check. It performs no I/O and does not decide whether a given
// Store may advance to the successor; that is
// RequireStoreEnrollmentSuccessorAdvance.
func VerifyStoreEnrollmentSuccessor(profile EstateProfileV1, value StoreEnrollmentSuccessorV1, now time.Time) (string, error) {
	digest, err := VerifyStoreEnrollmentSuccessorAuthorization(profile, value)
	if err != nil {
		return "", err
	}
	if now.IsZero() {
		return "", refuse(RefusalStoreEnrollmentTimeInvalid)
	}
	issuedAt, _ := parseIssuedAt(value.IssuedAt)
	expiresAt, _ := parseIssuedAt(value.ExpiresAt)
	now = now.UTC()
	if now.Before(issuedAt) {
		return "", refuse(RefusalStoreEnrollmentNotYetValid)
	}
	if now.After(expiresAt) {
		return "", refuse(RefusalStoreEnrollmentExpired)
	}
	return digest, nil
}

// RequireStoreEnrollmentSuccessorIdentity proves that value belongs to the
// Store whose initial enrollment is initial and leaves that Store's identity
// unchanged. It is the invariant half of an advance, and the check a Store
// repeats on the successor it persisted.
func RequireStoreEnrollmentSuccessorIdentity(initial StoreEnrollmentV1, value StoreEnrollmentSuccessorV1) error {
	initialDigest, err := StoreEnrollmentSHA256(initial)
	if err != nil {
		return err
	}
	if err := ValidateStoreEnrollmentSuccessor(value); err != nil {
		return err
	}
	if value.InitialEnrollmentSHA256 != initialDigest {
		return refuse(RefusalStoreEnrollmentSuccessorAnchorMismatch)
	}
	for _, field := range []struct {
		name string
		got  string
		want string
	}{
		{"estateId", value.EstateID, initial.EstateID},
		{"profileSha256", value.ProfileSHA256, initial.ProfileSHA256},
		{"networkGenesisHash", value.NetworkGenesisHash, initial.NetworkGenesisHash},
		{"rootDomain", value.RootDomain, initial.RootDomain},
		{"rootDomainSha256", value.RootDomainSHA256, initial.RootDomainSHA256},
		{"storeId", value.StoreID, initial.StoreID},
		{"storeOperatorKey", value.StoreOperatorKey, initial.StoreOperatorKey},
		{"storeBoxKey", value.StoreBoxKey, initial.StoreBoxKey},
		{"licenseNftMint", value.LicenseNFTMint, initial.LicenseNFTMint},
		{"licenseRegistryProgramId", value.LicenseRegistryID, initial.LicenseRegistryID},
		{"sidecarId", value.SidecarID, initial.SidecarID},
		{"operatorDomain", value.OperatorDomain, initial.OperatorDomain},
	} {
		if field.got != field.want {
			return refuseSubject(RefusalStoreEnrollmentSuccessorIdentityChanged, field.name)
		}
	}
	if value.ProfileRevision != initial.ProfileRevision {
		return refuseSubject(RefusalStoreEnrollmentSuccessorIdentityChanged, "profileRevision")
	}
	if value.OperatorKeyVersion != initial.OperatorKeyVersion {
		return refuseSubject(RefusalStoreEnrollmentSuccessorIdentityChanged, "operatorKeyVersion")
	}
	return nil
}

// RequireStoreEnrollmentSuccessorAdvance decides whether candidate may replace
// the binding held: same Store identity, a strictly higher sequence, a binding
// key version that does not go backwards, a digest no accepted successor has
// recalled, and at least one changed bound value. It deliberately does not
// compare candidate.PredecessorEnrollmentSHA256 with the held digest.
func RequireStoreEnrollmentSuccessorAdvance(held StoreEnrollmentHeld, candidate StoreEnrollmentSuccessorV1) error {
	if err := RequireStoreEnrollmentSuccessorIdentity(held.Initial, candidate); err != nil {
		return err
	}
	heldSequence := StoreEnrollmentInitialSequence
	heldBinding := held.Initial
	if held.Current != nil {
		if err := RequireStoreEnrollmentSuccessorIdentity(held.Initial, *held.Current); err != nil {
			return err
		}
		heldSequence = held.Current.EnrollmentSequence
		heldBinding = held.Current.bindingView()
	}
	if candidate.EnrollmentSequence <= heldSequence {
		return refuse(RefusalStoreEnrollmentSuccessorNotForward)
	}
	digest := sha256Hex(storeEnrollmentSuccessorPreimage(candidate))
	for _, recalledDigest := range held.Recalled {
		if recalledDigest == digest {
			return refuseSubject(RefusalStoreEnrollmentRecalled, digest)
		}
	}
	if candidate.BindingKeyVersion < heldBinding.BindingKeyVersion {
		return refuse(RefusalStoreEnrollmentSuccessorBindingNotForward)
	}
	if candidate.BindingKeyVersion == heldBinding.BindingKeyVersion && candidate.SidecarIdentityPDA != heldBinding.SidecarIdentityPDA {
		return refuseSubject(RefusalStoreEnrollmentSuccessorIdentityChanged, "sidecarIdentityPda")
	}
	if candidate.BindingKeyVersion == heldBinding.BindingKeyVersion &&
		candidate.TLSCertFingerprint == heldBinding.TLSCertFingerprint &&
		candidate.BinarySHA256 == heldBinding.BinarySHA256 {
		return refuse(RefusalStoreEnrollmentSuccessorUnchanged)
	}
	return nil
}

// RequireStoreEnrollmentSuccessorFacts is the successor's local comparison,
// with exactly RequireStoreEnrollmentFacts' rules and refusal names.
func RequireStoreEnrollmentSuccessorFacts(value StoreEnrollmentSuccessorV1, facts StoreEnrollmentFacts) error {
	if err := ValidateStoreEnrollmentSuccessor(value); err != nil {
		return err
	}
	return RequireStoreEnrollmentFacts(value.bindingView(), facts)
}
