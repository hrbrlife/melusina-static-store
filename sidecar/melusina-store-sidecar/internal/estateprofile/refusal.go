package estateprofile

import "errors"

// Refusal names. Error() is exactly the name, or the name, a colon and the
// subject. The JavaScript twin and every consumer match on these strings, so
// they are a wire contract: a guard fails closed BY NAME, and absent, failed
// and unknown are different names.
const (
	// Transport.
	RefusalJSONEmpty         = "estate-json-empty"
	RefusalJSONTooLarge      = "estate-json-too-large"
	RefusalJSONMalformed     = "estate-json-malformed"
	RefusalJSONTooDeep       = "estate-json-too-deep"
	RefusalJSONTrailingData  = "estate-json-trailing-data"
	RefusalJSONDuplicateKey  = "estate-json-duplicate-key"
	RefusalJSONUnknownField  = "estate-json-unknown-field"
	RefusalJSONMissingField  = "estate-json-missing-field"
	RefusalJSONNull          = "estate-json-null"
	RefusalJSONWrongType     = "estate-json-wrong-type"
	RefusalJSONUnsafeInteger = "estate-json-unsafe-integer"

	// Document shape.
	RefusalSchemaUnsupported  = "estate-profile-schema-unsupported"
	RefusalDraftNotEnrollable = "estate-profile-draft-not-enrollable"
	RefusalFieldMalformed     = "estate-profile-field-malformed"
	RefusalArrayNotSorted     = "estate-profile-array-not-sorted"
	RefusalArrayDuplicate     = "estate-profile-array-duplicate"
	RefusalIncomplete         = "estate-profile-incomplete"
	RefusalMainnetGenesis     = "estate-mainnet-genesis-refused"
	// A program's stated upgrade authority disagrees with how its role is
	// deployed: a final role (the witness verifier) not stated final or
	// stated with an authority, or a governed role stated final. The names
	// mirror the chain-foundation executor's program-must-be-final and
	// program-must-be-governed.
	RefusalProgramMustBeFinal    = "estate-profile-program-must-be-final"
	RefusalProgramMustBeGoverned = "estate-profile-program-must-be-governed"

	// Identity and authority.
	RefusalIDNotSelfCertifying    = "estate-profile-id-not-self-certifying"
	RefusalSuccessorUnauthorized  = "estate-profile-successor-unauthorized"
	RefusalSignaturesInsufficient = "estate-profile-owner-signatures-insufficient"
	RefusalSignatureInvalid       = "estate-profile-owner-signature-invalid"
	RefusalDigestMismatch         = "estate-profile-digest-mismatch"

	// Fresh-foundation authorization. This is a distinct, pre-profile
	// contract signed by the self-certifying genesis owner policy.
	RefusalFoundationAuthorizationSchemaUnsupported       = "estate-foundation-authorization-schema-unsupported"
	RefusalFoundationAuthorizationFieldMalformed          = "estate-foundation-authorization-field-malformed"
	RefusalFoundationAuthorizationTimeInvalid             = "estate-foundation-authorization-time-invalid"
	RefusalFoundationAuthorizationNotYetValid             = "estate-foundation-authorization-not-yet-valid"
	RefusalFoundationAuthorizationExpired                 = "estate-foundation-authorization-expired"
	RefusalFoundationAuthorizationIDNotSelfCertifying     = "estate-foundation-authorization-id-not-self-certifying"
	RefusalFoundationAuthorizationSignaturesInsufficient  = "estate-foundation-authorization-owner-signatures-insufficient"
	RefusalFoundationAuthorizationSignatureInvalid        = "estate-foundation-authorization-owner-signature-invalid"
	RefusalFoundationAuthorizationCeremonySchemaMismatch  = "estate-foundation-authorization-ceremony-schema-mismatch"
	RefusalFoundationAuthorizationCeremonyProfileMismatch = "estate-foundation-authorization-ceremony-profile-mismatch"
	RefusalFoundationAuthorizationReleaseSetMismatch      = "estate-foundation-authorization-release-set-mismatch"
	RefusalFoundationAuthorizationTargetBindingMismatch   = "estate-foundation-authorization-target-binding-mismatch"
	RefusalFoundationAuthorizationGenesisMismatch         = "estate-foundation-authorization-genesis-mismatch"

	// Root-Store enrollment. This is a separate, post-foundation contract: a
	// final EstateProfileV1 names the public estate, while this document binds
	// the Store's root-only facts that exist only after foundation read-back.
	RefusalStoreEnrollmentSchemaUnsupported      = "store-enrollment-schema-unsupported"
	RefusalStoreEnrollmentFieldMalformed         = "store-enrollment-field-malformed"
	RefusalStoreEnrollmentTimeInvalid            = "store-enrollment-time-invalid"
	RefusalStoreEnrollmentNotYetValid            = "store-enrollment-not-yet-valid"
	RefusalStoreEnrollmentExpired                = "store-enrollment-expired"
	RefusalStoreEnrollmentProfileMismatch        = "store-enrollment-profile-mismatch"
	RefusalStoreEnrollmentSignaturesInsufficient = "store-enrollment-owner-signatures-insufficient"
	RefusalStoreEnrollmentSignatureInvalid       = "store-enrollment-owner-signature-invalid"
	RefusalStoreEnrollmentFactsMismatch          = "store-enrollment-facts-mismatch"
	RefusalStoreRPCGenesisMismatch               = "store-rpc-genesis-mismatch"

	// Provider install. The estate owners' threshold authorizes creating one
	// provider host's substrate: one host, one Spec, one suite, one profile.
	RefusalProviderInstallAuthorizationSchemaUnsupported      = "estate-provider-install-authorization-schema-unsupported"
	RefusalProviderInstallAuthorizationFieldMalformed         = "estate-provider-install-authorization-field-malformed"
	RefusalProviderInstallAuthorizationTimeInvalid            = "estate-provider-install-authorization-time-invalid"
	RefusalProviderInstallAuthorizationNotYetValid            = "estate-provider-install-authorization-not-yet-valid"
	RefusalProviderInstallAuthorizationExpired                = "estate-provider-install-authorization-expired"
	RefusalProviderInstallAuthorizationProfileMismatch        = "estate-provider-install-authorization-profile-mismatch"
	RefusalProviderInstallAuthorizationSignaturesInsufficient = "estate-provider-install-authorization-owner-signatures-insufficient"
	RefusalProviderInstallAuthorizationSignatureInvalid       = "estate-provider-install-authorization-owner-signature-invalid"

	// Select, migrate and recall.
	RefusalNotEnrolled            = "estate-profile-not-enrolled"
	RefusalSelectionRequiresEmpty = "estate-selection-requires-empty-consumer"
	RefusalNotForward             = "estate-profile-not-forward"
	RefusalNetworkImmutable       = "estate-profile-network-immutable"
	RefusalRecalled               = "estate-profile-recalled"
	RefusalPinnedInvalid          = "estate-profile-pinned-invalid"
	RefusalConsumerStateUnknown   = "estate-consumer-state-unknown"

	// Projection.
	RefusalGenesisMismatch            = "estate-genesis-mismatch"
	RefusalAnchorMismatch             = "estate-profile-anchor-mismatch"
	RefusalProjectionFieldUnknown     = "estate-projection-field-unknown"
	RefusalAuthorityThresholdMismatch = "estate-authority-threshold-mismatch"
	RefusalAuthorityAccountMalformed  = "estate-authority-account-malformed"
	RefusalProgramExecutable          = "program-executable-not-profile"

	// Network access.
	RefusalNetworkAccessForeignEstate = "estate-network-access-foreign-estate"
	RefusalNetworkAccessNotForward    = "estate-network-access-not-forward"
	RefusalNetworkAccessRecalled      = "estate-network-access-recalled"
	RefusalOriginNotListed            = "estate-origin-not-listed"
	RefusalOriginSPKIMismatch         = "estate-origin-spki-mismatch"
)

// Refusal is the only error type this package returns.
type Refusal struct {
	Name    string
	Subject string
}

func (refusal *Refusal) Error() string {
	if refusal.Subject == "" {
		return refusal.Name
	}
	return refusal.Name + ":" + refusal.Subject
}

func refuse(name string) error { return &Refusal{Name: name} }

func refuseSubject(name, subject string) error {
	return &Refusal{Name: name, Subject: subject}
}

// RefusalName returns the bare refusal name of err, or "" when err is nil or
// did not come from this package. A consumer that receives "" for a non-nil
// error must treat it as unknown and stop.
func RefusalName(err error) string {
	var refusal *Refusal
	if errors.As(err, &refusal) {
		return refusal.Name
	}
	return ""
}
