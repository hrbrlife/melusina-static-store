// Package storerecovery holds the Store's two backup subjects (item M25 of the
// off-box backup, restore and recovery kit spec):
//
//   - Store data: store-state-tar-v1, one deterministic, operator-signed tar
//     stream of every durable Store root, carried by the deployer's RemoteBak
//     runner as ciphertext in a namespace of subject kind store-state;
//   - Store identity: the three attest shards the Store operator is derived
//     from, escrowed shard-wise so that no single holder can rebuild the
//     operator key, and restored on a replacement host through a one-time
//     session key.
//
// The package reads no configuration, opens no network connection and names
// no escrow holder, backup store or custody location: every destination is an
// explicit input (owner decision D-2 is open). It imports no Store runtime
// code; the sidecar binds these primitives to its configuration and to its
// catalog verification.
package storerecovery

import "errors"

// Refusal names. Error() is exactly the name, or the name, a colon and the
// subject. Consumers match on the name, so these strings are a contract: a
// guard fails closed by name.
const (
	// store-state-tar-v1 export.
	RefusalStateRootInvalid       = "store-state-root-invalid"
	RefusalStateRootsOverlap      = "store-state-roots-overlap"
	RefusalStateRootMissing       = "store-state-root-missing"
	RefusalStateMemberUnsupported = "store-state-member-unsupported"
	RefusalStateMemberPathUnsafe  = "store-state-member-path-unsafe"
	RefusalStateTooLarge          = "store-state-too-large"
	RefusalStateMemberChanged     = "store-state-member-changed-during-export"
	RefusalStateHeaderInvalid     = "store-state-header-invalid"

	// store-state-tar-v1 verification and import.
	RefusalStateStreamMalformed      = "store-state-stream-malformed"
	RefusalStateManifestMalformed    = "store-state-manifest-malformed"
	RefusalStateManifestSignature    = "store-state-manifest-signature-invalid"
	RefusalStateOperatorMismatch     = "store-state-operator-mismatch"
	RefusalStateStoreMismatch        = "store-state-store-mismatch"
	RefusalStateRootSetMismatch      = "store-state-root-set-mismatch"
	RefusalStateTargetNotEmpty       = "store-state-target-not-empty"
	RefusalStateMemberMissing        = "store-state-member-missing"
	RefusalStateMemberUnexpected     = "store-state-member-unexpected"
	RefusalStateMemberHeaderMismatch = "store-state-member-header-mismatch"
	RefusalStateMemberDigestMismatch = "store-state-member-digest-mismatch"
	RefusalStateCommitFailed         = "store-state-commit-failed"

	// RemoteBak namespace naming.
	RefusalStateNamespaceInvalid = "store-state-namespace-invalid"

	// Store identity shard escrow.
	RefusalIdentityRecipients           = "store-identity-escrow-recipients-invalid"
	RefusalIdentityHolderOverlap        = "store-identity-escrow-holder-overlap"
	RefusalIdentityRefInvalid           = "store-identity-escrow-ref-invalid"
	RefusalIdentityOperatorMismatch     = "store-identity-escrow-operator-mismatch"
	RefusalIdentityManifestMalformed    = "store-identity-escrow-manifest-malformed"
	RefusalIdentityManifestSignature    = "store-identity-escrow-manifest-signature-invalid"
	RefusalIdentityDocumentMalformed    = "store-identity-escrow-document-malformed"
	RefusalIdentityDocumentMismatch     = "store-identity-escrow-document-mismatch"
	RefusalIdentityNoEnvelope           = "store-identity-escrow-no-envelope"
	RefusalIdentityEnvelopeInvalid      = "store-identity-escrow-envelope-invalid"
	RefusalIdentityCommitmentMismatch   = "store-identity-shard-commitment-mismatch"
	RefusalIdentityHandoffMalformed     = "store-identity-handoff-malformed"
	RefusalIdentityHandoffMismatch      = "store-identity-handoff-mismatch"
	RefusalIdentityHandoffWrongSession  = "store-identity-handoff-wrong-session"
	RefusalIdentityHandoffRoleDuplicate = "store-identity-handoff-duplicate-role"
	RefusalIdentityHandoffRoleMissing   = "store-identity-handoff-missing-role"
	RefusalIdentityDerivationMismatch   = "store-identity-restore-derivation-mismatch"
	RefusalIdentityTargetNotEmpty       = "store-identity-restore-target-not-empty"
	RefusalIdentityKeyFileInvalid       = "store-identity-key-file-invalid"
)

// Refusal is the error type every exported function of this package returns
// for a decision. Operating-system errors that are not decisions are wrapped
// in a Refusal naming the step, so a caller never has to guess.
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

// Refuse returns a Refusal. The sidecar uses it for the refusals it adds on
// top of these primitives, so every store-state refusal has one shape.
func Refuse(name, subject string) error { return &Refusal{Name: name, Subject: subject} }

// RefusalName returns the bare refusal name of err, or "" when err is nil or
// is not a Refusal. A consumer that receives "" for a non-nil error must treat
// it as unknown and stop.
func RefusalName(err error) string {
	var refusal *Refusal
	if errors.As(err, &refusal) {
		return refusal.Name
	}
	return ""
}
