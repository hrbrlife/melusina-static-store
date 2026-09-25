package estateprofile

import "testing"

// VerifyOwnerThreshold is the owner-threshold check another package's
// document (the recovery kit) is verified with. These tests hold it to the
// same refusals VerifyProfile gives, and to refusing a policy that could not
// be an estate owner policy at all.

func TestVerifyOwnerThresholdAcceptsExactlyTheThreshold(t *testing.T) {
	policy := vectorPolicy("policy.rehearsal.owners.v1", 1, 2, "owner-a", "owner-b", "owner-c")
	digest := vectorDigest("recovery-kit/threshold")
	if err := VerifyOwnerThreshold(policy, digest, signDigest(policy, digest, "owner-a", "owner-c")); err != nil {
		t.Fatalf("two of three owners over the digest must verify: %v", err)
	}
}

func TestVerifyOwnerThresholdRefusesBelowTheThreshold(t *testing.T) {
	policy := vectorPolicy("policy.rehearsal.owners.v1", 1, 2, "owner-a", "owner-b", "owner-c")
	digest := vectorDigest("recovery-kit/threshold")
	err := VerifyOwnerThreshold(policy, digest, signDigest(policy, digest, "owner-b"))
	requireRefusal(t, err, RefusalSignaturesInsufficient)
}

func TestVerifyOwnerThresholdRefusesASignatureOverAnotherDigest(t *testing.T) {
	policy := vectorPolicy("policy.rehearsal.owners.v1", 1, 2, "owner-a", "owner-b", "owner-c")
	digest := vectorDigest("recovery-kit/threshold")
	signatures := signDigest(policy, digest, "owner-a", "owner-b")
	signatures[1] = signDigest(policy, vectorDigest("recovery-kit/other"), "owner-b")[0]
	err := VerifyOwnerThreshold(policy, digest, signatures)
	requireRefusal(t, err, RefusalSignatureInvalid+":owner-b")
}

// TestVerifyOwnerThresholdRefusesAPolicyBelowTheOwnerMinimum is the guard
// that makes the export safe to call with a policy the caller did not take
// from a verified profile: a one-of-two policy is not an owner policy, and
// one genuine signature under it must not pass.
func TestVerifyOwnerThresholdRefusesAPolicyBelowTheOwnerMinimum(t *testing.T) {
	policy := vectorPolicy("policy.rehearsal.owners.v1", 1, 1, "owner-a", "owner-b")
	digest := vectorDigest("recovery-kit/threshold")
	err := VerifyOwnerThreshold(policy, digest, signDigest(policy, digest, "owner-a"))
	requireRefusal(t, err, RefusalFieldMalformed+":ownerPolicy.threshold")
}

func TestVerifyOwnerThresholdRefusesAMalformedDigest(t *testing.T) {
	policy := vectorPolicy("policy.rehearsal.owners.v1", 1, 2, "owner-a", "owner-b", "owner-c")
	digest := "SHA256:" + vectorDigest("recovery-kit/threshold")[7:]
	err := VerifyOwnerThreshold(policy, digest, signDigest(policy, digest, "owner-a", "owner-b"))
	requireRefusal(t, err, RefusalFieldMalformed+":digest")
}
