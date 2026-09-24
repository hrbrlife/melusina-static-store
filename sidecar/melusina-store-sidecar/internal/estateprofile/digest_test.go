package estateprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestProfileDigestIsDeterministic(t *testing.T) {
	profile := newEstateProfile(t)
	first, err := ProfileSHA256(profile)
	if err != nil {
		t.Fatalf("first digest: %v", err)
	}
	second, err := ProfileSHA256(profile)
	if err != nil {
		t.Fatalf("second digest: %v", err)
	}
	if first != second {
		t.Fatalf("the digest of one profile differed between calls: %s then %s", first, second)
	}
	// The same document after a JSON round trip must digest identically, or
	// the twin implementations cannot agree on what they signed.
	decoded, err := DecodeProfile(marshalProfile(t, profile))
	if err != nil {
		t.Fatalf("decode the marshalled profile: %v", err)
	}
	roundTripped, err := ProfileSHA256(decoded)
	if err != nil {
		t.Fatalf("digest the decoded profile: %v", err)
	}
	if roundTripped != first {
		t.Fatalf("the digest changed across a JSON round trip: %s then %s", first, roundTripped)
	}
}

func TestProfileDigestExcludesOnlyTheTopLevelSignatures(t *testing.T) {
	profile := newEstateProfile(t)
	signed, err := ProfileSHA256(profile)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	unsigned := profile
	unsigned.Signatures = nil
	bare, err := ProfileSHA256(unsigned)
	if err != nil {
		t.Fatalf("digest unsigned: %v", err)
	}
	if bare != signed {
		t.Fatalf("owner signatures entered the digest owners sign: %s then %s", signed, bare)
	}
	// A succession signature IS bound: it is the proof the current policy
	// descends from the genesis policy.
	migrate := newEstateMigrate(t, profile, false)
	before, err := ProfileSHA256(migrate)
	if err != nil {
		t.Fatalf("digest migrate: %v", err)
	}
	migrate.PolicySuccession[0].Signatures = nil
	after, err := ProfileSHA256(migrate)
	if err != nil {
		t.Fatalf("digest migrate without succession signatures: %v", err)
	}
	if before == after {
		t.Fatalf("dropping the succession signatures left the digest unchanged: %s", before)
	}
}

func TestProfileDigestIsDomainSeparated(t *testing.T) {
	domains := []string{
		profileDigestDomain,
		estateIDDomain,
		ownerPolicyDigestDomain,
		policySuccessionDigestDomain,
		networkAccessDigestDomain,
		draftDigestDomain,
	}
	seen := map[string]bool{}
	for _, domain := range domains {
		if !strings.HasSuffix(domain, "\n") {
			t.Fatalf("domain %q does not end in a newline", domain)
		}
		if seen[domain] {
			t.Fatalf("domain %q is used twice", domain)
		}
		seen[domain] = true
	}

	profile := newEstateProfile(t)
	preimage, err := ProfilePreimage(profile)
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	var prefix binaryWriter
	prefix.bytes([]byte(profileDigestDomain))
	if !bytes.HasPrefix(preimage, prefix.Bytes()) {
		t.Fatalf("the profile preimage does not begin with its length-prefixed domain")
	}
	// The domain is inside the hash: the same body under another domain must
	// give another digest.
	body := preimage[len(prefix.Bytes()):]
	var other binaryWriter
	other.bytes([]byte(estateIDDomain))
	other.raw(body)
	if sha256Hex(other.Bytes()) == sha256Hex(preimage) {
		t.Fatalf("changing the domain did not change the digest")
	}
}

func TestBinaryWriterLengthPrefixIsInjective(t *testing.T) {
	var left, right binaryWriter
	left.string("ab")
	left.string("c")
	right.string("a")
	right.string("bc")
	if bytes.Equal(left.Bytes(), right.Bytes()) {
		t.Fatalf("two different field splittings produced one preimage: %x", left.Bytes())
	}
	var counted binaryWriter
	counted.string("abc")
	if len(counted.Bytes()) != 4+3 {
		t.Fatalf("a string is not its 4-byte big-endian length and then its bytes: %x", counted.Bytes())
	}
	if !bytes.Equal(counted.Bytes()[:4], []byte{0, 0, 0, 3}) {
		t.Fatalf("the length prefix is not 4-byte big-endian: %x", counted.Bytes()[:4])
	}
}

func TestOwnerPolicyDigestCarriesThePolicyAsOneByteString(t *testing.T) {
	policy := vectorPolicy(newEstatePolicyID, 1, 2, "owner-a", "owner-b", "owner-c")
	digest, err := OwnerPolicySHA256(policy)
	if err != nil {
		t.Fatalf("policy digest: %v", err)
	}
	var writer binaryWriter
	writer.bytes([]byte(ownerPolicyDigestDomain))
	writer.bytes(ownerPolicyEncoding(policy))
	sum := sha256.Sum256(writer.Bytes())
	if digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("the policy digest is not sha256(W(domain) || W(policy)): %s", digest)
	}
	// A different threshold is a different policy, so a succession step that
	// changes only the threshold cannot reuse its predecessor's digest.
	changed := policy
	changed.Threshold = 3
	other, err := OwnerPolicySHA256(changed)
	if err != nil {
		t.Fatalf("changed policy digest: %v", err)
	}
	if other == digest {
		t.Fatalf("the threshold is outside the policy digest")
	}
}

func TestEstateIDIsSelfCertifying(t *testing.T) {
	profile := newEstateProfile(t)
	recomputed, err := EstateID(profile.GenesisOwnerPolicy, profile.EstateNonce)
	if err != nil {
		t.Fatalf("estate id: %v", err)
	}
	if recomputed != profile.EstateID {
		t.Fatalf("the estate id in the profile is not the one its genesis policy and nonce certify")
	}
	if _, err := VerifyProfile(profile); err != nil {
		t.Fatalf("the unmutated profile must verify: %v", err)
	}
	nonce, err := hex.DecodeString(profile.EstateNonce)
	if err != nil {
		t.Fatalf("decode nonce: %v", err)
	}
	var raw [32]byte
	copy(raw[:], nonce)
	preimage := estateIDPreimage(profile.GenesisOwnerPolicy, raw)
	var prefix binaryWriter
	prefix.bytes([]byte(estateIDDomain))
	if !bytes.HasPrefix(preimage, prefix.Bytes()) {
		t.Fatalf("the estate-id preimage does not begin with its length-prefixed domain")
	}
	if !bytes.HasSuffix(preimage, raw[:]) {
		t.Fatalf("the estate-id preimage does not end in the 32 raw nonce bytes")
	}
}

func TestEstateIDSelfCertificationRefusesAForeignNonce(t *testing.T) {
	profile := newEstateProfile(t)
	profile.EstateNonce = vectorDigest("rehearsal/estateNonce/other")
	profile = signProfile(t, profile, "owner-a", "owner-b")
	_, err := VerifyProfile(profile)
	requireRefusal(t, err, RefusalIDNotSelfCertifying)
}

func TestEstateIDSelfCertificationRefusesASubstitutedGenesisPolicy(t *testing.T) {
	profile := newEstateProfile(t)
	// Swap in a genesis policy the estate id was never derived from, and make
	// the current policy match it so the chain itself is consistent.
	substitute := vectorPolicy(newEstatePolicyID, 1, 2, "owner-a", "owner-b", "owner-d")
	profile.GenesisOwnerPolicy = substitute
	profile.OwnerPolicy = substitute
	profile = signProfile(t, profile, "owner-a", "owner-b")
	_, err := VerifyProfile(profile)
	requireRefusal(t, err, RefusalIDNotSelfCertifying)
}

func TestProfilePreimageRefusesAnInvalidProfile(t *testing.T) {
	profile := newEstateProfile(t)
	profile.Network.Commitment = "processed"
	if _, err := ProfilePreimage(profile); err == nil {
		t.Fatalf("a preimage was produced for a profile that does not validate")
	} else {
		requireRefusal(t, err, RefusalFieldMalformed+":network.commitment")
	}
}

// The final flag is part of what owners sign: the preimage carries it as one
// byte right after the upgrade authority, so two profiles that differ only in
// it can never share a digest.
func TestProfileDigestBindsTheFinalFlag(t *testing.T) {
	profile := newEstateProfile(t)
	flipped := profile
	flipped.Programs = append([]ProgramV1{}, profile.Programs...)
	flipped.Programs[1].Final = false
	if bytes.Equal(profilePreimage(profile), profilePreimage(flipped)) {
		t.Fatalf("the final flag did not reach the digest preimage")
	}
	var want binaryWriter
	want.string(profile.Programs[1].ProgramID)
	want.string("")
	want.bool(true)
	want.string(profile.Programs[1].SourceCommit)
	if !bytes.Contains(profilePreimage(profile), want.Bytes()) {
		t.Fatalf("the preimage does not carry programId, the empty authority, final=1 and sourceCommit in that order")
	}
}
