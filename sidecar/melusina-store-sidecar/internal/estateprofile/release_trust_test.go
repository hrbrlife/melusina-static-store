package estateprofile

import (
	"sort"
	"testing"
)

// ceremonyTrustOf is a copy of the profile's release trust, as the ceremony
// that approved it would have stated it.
func ceremonyTrustOf(profile EstateProfileV1) ReleaseTrustV1 {
	return ReleaseTrustV1{PublisherKeys: append([]string(nil), profile.ReleaseTrust.PublisherKeys...), Threshold: profile.ReleaseTrust.Threshold}
}

// The positive control: a profile carrying exactly the ceremony's trust.
func TestRequireReleaseTrustCarriedAcceptsTheCeremonyTrust(t *testing.T) {
	profile := newEstateProfile(t)
	if err := RequireReleaseTrustCarried(profile, ceremonyTrustOf(profile)); err != nil {
		t.Fatalf("a profile carrying its ceremony's trust byte for byte was refused: %v", err)
	}
}

// Every way a carried trust can differ from a valid ceremony trust is one
// refusal, by one name. Both sides of each case are valid trusts, so only the
// comparison can refuse them.
func TestRequireReleaseTrustCarriedRefusesEveryDifference(t *testing.T) {
	profile := newEstateProfile(t)
	keys := profile.ReleaseTrust.PublisherKeys
	if len(keys) != 2 || profile.ReleaseTrust.Threshold != 1 {
		t.Fatalf("the fixture trust is %+v, not two keys at threshold one", profile.ReleaseTrust)
	}
	third := []string{keys[0], keys[1], vectorPublicKey("rehearsal/publisher-3")}
	sort.Strings(third)
	other := []string{vectorPublicKey("rehearsal/publisher-3"), vectorPublicKey("rehearsal/publisher-4")}
	sort.Strings(other)
	for name, ceremony := range map[string]ReleaseTrustV1{
		// The profile keeps a key the ceremony never named.
		"the ceremony names only the first key":  {PublisherKeys: []string{keys[0]}, Threshold: 1},
		"the ceremony names only the second key": {PublisherKeys: []string{keys[1]}, Threshold: 1},
		// The ceremony named a publisher the profile dropped.
		"the ceremony names a third key": {PublisherKeys: third, Threshold: 1},
		"another threshold":              {PublisherKeys: append([]string(nil), keys...), Threshold: 2},
		"other keys, same count":         {PublisherKeys: other, Threshold: 1},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateReleaseTrust(ceremony); err != nil {
				t.Fatalf("the case's ceremony trust is itself invalid: %v", err)
			}
			requireRefusal(t, RequireReleaseTrustCarried(profile, ceremony), RefusalReleaseTrustNotCarried)
		})
	}
}

// A ceremony trust no profile could carry is refused by the rule, before any
// comparison, and a profile that is not valid is refused as itself.
func TestRequireReleaseTrustCarriedHoldsBothSidesToTheRule(t *testing.T) {
	profile := newEstateProfile(t)
	reversed := ceremonyTrustOf(profile)
	reversed.PublisherKeys[0], reversed.PublisherKeys[1] = reversed.PublisherKeys[1], reversed.PublisherKeys[0]
	requireRefusal(t, RequireReleaseTrustCarried(profile, reversed), RefusalArrayNotSorted+":releaseTrust.publisherKeys")
	zero := ceremonyTrustOf(profile)
	zero.Threshold = 0
	requireRefusal(t, RequireReleaseTrustCarried(profile, zero), RefusalFieldMalformed+":releaseTrust.threshold")
	requireRefusal(t, RequireReleaseTrustCarried(profile, ReleaseTrustV1{}), RefusalIncomplete+":releaseTrust.publisherKeys")

	broken := profile
	broken.Network.GenesisHash = MainnetBetaGenesisHash
	requireRefusal(t, RequireReleaseTrustCarried(broken, ceremonyTrustOf(profile)), RefusalMainnetGenesis)
}

// ValidatePublisherKeys refuses exactly the key lists ValidateReleaseTrust
// refuses, by the same names, and nothing about a threshold.
func TestValidatePublisherKeysIsTheKeyHalfOfTheRule(t *testing.T) {
	profile := newEstateProfile(t)
	keys := profile.ReleaseTrust.PublisherKeys
	seventeen := make([]string, 0, MaxPublisherKeys+1)
	for index := 0; index <= MaxPublisherKeys; index++ {
		seventeen = append(seventeen, vectorPublicKey("release-trust-test/"+string(rune('a'+index))))
	}
	sort.Strings(seventeen)
	for name, test := range map[string]struct {
		keys []string
		want string
	}{
		"the fixture keys":   {keys: keys},
		"none":               {keys: nil, want: RefusalIncomplete + ":releaseTrust.publisherKeys"},
		"seventeen":          {keys: seventeen, want: RefusalFieldMalformed + ":releaseTrust.publisherKeys"},
		"sixteen":            {keys: seventeen[:MaxPublisherKeys]},
		"repeated":           {keys: []string{keys[0], keys[0]}, want: RefusalArrayDuplicate + ":releaseTrust.publisherKeys"},
		"unsorted":           {keys: []string{keys[1], keys[0]}, want: RefusalArrayNotSorted + ":releaseTrust.publisherKeys"},
		"upper-case hex":     {keys: []string{upperHex(keys[0])}, want: RefusalFieldMalformed + ":releaseTrust.publisherKeys"},
		"the identity point": {keys: []string{"0100000000000000000000000000000000000000000000000000000000000000"}, want: RefusalFieldMalformed + ":releaseTrust.publisherKeys"},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidatePublisherKeys(test.keys)
			whole := ValidateReleaseTrust(ReleaseTrustV1{PublisherKeys: test.keys, Threshold: 1})
			if test.want == "" {
				if err != nil || whole != nil {
					t.Fatalf("valid keys refused: %v / %v", err, whole)
				}
				return
			}
			requireRefusal(t, err, test.want)
			requireRefusal(t, whole, test.want)
		})
	}
	// The threshold is not the key half's to judge.
	if err := ValidatePublisherKeys(keys); err != nil {
		t.Fatal(err)
	}
	requireRefusal(t, ValidateReleaseTrust(ReleaseTrustV1{PublisherKeys: keys, Threshold: 3}), RefusalFieldMalformed+":releaseTrust.threshold")
}

func upperHex(value string) string {
	out := []byte(value)
	for index, char := range out {
		if char >= 'a' && char <= 'f' {
			out[index] = char - 'a' + 'A'
		}
	}
	return string(out)
}
