package estateprofile

import (
	"strings"
	"testing"
)

// mutateJSON replaces exactly one occurrence of old, failing loudly when the
// document does not contain it, so a negative control can never silently
// become a test of the unmutated document.
func mutateJSON(t *testing.T, raw []byte, old, new string) []byte {
	t.Helper()
	if strings.Count(string(raw), old) != 1 {
		t.Fatalf("the negative control needs exactly one %q in the document, found %d", old, strings.Count(string(raw), old))
	}
	return []byte(strings.Replace(string(raw), old, new, 1))
}

func TestDecodeProfileAcceptsTheCanonicalDocument(t *testing.T) {
	profile := newEstateProfile(t)
	decoded, err := DecodeProfile(marshalProfile(t, profile))
	if err != nil {
		t.Fatalf("the canonical document must decode: %v", err)
	}
	if decoded.EstateID != profile.EstateID || decoded.Revision != profile.Revision {
		t.Fatalf("the decoded document is not the one that was marshalled")
	}
	if _, err := VerifyProfile(decoded); err != nil {
		t.Fatalf("the decoded document must verify: %v", err)
	}
}

func TestStrictDecodeRefusesADuplicateKey(t *testing.T) {
	raw := marshalProfile(t, newEstateProfile(t))
	duplicated := mutateJSON(t, raw, `"kind":"estate-profile",`, `"kind":"estate-profile","kind":"estate-profile",`)
	_, err := DecodeProfile(duplicated)
	requireRefusal(t, err, RefusalJSONDuplicateKey+":$.kind")
}

func TestStrictDecodeRefusesADuplicateKeyInsideANestedObject(t *testing.T) {
	raw := marshalProfile(t, newEstateProfile(t))
	duplicated := mutateJSON(t, raw, `"commitment":"finalized"`, `"commitment":"finalized","commitment":"finalized"`)
	_, err := DecodeProfile(duplicated)
	requireRefusal(t, err, RefusalJSONDuplicateKey+":$.network.commitment")
}

func TestStrictDecodeRefusesAnUnknownField(t *testing.T) {
	raw := marshalProfile(t, newEstateProfile(t))
	extended := mutateJSON(t, raw, `{"schema":`, `{"stage":"draft","schema":`)
	_, err := DecodeProfile(extended)
	requireRefusal(t, err, RefusalJSONUnknownField+":$.stage")
}

func TestStrictDecodeRefusesACaseAliasedField(t *testing.T) {
	raw := marshalProfile(t, newEstateProfile(t))
	aliased := mutateJSON(t, raw, `"revision":1,"issuedAt"`, `"Revision":1,"issuedAt"`)
	_, err := DecodeProfile(aliased)
	requireRefusal(t, err, RefusalJSONUnknownField+":$.Revision")
}

func TestStrictDecodeRefusesAMissingField(t *testing.T) {
	raw := marshalProfile(t, newEstateProfile(t))
	shortened := mutateJSON(t, raw, `,"commitment":"finalized"`, ``)
	_, err := DecodeProfile(shortened)
	requireRefusal(t, err, RefusalJSONMissingField+":$.network.commitment")
}

func TestStrictDecodeRefusesANonIntegerNumber(t *testing.T) {
	raw := marshalProfile(t, newEstateProfile(t))
	for _, item := range []struct{ name, number, refusal string }{
		{"fractional", "1.0", RefusalJSONUnsafeInteger + ":$.revision"},
		{"exponent", "1e0", RefusalJSONUnsafeInteger + ":$.revision"},
		{"negative", "-1", RefusalJSONUnsafeInteger + ":$.revision"},
		{"above the safe integer range", "9007199254740992", RefusalJSONUnsafeInteger + ":$.revision"},
		// A leading zero is not a JSON number at all, so it is refused one
		// step earlier, by the tokeniser.
		{"leading zero", "01", RefusalJSONMalformed},
	} {
		t.Run(item.name, func(t *testing.T) {
			mutated := mutateJSON(t, raw, `"revision":1,"issuedAt"`, `"revision":`+item.number+`,"issuedAt"`)
			_, err := DecodeProfile(mutated)
			requireRefusal(t, err, item.refusal)
		})
	}
}

func TestStrictDecodeRefusesANumberSpeltAsAString(t *testing.T) {
	raw := marshalProfile(t, newEstateProfile(t))
	mutated := mutateJSON(t, raw, `"revision":1,"issuedAt"`, `"revision":"1","issuedAt"`)
	_, err := DecodeProfile(mutated)
	requireRefusal(t, err, RefusalJSONWrongType+":$.revision")
}

func TestStrictDecodeRefusesNull(t *testing.T) {
	raw := marshalProfile(t, newEstateProfile(t))
	mutated := mutateJSON(t, raw, `"commitment":"finalized"`, `"commitment":null`)
	_, err := DecodeProfile(mutated)
	requireRefusal(t, err, RefusalJSONNull+":$.network.commitment")
}

func TestStrictDecodeRefusesAnOversizeDocument(t *testing.T) {
	raw := marshalProfile(t, newEstateProfile(t))
	padded := append([]byte(strings.Repeat(" ", MaxProfileJSONBytes)), raw...)
	_, err := DecodeProfile(padded)
	requireRefusal(t, err, RefusalJSONTooLarge)
	if len(padded) <= MaxProfileJSONBytes {
		t.Fatalf("the oversize control was not oversize")
	}
}

func TestStrictDecodeRefusesAnEmptyDocument(t *testing.T) {
	_, err := DecodeProfile(nil)
	requireRefusal(t, err, RefusalJSONEmpty)
}

func TestStrictDecodeRefusesTrailingData(t *testing.T) {
	raw := marshalProfile(t, newEstateProfile(t))
	_, err := DecodeProfile(append(raw, []byte("{}")...))
	requireRefusal(t, err, RefusalJSONTrailingData)
}

func TestStrictDecodeRefusesInvalidUTF8(t *testing.T) {
	raw := marshalProfile(t, newEstateProfile(t))
	mutated := mutateJSON(t, raw, `"label":"melusina-rehearsal"`, "\"label\":\"melusina-rehearsal\xff\"")
	_, err := DecodeProfile(mutated)
	requireRefusal(t, err, RefusalJSONMalformed)
}

func TestStrictDecodeRefusesExcessNesting(t *testing.T) {
	deep := `{"schema":"` + ProfileSchema + `","kind":"` + ProfileKind + `","estateId":{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":1}}}}}}}}}`
	_, err := DecodeProfile([]byte(deep))
	requireRefusal(t, err, RefusalJSONTooDeep+":$.estateId.a.b.c.d.e.f.g")
}

// The draft is the ceremony profile's schema, whatever else the document
// carries: a profile relabelled with it is refused as a draft at decode and at
// validation. The invented draft kind no producer ever emitted is not a draft;
// it is an unsupported document like any other.
func TestStrictDecodeRefusesADraftAsADraft(t *testing.T) {
	// contracts scripts/estate/estate-profile.schema.json schema const.
	if ceremonySchema := "melusina.estate-profile/v1"; DraftSchema != ceremonySchema {
		t.Fatalf("the draft is %q, not the chain-foundation ceremony profile's schema %q", DraftSchema, ceremonySchema)
	}
	profile := newEstateProfile(t)
	raw := marshalProfile(t, profile)
	draft := mutateJSON(t, raw, `"schema":"`+ProfileSchema+`"`, `"schema":"`+DraftSchema+`"`)
	_, err := DecodeProfile(draft)
	requireRefusal(t, err, RefusalDraftNotEnrollable)

	relabelled := profile
	relabelled.Schema = DraftSchema
	requireRefusal(t, ValidateProfile(relabelled), RefusalDraftNotEnrollable)

	invented := mutateJSON(t, raw, `"kind":"estate-profile",`, `"kind":"estate-profile-draft",`)
	_, err = DecodeProfile(invented)
	requireRefusal(t, err, RefusalSchemaUnsupported)
}

func TestStrictDecodeRefusesAnUnknownSchema(t *testing.T) {
	raw := marshalProfile(t, newEstateProfile(t))
	mutated := mutateJSON(t, raw, `"schema":"`+ProfileSchema+`"`, `"schema":"melusina.estate.profile.v2"`)
	_, err := DecodeProfile(mutated)
	requireRefusal(t, err, RefusalSchemaUnsupported)
}

func TestStrictDecodeRefusesAWronglyTypedArray(t *testing.T) {
	raw := marshalProfile(t, newEstateProfile(t))
	mutated := mutateJSON(t, raw, `"recalls":[]`, `"recalls":{}`)
	_, err := DecodeProfile(mutated)
	requireRefusal(t, err, RefusalJSONWrongType+":$.recalls")
}

func TestStrictDecodeRefusesAnUnsortedArray(t *testing.T) {
	profile := newEstateProfile(t)
	profile.Programs[0], profile.Programs[1] = profile.Programs[1], profile.Programs[0]
	_, err := DecodeProfile(marshalProfile(t, profile))
	requireRefusal(t, err, RefusalArrayNotSorted+":programs")
}

func TestStrictDecodeRefusesADuplicateArrayEntry(t *testing.T) {
	profile := newEstateProfile(t)
	profile.Programs[1] = profile.Programs[0]
	_, err := DecodeProfile(marshalProfile(t, profile))
	requireRefusal(t, err, RefusalArrayDuplicate+":programs")
}

func TestValidateRefusesAnIncompleteProfile(t *testing.T) {
	profile := newEstateProfile(t)
	profile.Programs[0].ExecutableSHA256 = ""
	requireRefusal(t, ValidateProfile(profile), RefusalIncomplete+":programs.license-registry.executableSha256")

	missing := newEstateProfile(t)
	missing.Programs = missing.Programs[:1]
	requireRefusal(t, ValidateProfile(missing), RefusalIncomplete+":programs.witness-verifier")
}

// The witness verifier is deployed final: its ProgramData authority is None,
// so the only truthful statement is final with no address. The licence
// registry is governed: final is refused there and its authority is required.
// Each disagreement is refused by its own name.
func TestValidateHoldsEachProgramToHowItsRoleIsDeployed(t *testing.T) {
	profile := newEstateProfile(t)
	if err := ValidateProfile(profile); err != nil {
		t.Fatalf("a final witness verifier beside a governed licence registry must validate: %v", err)
	}
	if !ProgramRoleIsFinal(ProgramRoleWitnessVerifier) || ProgramRoleIsFinal(ProgramRoleLicenseRegistry) {
		t.Fatalf("the witness verifier must be the final role and the licence registry the governed one")
	}
	governed := profile.Programs[0].UpgradeAuthority
	for _, item := range []struct {
		name   string
		edit   func(*EstateProfileV1)
		refuse string
	}{
		{"final role naming an authority", func(p *EstateProfileV1) { p.Programs[1].UpgradeAuthority = governed },
			RefusalProgramMustBeFinal + ":programs.witness-verifier.upgradeAuthority"},
		{"final role naming the all-zero authority", func(p *EstateProfileV1) { p.Programs[1].UpgradeAuthority = "11111111111111111111111111111111" },
			RefusalProgramMustBeFinal + ":programs.witness-verifier.upgradeAuthority"},
		{"final role stated governed", func(p *EstateProfileV1) { p.Programs[1].Final, p.Programs[1].UpgradeAuthority = false, governed },
			RefusalProgramMustBeFinal + ":programs.witness-verifier.final"},
		{"final role stated governed with no authority", func(p *EstateProfileV1) { p.Programs[1].Final = false },
			RefusalProgramMustBeFinal + ":programs.witness-verifier.final"},
		{"governed role stated final", func(p *EstateProfileV1) { p.Programs[0].Final, p.Programs[0].UpgradeAuthority = true, "" },
			RefusalProgramMustBeGoverned + ":programs.license-registry.final"},
		{"governed role stated final keeping its authority", func(p *EstateProfileV1) { p.Programs[0].Final = true },
			RefusalProgramMustBeGoverned + ":programs.license-registry.final"},
		{"governed role without authority", func(p *EstateProfileV1) { p.Programs[0].UpgradeAuthority = "" },
			RefusalIncomplete + ":programs.license-registry.upgradeAuthority"},
		{"governed role with the all-zero authority", func(p *EstateProfileV1) { p.Programs[0].UpgradeAuthority = "11111111111111111111111111111111" },
			RefusalFieldMalformed + ":programs.license-registry.upgradeAuthority"},
	} {
		t.Run(item.name, func(t *testing.T) {
			mutated := newEstateProfile(t)
			item.edit(&mutated)
			requireRefusal(t, ValidateProfile(mutated), item.refuse)
			// The consumer decoder refuses the same document by the same name.
			_, err := DecodeProfile(marshalProfile(t, mutated))
			requireRefusal(t, err, item.refuse)
		})
	}
}

func TestStrictDecodeRequiresTheFinalFlagAsABoolean(t *testing.T) {
	raw := marshalProfile(t, newEstateProfile(t))
	_, err := DecodeProfile(mutateJSON(t, raw, `"upgradeAuthority":"","final":true,`, `"upgradeAuthority":"",`))
	requireRefusal(t, err, RefusalJSONMissingField+":$.programs[1].final")
	_, err = DecodeProfile(mutateJSON(t, raw, `"final":true`, `"final":1`))
	requireRefusal(t, err, RefusalJSONWrongType+":$.programs[1].final")
}
