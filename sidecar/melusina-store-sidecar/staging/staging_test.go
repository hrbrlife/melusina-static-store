package staging

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func testHash(t *testing.T, text string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != 32 {
		t.Fatal("invalid test hash")
	}
	var value [32]byte
	copy(value[:], raw)
	return value
}

func selectedWelcomeStage(t *testing.T) Identity {
	runtime := testHash(t, "b2f0643486eff7538937ddf57258811a9498ce043ae0177630f9bf34b65f4b14")
	return Identity{
		SPKSHA256:             testHash(t, "f245b7fd1f198334ea0a376e5340e3fe36c057cd07a574179c88ab5997897626"),
		MetadataSHA256:        testHash(t, "3f0a88c8b4c8ac555b360bb2c8458ea5cfb42ecf901ec204a756ed7c3653638b"),
		ReleaseHash:           testHash(t, "abf91c1cd077e1355d32287fd8d611a40a134fd3f4ce15fa707367dc82070881"),
		RuntimeContractSHA256: &runtime, Version: "0.1.31", MasterNftMint: "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe",
		Developer: "hrbrlife", Repo: "welcome-pearl", Slug: "welcome-pearl",
	}
}

func TestStageIdentityMatchesOriginalRetainedWelcomeReceipt(t *testing.T) {
	// Public original 2026-08-28 Welcome 0.1.31/v32 stage tuple, retained before
	// this factoring. This tests byte compatibility, not current authorization.
	input := selectedWelcomeStage(t)
	if actual := StageID(input); actual != "96c1af0e2835344d11b2ed3d97e84c38c82d85630e323c7017abd0ab25120178" {
		t.Fatalf("original Store stage changed: %s", actual)
	}
	input.Developer, input.Repo, input.Slug = "", "", ""
	if actual := StageID(input); actual != "e91a970ef652199d916175b0018b1e3b82a7fd2b3d391bd6a2254b8c00d64fed" {
		t.Fatalf("original empty-locator framing changed: %s", actual)
	}
}

func TestStageIdentityBindsEveryOriginalInput(t *testing.T) {
	original := selectedWelcomeStage(t)
	expected := StageID(original)
	for name, change := range map[string]func(*Identity){
		"SPK":             func(i *Identity) { i.SPKSHA256[0] ^= 1 },
		"metadata":        func(i *Identity) { i.MetadataSHA256[0] ^= 1 },
		"release intent":  func(i *Identity) { i.ReleaseHash[0] ^= 1 },
		"runtime":         func(i *Identity) { value := *i.RuntimeContractSHA256; value[0] ^= 1; i.RuntimeContractSHA256 = &value },
		"runtime omitted": func(i *Identity) { i.RuntimeContractSHA256 = nil },
		"version":         func(i *Identity) { i.Version = "0.1.32" },
		"master":          func(i *Identity) { i.MasterNftMint = "another-master" },
		"developer":       func(i *Identity) { i.Developer = "another" },
		"repo":            func(i *Identity) { i.Repo = "another" },
		"slug":            func(i *Identity) { i.Slug = "another" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := original
			change(&changed)
			if StageID(changed) == expected {
				t.Fatal("changed candidate retained prior stage identity")
			}
		})
	}
	a, b := original, original
	a.Developer, a.Repo = "ab", "c"
	b.Developer, b.Repo = "a", "bc"
	if StageID(a) == StageID(b) {
		t.Fatal("locator fields lost length framing")
	}
}

func TestStageReceiptVerifiesOnlyOriginalAuthorityAndExpectedTuple(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x65}, 32))
	public := key.Public().(ed25519.PublicKey)
	input := selectedWelcomeStage(t)
	domain := testHash(t, "1bdcbe62b188e6ffe095d43b5a6a2c7bed70e738d8a5cf3e6d389563fab46592")
	receipt := Receipt{Schema: ReceiptSchema, StageID: StageID(input), AppID: "021x360jnqz798taefscu7r69a0xvvqyhfwfjadq8g2f9wuqm5h0", AppHash: "37bffeb984326a526bc974e772a2c7861e16264451b02cef1f0e23dca82dd802", ReleaseHash: hex.EncodeToString(input.ReleaseHash[:]), ServingDomainHash: hex.EncodeToString(domain[:]), StoredAt: 1787938994}
	receipt.OperatorSignature = primitives.EncodeBase58(ed25519.Sign(key, ReceiptMessage(testHash(t, receipt.StageID), testHash(t, receipt.AppHash), input.ReleaseHash, domain, receipt.StoredAt)))
	expected := Expected{StageID: receipt.StageID, AppID: receipt.AppID, AppHash: receipt.AppHash, ReleaseHash: receipt.ReleaseHash}
	if err := VerifyExpected(public, domain, expected, receipt); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Receipt){
		"schema":             func(r *Receipt) { r.Schema = "unknown" },
		"unsigned app alias": func(r *Receipt) { r.AppID = "another-app" },
		"stage":              func(r *Receipt) { r.StageID = receipt.AppHash },
		"app hash":           func(r *Receipt) { r.AppHash = receipt.ReleaseHash },
		"release":            func(r *Receipt) { r.ReleaseHash = receipt.AppHash },
		"domain":             func(r *Receipt) { r.ServingDomainHash = receipt.AppHash },
		"stored time":        func(r *Receipt) { r.StoredAt++ },
		"signature":          func(r *Receipt) { r.OperatorSignature = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := receipt
			change(&changed)
			if VerifyExpected(public, domain, expected, changed) == nil {
				t.Fatal("foreign receipt scope accepted")
			}
		})
	}
	foreign := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x66}, 32)).Public().(ed25519.PublicKey)
	if VerifyExpected(foreign, domain, expected, receipt) == nil || VerifyExpected(nil, domain, expected, receipt) == nil {
		t.Fatal("foreign or malformed authority accepted")
	}
	domain[0] ^= 1
	if VerifyExpected(public, domain, expected, receipt) == nil {
		t.Fatal("foreign independently selected domain accepted")
	}
}
