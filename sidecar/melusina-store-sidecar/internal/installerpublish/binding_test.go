package installerpublish

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
)

// The golden vectors are the cross-repository contract for the installer
// publication binding: the deployer's InstallerPublishBindingDigest copies the
// file at its Store pin and asserts the same rows.
const bindingVectorsPath = "testdata/installer-publish-binding-v1.json"

type bindingInputs struct {
	Class           string `json:"class"`
	Name            string `json:"name"`
	ArtifactSHA256  string `json:"artifactSha256"`
	StoreID         string `json:"storeId"`
	StoreDomain     string `json:"storeDomain"`
	LicenseMint     string `json:"licenseMint"`
	RegistryProgram string `json:"registryProgram"`
}

func (in bindingInputs) preimage() ([]byte, error) {
	return Preimage(in.Class, in.Name, in.ArtifactSHA256, in.StoreID, in.StoreDomain, in.LicenseMint, in.RegistryProgram)
}

func (in bindingInputs) digest() (string, error) {
	return Digest(in.Class, in.Name, in.ArtifactSHA256, in.StoreID, in.StoreDomain, in.LicenseMint, in.RegistryProgram)
}

type bindingVector struct {
	Name     string        `json:"name"`
	Inputs   bindingInputs `json:"inputs"`
	Preimage string        `json:"preimage"`
	Digest   string        `json:"digest"`
}

type bindingRefusal struct {
	Name   string        `json:"name"`
	Inputs bindingInputs `json:"inputs"`
	Error  string        `json:"error"`
}

type bindingVectorFile struct {
	Schema     string           `json:"schema"`
	Notes      []string         `json:"notes"`
	FieldOrder []string         `json:"fieldOrder"`
	Vectors    []bindingVector  `json:"vectors"`
	Refusals   []bindingRefusal `json:"refusals"`
}

func loadBindingVectors(t *testing.T) bindingVectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.FromSlash(bindingVectorsPath))
	if err != nil {
		t.Fatalf("INSTALLER_PUBLISH_BINDING_VECTORS_ABSENT: %v", err)
	}
	var file bindingVectorFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		t.Fatalf("INSTALLER_PUBLISH_BINDING_VECTORS_MALFORMED: %v", err)
	}
	if file.Schema != "melusina.installer-publish-binding-vectors.v1" || len(file.Vectors) < 3 || len(file.Refusals) < 7 {
		t.Fatalf("INSTALLER_PUBLISH_BINDING_VECTORS_INCOMPLETE: schema=%q vectors=%d refusals=%d",
			file.Schema, len(file.Vectors), len(file.Refusals))
	}
	return file
}

func vectorByName(t *testing.T, file bindingVectorFile, name string) bindingVector {
	t.Helper()
	for _, vector := range file.Vectors {
		if vector.Name == name {
			return vector
		}
	}
	t.Fatalf("INSTALLER_PUBLISH_BINDING_VECTOR_MISSING: %s", name)
	return bindingVector{}
}

// topLevelKeys returns the object keys of raw in the order they appear.
func topLevelKeys(t *testing.T, raw string) []string {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		t.Fatalf("preimage is not a JSON object: %v", err)
	}
	var keys []string
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			t.Fatal(err)
		}
		key, ok := token.(string)
		if !ok {
			t.Fatalf("preimage key %v is not a string", token)
		}
		keys = append(keys, key)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

// Positive: Preimage reproduces every vector's exact bytes and Digest its
// digest; each vector is internally consistent; the key order is the
// declared field order of Binding and of the vector file.
func TestInstallerPublishBindingGoldenVectors(t *testing.T) {
	file := loadBindingVectors(t)
	var structOrder []string
	bindingType := reflect.TypeOf(Binding{})
	for index := 0; index < bindingType.NumField(); index++ {
		structOrder = append(structOrder, strings.Split(bindingType.Field(index).Tag.Get("json"), ",")[0])
	}
	if !reflect.DeepEqual(structOrder, file.FieldOrder) {
		t.Fatalf("INSTALLER_PUBLISH_BINDING_STRUCT_ORDER_DRIFT: Binding %v, vectors %v", structOrder, file.FieldOrder)
	}
	for _, vector := range file.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			sum := sha256.Sum256([]byte(vector.Preimage))
			if hex.EncodeToString(sum[:]) != vector.Digest {
				t.Fatalf("INSTALLER_PUBLISH_BINDING_VECTOR_INCONSISTENT: sha256(preimage) %x, digest %s", sum, vector.Digest)
			}
			if keys := topLevelKeys(t, vector.Preimage); !reflect.DeepEqual(keys, file.FieldOrder) {
				t.Fatalf("INSTALLER_PUBLISH_BINDING_FIELD_ORDER_DRIFT: preimage keys %v, want %v", keys, file.FieldOrder)
			}
			preimage, err := vector.Inputs.preimage()
			if err != nil || string(preimage) != vector.Preimage {
				t.Fatalf("INSTALLER_PUBLISH_BINDING_PREIMAGE_DRIFT: %v\n got  %s\n want %s", err, preimage, vector.Preimage)
			}
			digest, err := vector.Inputs.digest()
			if err != nil || digest != vector.Digest {
				t.Fatalf("INSTALLER_PUBLISH_BINDING_DIGEST_DRIFT: %v got %s want %s", err, digest, vector.Digest)
			}
			var fixed map[string]string
			if err := json.Unmarshal([]byte(vector.Preimage), &fixed); err != nil {
				t.Fatal(err)
			}
			if fixed["schema"] != BindingSchema || fixed["method"] != http.MethodPost || fixed["target"] != Target ||
				fixed["purpose"] != BindingPurpose || fixed["artifact_sha256"] != strings.ToLower(vector.Inputs.ArtifactSHA256) {
				t.Fatalf("INSTALLER_PUBLISH_BINDING_CONSTANT_DRIFT: %v", fixed)
			}
		})
	}
	lower := vectorByName(t, file, "generation-one-installer-member")
	upper := vectorByName(t, file, "uppercase-artifact-digest-is-lowercased")
	if upper.Inputs.ArtifactSHA256 != strings.ToUpper(lower.Inputs.ArtifactSHA256) || upper.Inputs.ArtifactSHA256 == lower.Inputs.ArtifactSHA256 ||
		upper.Digest != lower.Digest || upper.Preimage != lower.Preimage {
		t.Fatal("INSTALLER_PUBLISH_BINDING_CASE_NOT_FOLDED: an uppercase artifact digest must bind the same bytes as its lowercase form")
	}
}

// Negative: every refusal vector is refused with its exact message by both
// Preimage and Digest.
func TestInstallerPublishBindingRefusalVectors(t *testing.T) {
	for _, refusal := range loadBindingVectors(t).Refusals {
		t.Run(refusal.Name, func(t *testing.T) {
			if preimage, err := refusal.Inputs.preimage(); err == nil || err.Error() != refusal.Error || preimage != nil {
				t.Fatalf("INSTALLER_PUBLISH_BINDING_REFUSAL_ACCEPTED/preimage: %v %s, want %q", err, preimage, refusal.Error)
			}
			if digest, err := refusal.Inputs.digest(); err == nil || err.Error() != refusal.Error || digest != "" {
				t.Fatalf("INSTALLER_PUBLISH_BINDING_REFUSAL_ACCEPTED/digest: %v %s, want %q", err, digest, refusal.Error)
			}
		})
	}
}

// Mutation control: every input is bound (changing any one moves the digest)
// and the golden comparison is not vacuous (a one-byte change of the expected
// preimage is detected).
func TestInstallerPublishBindingEveryFieldIsBound(t *testing.T) {
	vector := vectorByName(t, loadBindingVectors(t), "generation-one-installer-member")
	flipHex := func(value string) string {
		if value[0] == 'a' {
			return "b" + value[1:]
		}
		return "a" + value[1:]
	}
	for field, mutate := range map[string]func(*bindingInputs){
		"class":          func(in *bindingInputs) { in.Class = "data" },
		"name":           func(in *bindingInputs) { in.Name += ".other" },
		"artifactSha256": func(in *bindingInputs) { in.ArtifactSHA256 = flipHex(in.ArtifactSHA256) },
		"storeId":        func(in *bindingInputs) { in.StoreID += "-other" },
		"storeDomain":    func(in *bindingInputs) { in.StoreDomain = "other." + in.StoreDomain },
		"licenseMint": func(in *bindingInputs) {
			in.LicenseMint = vectorByName(t, loadBindingVectors(t), "deployer-class-other-store").Inputs.LicenseMint
		},
		"registryProgram": func(in *bindingInputs) {
			in.RegistryProgram = vectorByName(t, loadBindingVectors(t), "deployer-class-other-store").Inputs.RegistryProgram
		},
	} {
		inputs := vector.Inputs
		mutate(&inputs)
		digest, err := inputs.digest()
		if err != nil {
			t.Fatalf("INSTALLER_PUBLISH_BINDING_MUTATION_INVALID/%s: %v", field, err)
		}
		if digest == vector.Digest {
			t.Fatalf("INSTALLER_PUBLISH_BINDING_FIELD_NOT_BOUND/%s: a changed %s kept digest %s", field, field, digest)
		}
	}
	preimage, err := vector.Inputs.preimage()
	if err != nil {
		t.Fatal(err)
	}
	mutated := []byte(vector.Preimage)
	mutated[len(mutated)-2] ^= 0x01
	if bytes.Equal(preimage, mutated) {
		t.Fatal("INSTALLER_PUBLISH_BINDING_COMPARISON_VACUOUS: a mutated golden preimage still matched")
	}
}

// Sign carries the golden digest as the envelope body hash and the lowercase
// artifact digest as its request hash, bound to POST /publish/installer.
func TestSignBindsTheGoldenDigest(t *testing.T) {
	vector := vectorByName(t, loadBindingVectors(t), "uppercase-artifact-digest-is-lowercased")
	ref := identity.Ref{Kind: identity.KindSidecar, ChainID: "solana:installer-publish-binding-test",
		ProgramID: vector.Inputs.RegistryProgram, LicenseMint: vector.Inputs.LicenseMint,
		Domain: "publisher.binding-test.invalid", PDA: "11111111111111111111111111111111",
		SidecarID: "release-publisher", KeyVersion: 1}
	publisher, err := identity.NewPrivate(ref, sha256.Sum256([]byte("installer-publish-binding-test: publisher sign")),
		sha256.Sum256([]byte("installer-publish-binding-test: publisher box")))
	if err != nil {
		t.Fatal(err)
	}
	storeRef := ref
	storeRef.Domain = vector.Inputs.StoreDomain
	storeRef.SidecarID = vector.Inputs.StoreID
	store, err := identity.NewPrivate(storeRef, sha256.Sum256([]byte("installer-publish-binding-test: store sign")),
		sha256.Sum256([]byte("installer-publish-binding-test: store box")))
	if err != nil {
		t.Fatal(err)
	}
	in := vector.Inputs
	signed, err := Sign(publisher, store.Public(), in.Class, in.Name, in.ArtifactSHA256, in.StoreID, in.StoreDomain,
		in.LicenseMint, in.RegistryProgram, 7, 10*time.Minute)
	if err != nil {
		t.Fatalf("INSTALLER_PUBLISH_SIGN_POSITIVE: %v", err)
	}
	if signed.Payload.BodyHashHex != vector.Digest || signed.Payload.RequestHashHex != strings.ToLower(in.ArtifactSHA256) ||
		signed.Payload.Method != http.MethodPost || signed.Payload.Target != Target {
		t.Fatalf("INSTALLER_PUBLISH_SIGN_NOT_BOUND_TO_GOLDEN_DIGEST: body=%s request=%s method=%s target=%s",
			signed.Payload.BodyHashHex, signed.Payload.RequestHashHex, signed.Payload.Method, signed.Payload.Target)
	}
}
