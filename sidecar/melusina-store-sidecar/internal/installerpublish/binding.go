// Package installerpublish defines the purpose-bound bytes signed by the
// installer artifact publisher and checked by the Store receiver.
package installerpublish

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
)

const Target = "/publish/installer"

type Binding struct {
	Schema          string `json:"schema"`
	Method          string `json:"method"`
	Target          string `json:"target"`
	Purpose         string `json:"purpose"`
	Class           string `json:"class"`
	Name            string `json:"name"`
	ArtifactSHA256  string `json:"artifact_sha256"`
	StoreID         string `json:"store_id"`
	StoreDomain     string `json:"store_domain"`
	LicenseMint     string `json:"license_mint"`
	RegistryProgram string `json:"registry_program"`
}

func Digest(class, name, artifactSHA256, storeID, storeDomain, licenseMint, registryProgram string) (string, error) {
	binding := Binding{
		Schema: "melusina.installer-publish-binding.v1", Method: http.MethodPost,
		Target: Target, Purpose: "installer-artifact-publication",
		Class: class, Name: name, ArtifactSHA256: strings.ToLower(artifactSHA256),
		StoreID: storeID, StoreDomain: storeDomain,
		LicenseMint: licenseMint, RegistryProgram: registryProgram,
	}
	for _, value := range []string{binding.Class, binding.Name, binding.StoreID, binding.StoreDomain,
		binding.LicenseMint, binding.RegistryProgram} {
		if strings.TrimSpace(value) == "" {
			return "", errors.New("installer-publish-binding: required audience or release field is empty")
		}
	}
	if raw, err := hex.DecodeString(binding.ArtifactSHA256); err != nil || len(raw) != sha256.Size {
		return "", errors.New("installer-publish-binding: artifact digest invalid")
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

// Sign is the command producer for the exact installer publication purpose.
// The receiver recomputes Digest from the HTTP request and its pinned estate.
func Sign(publisher *identity.Private, destination identity.Public, class, name, artifactSHA256,
	storeID, storeDomain, licenseMint, registryProgram string, verifiedSlot uint64, ttl time.Duration) (envelope.Signed, error) {
	binding, err := Digest(class, name, artifactSHA256, storeID, storeDomain, licenseMint, registryProgram)
	if err != nil {
		return envelope.Signed{}, err
	}
	return envelope.Sign(envelope.KindPublishRequest, publisher, destination, envelope.SignOptions{
		RequestHash: artifactSHA256, BodyHash: binding, Method: http.MethodPost, Target: Target, TTL: ttl,
		Chain: envelope.ChainEvidence{ChainID: publisher.Public().Ref.ChainID,
			ProgramID: registryProgram, VerifiedSlot: verifiedSlot},
	})
}
