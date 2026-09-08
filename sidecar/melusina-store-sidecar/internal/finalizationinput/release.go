package finalizationinput

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"github.com/hrbrlife/melusina-store-sidecar/internal/squadsproof"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// ReleaseClaims mirrors the complete canonical melusina-release-v1 descriptor
// in the Store's release.go. A finalizer must accept the actual provider output,
// including its author, quorum and runtime claims, while retaining the original
// bytes for the publisher envelope. These are claims, not authority: the fixed
// governance observer and Store still independently verify the live release,
// configured publisher authority, policy/grant, predecessor and runtime.
type ReleaseClaims struct {
	Schema                string        `json:"$schema"`
	AppHash               string        `json:"appHash"`
	ReleaseHash           string        `json:"releaseHash"`
	Version               string        `json:"version"`
	SignedAtUnix          int64         `json:"signedAtUnix"`
	MasterNftMint         string        `json:"masterNftMint"`
	LicenseSquadsVault    string        `json:"licenseSquadsVault"`
	ReleaseEntryPDA       string        `json:"releaseEntryPda"`
	AuthorSig             string        `json:"authorSig"`
	QuorumPolicy          ReleaseQuorum `json:"quorumPolicy"`
	ReleaseNonce          string        `json:"releaseNonce"`
	RuntimeContractSHA256 string        `json:"runtimeContractSha256,omitempty"`
	RuntimeContractSchema string        `json:"runtimeContractSchema,omitempty"`
}

type ReleaseQuorum struct {
	Threshold   int    `json:"threshold"`
	MemberCount int    `json:"memberCount"`
	MultisigPDA string `json:"multisigPda"`
}

func decodeRelease(raw []byte) (ReleaseClaims, error) {
	var claims ReleaseClaims
	fields, err := exactReleaseObject(raw, map[string]bool{
		"$schema": true, "appHash": true, "releaseHash": true, "version": true,
		"signedAtUnix": true, "masterNftMint": true, "licenseSquadsVault": true,
		"releaseEntryPda": true, "authorSig": true, "quorumPolicy": true, "releaseNonce": true,
		"runtimeContractSha256": false, "runtimeContractSchema": false,
	})
	if err != nil {
		return claims, err
	}
	if _, err := exactReleaseObject(fields["quorumPolicy"], map[string]bool{"threshold": true, "memberCount": true, "multisigPda": true}); err != nil {
		return claims, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return claims, errors.New("release is not one canonical descriptor")
	}
	if claims.Schema != "melusina-release-v1" || !lowerHex(claims.AppHash, 64) || !lowerHex(claims.ReleaseHash, 64) || !safeText(claims.Version, 256) || !safeText(claims.ReleaseNonce, 256) || claims.SignedAtUnix <= 0 || digest([]byte(claims.AppHash+claims.Version+claims.ReleaseNonce)) != claims.ReleaseHash {
		return claims, errors.New("release identity or nonce binding is invalid")
	}
	for _, text := range []string{claims.MasterNftMint, claims.LicenseSquadsVault, claims.ReleaseEntryPDA, claims.QuorumPolicy.MultisigPDA} {
		if _, err := squadsproof.DecodePubkey(text); err != nil {
			return claims, errors.New("release authority claim is malformed")
		}
	}
	q := claims.QuorumPolicy
	if q.Threshold < 1 || q.MemberCount < q.Threshold || q.MemberCount > 65535 {
		return claims, errors.New("release quorum claim is invalid")
	}
	multisig, _ := squadsproof.DecodePubkey(q.MultisigPDA)
	vault, _, err := squadsproof.DeriveVaultPDA(multisig, 0, squadsproof.DefaultProgramID)
	if err != nil || primitives.EncodeBase58(vault[:]) != claims.LicenseSquadsVault {
		return claims, errors.New("release vault does not derive from its quorum")
	}
	// The canonical provider's ApplyEntryToManifest emits standard base64,
	// as retained in accepted RELEASE.json bytes (not a transaction signature).
	signature, err := base64.StdEncoding.Strict().DecodeString(claims.AuthorSig)
	if err != nil || len(signature) != 64 || base64.StdEncoding.EncodeToString(signature) != claims.AuthorSig {
		return claims, errors.New("release author signature claim is malformed")
	}
	if (claims.RuntimeContractSHA256 == "") != (claims.RuntimeContractSchema == "") || (claims.RuntimeContractSHA256 != "" && (!lowerHex(claims.RuntimeContractSHA256, 64) || claims.RuntimeContractSchema != "melusina-app-runtime-contract-v1")) {
		return claims, errors.New("release runtime claim is invalid")
	}
	return claims, nil
}

// Exact spellings are checked before Go's case-insensitive struct decoder.
// Duplicate fields, aliases, nulls and unsupported extensions must not acquire
// different meanings in the finalizer, envelope signer and Store.
func exactReleaseObject(raw []byte, allowed map[string]bool) (map[string]json.RawMessage, error) {
	return exactReleaseObjectWithNulls(raw, allowed, nil)
}

func exactReleaseObjectWithNulls(raw []byte, allowed, nullable map[string]bool) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("release claims require a JSON object")
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, errors.New("release field is malformed")
		}
		if _, ok := allowed[key]; !ok || fields[key] != nil {
			return nil, errors.New("release field is unknown, aliased or duplicated")
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil || (bytes.Equal(bytes.TrimSpace(value), []byte("null")) && !nullable[key]) {
			return nil, errors.New("release field is malformed or null")
		}
		fields[key] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || d.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("release claims have trailing data")
	}
	for key, required := range allowed {
		if required && fields[key] == nil {
			return nil, errors.New("release claims omit a required field")
		}
	}
	return fields, nil
}
