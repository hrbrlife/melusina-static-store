package derive

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/hrbrlife/melusina-attest/identity"
	"golang.org/x/crypto/hkdf"
)

const (
	labelPearlMaster   = "melusina-attest/pearl-master/v1"
	labelSidecarMaster = "melusina-attest/sidecar-master/v1"
	labelSignSeed      = "melusina-attest/sign-seed/v1"
	labelBoxSeed       = "melusina-attest/box-seed/v1"
)

type PearlShards struct {
	AuthorShard           [32]byte
	PearlObservationShard [32]byte
	OwnerShard            [32]byte
	ReleaseShard          [32]byte
}

type SidecarShards struct {
	AuthorShard          [32]byte
	HostObservationShard [32]byte
	ReleaseShard         [32]byte
}

type PearlObservation struct {
	MelusinaPearlID   string `json:"melusina_pearl_id"`
	MelusinaPublicID  string `json:"melusina_public_id"`
	MelusinaHostID    string `json:"melusina_host_id"`
	MelusinaAppID     string `json:"melusina_app_id"`
	VarDirFingerprint string `json:"var_dir_fingerprint"`
	LicenseMint       string `json:"license_mint"`
	Domain            string `json:"domain"`
}

func DerivePearl(ref identity.Ref, shards PearlShards) (*identity.Private, error) {
	if ref.Kind != identity.KindPearl {
		return nil, errors.New("attest derive: pearl ref must have kind=pearl")
	}
	ikm := concat(shards.AuthorShard, shards.PearlObservationShard, shards.OwnerShard, shards.ReleaseShard)
	return derive(ref, ikm, labelPearlMaster)
}

func DeriveSidecar(ref identity.Ref, shards SidecarShards) (*identity.Private, error) {
	if ref.Kind != identity.KindSidecar {
		return nil, errors.New("attest derive: sidecar ref must have kind=sidecar")
	}
	ikm := concat(shards.AuthorShard, shards.HostObservationShard, shards.ReleaseShard)
	return derive(ref, ikm, labelSidecarMaster)
}

func ComputePearlObservationShard(obs PearlObservation) ([32]byte, error) {
	if obs.MelusinaPearlID == "" || obs.LicenseMint == "" || obs.Domain == "" {
		return [32]byte{}, errors.New("attest derive: pearl id, license mint, and domain are required")
	}
	b, err := json.Marshal(obs)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

func ComputePearlOwnerShard(ownerUserID, ownerWallet, pearlID string, firstLaunchUnixMs int64) [32]byte {
	b, _ := json.Marshal(struct {
		OwnerUserID       string `json:"owner_user_id"`
		OwnerWallet       string `json:"owner_wallet"`
		PearlID           string `json:"pearl_id"`
		FirstLaunchUnixMs int64  `json:"first_launch_unix_ms"`
	}{ownerUserID, ownerWallet, pearlID, firstLaunchUnixMs})
	return sha256.Sum256(b)
}

func HashBytes(b []byte) [32]byte {
	return sha256.Sum256(b)
}

func derive(ref identity.Ref, ikm []byte, label string) (*identity.Private, error) {
	if len(ikm) == 0 {
		return nil, errors.New("attest derive: empty input key material")
	}
	refDigest, err := computeRefDigest(ref)
	if err != nil {
		return nil, err
	}
	info := []byte(fmt.Sprintf("%s|kv=%d|ref=%x", ref.Kind, ref.KeyVersion, refDigest[:]))
	master, err := hkdf32(ikm, []byte(label), info)
	if err != nil {
		return nil, err
	}
	signSeed, err := hkdf32(master[:], nil, []byte(labelSignSeed))
	if err != nil {
		return nil, err
	}
	boxSeed, err := hkdf32(master[:], nil, []byte(labelBoxSeed))
	if err != nil {
		return nil, err
	}
	return identity.NewPrivate(ref, signSeed, boxSeed)
}

func computeRefDigest(ref identity.Ref) ([32]byte, error) {
	if err := ref.Validate(); err != nil {
		return [32]byte{}, err
	}
	b, err := json.Marshal(ref)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

func hkdf32(ikm, salt, info []byte) ([32]byte, error) {
	var out [32]byte
	r := hkdf.New(sha256.New, ikm, salt, info)
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return out, err
	}
	return out, nil
}

func concat(parts ...[32]byte) []byte {
	out := make([]byte, 0, len(parts)*32)
	for _, part := range parts {
		out = append(out, part[:]...)
	}
	return out
}
