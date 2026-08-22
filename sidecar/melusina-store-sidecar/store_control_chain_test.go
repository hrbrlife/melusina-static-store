package main

import (
	"encoding/binary"
	"testing"
	"time"
)

func appendControlFixed(dst []byte, value byte, size int) []byte {
	for range size {
		dst = append(dst, value)
	}
	return dst
}

func appendControlU64(dst []byte, value uint64) []byte {
	var raw [8]byte
	binary.LittleEndian.PutUint64(raw[:], value)
	return append(dst, raw[:]...)
}

func appendControlU16(dst []byte, value uint16) []byte {
	var raw [2]byte
	binary.LittleEndian.PutUint16(raw[:], value)
	return append(dst, raw[:]...)
}

func storeControlPolicyBlob(status byte) []byte {
	b := append([]byte{}, accountDiscriminator("StoreControlPolicy")...)
	b = appendControlFixed(b, 1, 32) // license
	b = appendControlFixed(b, 2, 32) // domain
	b = appendControlFixed(b, 3, 32) // store authority
	b = appendControlFixed(b, 4, 32) // operator authz
	b = appendControlFixed(b, 5, 32) // Pearl command key
	b = appendControlU64(b, 7)
	b = append(b, status)
	b = appendControlFixed(b, 6, 32)
	b = appendControlU64(b, 100)
	b = appendControlFixed(b, 7, 32)
	b = appendControlU64(b, 101)
	b = append(b, 0) // retired_at None
	b = append(b, 9) // bump
	return b
}

func storePublisherGrantBlob(status byte) []byte {
	b := append([]byte{}, accountDiscriminator("StorePublisherGrant")...)
	b = appendControlFixed(b, 1, 32) // policy
	b = appendControlFixed(b, 2, 32) // app
	b = appendControlFixed(b, 3, 32) // vault
	b = appendControlFixed(b, 4, 32) // publisher key
	b = appendControlU16(b, storePublisherActionPublishRelease)
	b = appendControlU64(b, uint64(100))
	b = appendControlU64(b, uint64(200))
	b = appendControlU64(b, 5)
	b = append(b, status)
	b = append(b, 0) // previous grant None
	b = appendControlFixed(b, 5, 32)
	b = appendControlU64(b, 101)
	b = appendControlFixed(b, 6, 32)
	b = appendControlU64(b, 102)
	b = append(b, 1) // revoked_at Some
	b = appendControlU64(b, 103)
	b = append(b, 1) // revoked_by Some
	b = appendControlFixed(b, 7, 32)
	b = append(b, 8) // bump
	return b
}

func TestReadStoreControlPolicyMetaStrictlyDecodesLayout(t *testing.T) {
	meta, err := readStoreControlPolicyMeta(storeControlPolicyBlob(storePolicyStatusActive))
	if err != nil {
		t.Fatalf("read active policy: %v", err)
	}
	if !meta.Active || meta.PolicyEpoch != 7 || meta.LicenseNFTMint[0] != 1 || meta.LicenseNFTMint[31] != 1 || meta.PearlCommandPublicKey[0] != 5 || meta.PearlCommandPublicKey[31] != 5 {
		t.Fatalf("decoded policy drift: %#v", meta)
	}
	for name, mutate := range map[string]func([]byte){
		"unknown status": func(b []byte) { b[8+32+32+32+32+32+8] = 9 },
		"truncated":      func(b []byte) { b[len(b)-1] = 0; b = b[:len(b)-1] },
		"trailing":       func(b []byte) { b = append(b, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			b := storeControlPolicyBlob(storePolicyStatusActive)
			// Apply mutations that change a slice length explicitly, because a
			// function parameter cannot retain append's returned slice.
			if name == "truncated" {
				b = b[:len(b)-1]
			} else if name == "trailing" {
				b = append(b, 1)
			} else {
				mutate(b)
			}
			if _, err := readStoreControlPolicyMeta(b); err == nil {
				t.Fatal("malformed policy was accepted")
			}
		})
	}
}

func TestReadStorePublisherGrantMetaStrictlyDecodesLayout(t *testing.T) {
	meta, err := readStorePublisherGrantMeta(storePublisherGrantBlob(storeGrantStatusActive))
	if err != nil {
		t.Fatalf("read active grant: %v", err)
	}
	if !meta.Active || meta.Actions != storePublisherActionPublishRelease || meta.GrantEpoch != 5 || !meta.NotBefore.Equal(time.Unix(100, 0).UTC()) || !meta.ExpiresAt.Equal(time.Unix(200, 0).UTC()) {
		t.Fatalf("decoded grant drift: %#v", meta)
	}
	b := storePublisherGrantBlob(storeGrantStatusActive)
	b[8+32+32+32+32+2+8+8+8] = 9
	if _, err := readStorePublisherGrantMeta(b); err == nil {
		t.Fatal("unknown grant status was accepted")
	}
}
