package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	"github.com/hrbrlife/melusina-attest/identity"
)

// readFormFile reads the named multipart form file fully into memory.
func readFormFile(r *http.Request, field string) ([]byte, error) {
	f, _, err := r.FormFile(field)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// stdB64 decodes standard base64, tolerating empty input as empty bytes.
func stdB64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// signPubkey32 returns the operator's raw 32-byte ed25519 signing public key,
// which is what on-chain StoreOperatorAuthorization.store_authority pins and the
// VerifyPublish store_authority check compares against.
func signPubkey32(pub identity.Public) ([32]byte, error) {
	var out [32]byte
	raw, err := pub.SignPublicKey()
	if err != nil {
		return out, fmt.Errorf("operator sign pubkey: %w", err)
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("operator sign pubkey: want 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}
