package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
)

// Each transport verification carries its signed payload digest into the
// existing single-writer disk ledger. The envelope package calls Claim only
// after signature, audience and expiry checks have passed.
type durableEnvelopeNonceCache struct {
	ledger      *publishNonceLedger
	payloadHash string
	claimedAt   time.Time
	err         error
}

func (cache *durableEnvelopeNonceCache) Claim(scope, nonce string, expiresAt time.Time) bool {
	cache.err = cache.ledger.Claim("transport|"+scope, nonce, cache.payloadHash,
		expiresAt.UnixMilli(), cache.claimedAt)
	return cache.err == nil
}

func (s *publishService) verifyDurableEnvelope(sig envelope.Signed, options envelope.VerifyOptions) error {
	if s.appNonces == nil {
		return errors.New("check=nonce_ledger: durable nonce state unavailable")
	}
	cache := &durableEnvelopeNonceCache{
		ledger: s.appNonces, payloadHash: sig.PayloadHash, claimedAt: s.currentTime(),
	}
	options.NonceCache = cache
	if err := envelope.Verify(sig, options); err != nil {
		if cache.err != nil {
			return fmt.Errorf("check=nonce_ledger: %w", cache.err)
		}
		return err
	}
	return nil
}
