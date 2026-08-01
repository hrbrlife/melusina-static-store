package envelope

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

// VerifyError wraps a low-level Ed25519 / decode failure with a
// machine-stable reason slug the gate reports.
type VerifyError struct {
	Reason string
	Err    error
}

func (e *VerifyError) Error() string {
	if e.Err == nil {
		return e.Reason
	}
	return fmt.Sprintf("%s: %v", e.Reason, e.Err)
}

func (e *VerifyError) Unwrap() error { return e.Err }

// VerifyOptions tune the verification of a single envelope.
type VerifyOptions struct {
	// ClockSkew is the maximum allowed difference between the
	// server's current time and the envelope's claimed timestamp.
	// Zero means "unbounded" — callers SHOULD set a positive value.
	ClockSkew time.Duration
	// Now lets tests inject a fixed clock. Defaults to time.Now().UTC.
	Now func() time.Time
}

// EnforceMinProtocol refuses to proceed with verification when the
// envelope's claimed protocol version is below minProto. C19: the
// caller (gate, sealed-receipt CLI, audit replayer) is expected to
// resolve minProto via policy.EffectiveMinProtocolVer so that an
// unset MinProtocolVer in a freshly-authored bundle still rejects v1.
//
// The reason slug is "protocol_version_too_low" — the same the gate
// surfaces — so call sites that wrap this in a *VerifyError do not
// need a second reason vocabulary.
func EnforceMinProtocol(env SignedEnvelope, minProto int) *VerifyError {
	if minProto <= 0 {
		return nil
	}
	if env.Version >= minProto {
		return nil
	}
	return &VerifyError{
		Reason: "protocol_version_too_low",
		Err:    fmt.Errorf("envelope v%d, policy requires >=v%d", env.Version, minProto),
	}
}

// VerifyEnvelope checks the Ed25519 signature of a single signed
// envelope against the given canonical payload bytes. It also
// enforces the clock-skew window relative to opts.Now.
//
// On success, returns the parsed timestamp (ms) and nil. On failure
// returns a *VerifyError whose Reason slug feeds the gate's
// rejection response ("timestamp_invalid", "signature_invalid", etc).
func VerifyEnvelope(env SignedEnvelope, canonical []byte, opts VerifyOptions) (int64, error) {
	if !env.Populated() {
		return 0, &VerifyError{Reason: "envelope_incomplete"}
	}
	ts, err := env.Timestamp()
	if err != nil {
		return 0, &VerifyError{Reason: "timestamp_invalid", Err: err}
	}
	now := time.Now().UTC
	if opts.Now != nil {
		now = opts.Now
	}
	if opts.ClockSkew > 0 {
		drift := now().UnixMilli() - ts
		if drift > int64(opts.ClockSkew/time.Millisecond) ||
			-drift > int64(opts.ClockSkew/time.Millisecond) {
			return 0, &VerifyError{
				Reason: "timestamp_out_of_range",
				Err:    fmt.Errorf("drift_ms=%d skew_ms=%d", drift, int64(opts.ClockSkew/time.Millisecond)),
			}
		}
	}

	pubBytes, err := DecodeBase58(env.Pubkey)
	if err != nil {
		return 0, &VerifyError{Reason: "pubkey_invalid", Err: err}
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return 0, &VerifyError{
			Reason: "pubkey_invalid",
			Err:    fmt.Errorf("want %d bytes, got %d", ed25519.PublicKeySize, len(pubBytes)),
		}
	}
	sigBytes, err := DecodeBase58(env.Signature)
	if err != nil {
		return 0, &VerifyError{Reason: "signature_invalid", Err: err}
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return 0, &VerifyError{
			Reason: "signature_invalid",
			Err:    fmt.Errorf("want %d bytes, got %d", ed25519.SignatureSize, len(sigBytes)),
		}
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), canonical, sigBytes) {
		return 0, &VerifyError{Reason: "signature_invalid", Err: errors.New("ed25519 verify failed")}
	}
	return ts, nil
}
