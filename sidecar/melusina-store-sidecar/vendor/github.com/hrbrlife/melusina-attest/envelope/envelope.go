package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const ProtocolV1 = 1

type Kind string

const (
	KindArtifact        Kind = "artifact"
	KindSidecarRequest  Kind = "sidecar-request"
	KindSidecarResponse Kind = "sidecar-response"
	KindCapnp           Kind = "capnp"
	KindSensitiveAction Kind = "sensitive-action"
)

type ChainEvidence struct {
	ChainID               string   `json:"chain_id"`
	ProgramID             string   `json:"program_id"`
	VerifiedSlot          uint64   `json:"verified_slot"`
	ReleaseEntryPDA       string   `json:"release_entry_pda,omitempty"`
	PearlIdentityPDA      string   `json:"pearl_identity_pda,omitempty"`
	SidecarIdentityPDA    string   `json:"sidecar_identity_pda,omitempty"`
	AppSidecarAuthzPDA    string   `json:"app_sidecar_authz_pda,omitempty"`
	AppCapnpAuthzPDA      string   `json:"app_capnp_authz_pda,omitempty"`
	CrossLicenseHopPDA    string   `json:"cross_license_hop_pda,omitempty"`
	SensitivePolicyPDA    string   `json:"sensitive_policy_pda,omitempty"`
	AdditionalEvidencePDA []string `json:"additional_evidence_pda,omitempty"`
}

type Payload struct {
	Protocol               int             `json:"protocol"`
	Kind                   Kind            `json:"kind"`
	Source                 identity.Public `json:"source"`
	Destination            identity.Public `json:"destination"`
	RequestHashHex         string          `json:"request_hash_hex,omitempty"`
	BodyHashHex            string          `json:"body_hash_hex,omitempty"`
	CiphertextHashHex      string          `json:"ciphertext_hash_hex,omitempty"`
	Method                 string          `json:"method,omitempty"`
	Target                 string          `json:"target,omitempty"`
	LicenseMint            string          `json:"license_mint"`
	Domain                 string          `json:"domain"`
	SidecarID              string          `json:"sidecar_id,omitempty"`
	Nonce                  string          `json:"nonce"`
	TimestampMs            int64           `json:"timestamp_ms"`
	ExpiresAtMs            int64           `json:"expires_at_ms"`
	ChainEvidence          ChainEvidence   `json:"chain_evidence"`
	ApproverSetHashHex     string          `json:"approver_set_hash_hex,omitempty"`
	SensitiveActionHashHex string          `json:"sensitive_action_hash_hex,omitempty"`
}

type Signed struct {
	Payload      Payload `json:"payload"`
	PayloadHash  string  `json:"payload_hash"`
	SignatureB58 string  `json:"signature_b58"`
}

type SignOptions struct {
	Now         time.Time
	TTL         time.Duration
	Nonce       string
	Method      string
	Target      string
	Body        []byte
	BodyHash    string
	RequestHash string
	Chain       ChainEvidence
}

type VerifyOptions struct {
	Now                 time.Time
	ClockSkew           time.Duration
	ExpectedKind        Kind
	ExpectedSourceKind  identity.Kind
	ExpectedDestination *identity.Public
	ExpectedRequestHash string
	ExpectedLicenseMint string
	ExpectedDomain      string
	ExpectedSidecarID   string
	NonceCache          NonceCache
}

type NonceCache interface {
	Claim(scope, nonce string, expiresAt time.Time) bool
}

func Sign(kind Kind, src *identity.Private, dst identity.Public, opts SignOptions) (Signed, error) {
	if src == nil {
		return Signed{}, errors.New("attest envelope: source identity is nil")
	}
	if err := dst.Validate(); err != nil {
		return Signed{}, fmt.Errorf("destination: %w", err)
	}
	if err := opts.Chain.Validate(); err != nil {
		return Signed{}, err
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.TTL < 0 {
		return Signed{}, errors.New("attest envelope: negative ttl")
	}
	if opts.TTL == 0 {
		opts.TTL = 2 * time.Minute
	}
	if opts.Nonce == "" {
		nonce, err := RandomNonce()
		if err != nil {
			return Signed{}, err
		}
		opts.Nonce = nonce
	}
	srcPub := src.Public()
	bodyHash := opts.BodyHash
	if bodyHash == "" {
		bodyHash = SHA256Hex(opts.Body)
	}
	p := Payload{
		Protocol:       ProtocolV1,
		Kind:           kind,
		Source:         srcPub,
		Destination:    dst,
		RequestHashHex: strings.ToLower(opts.RequestHash),
		BodyHashHex:    strings.ToLower(bodyHash),
		Method:         strings.ToUpper(opts.Method),
		Target:         opts.Target,
		LicenseMint:    srcPub.Ref.LicenseMint,
		Domain:         srcPub.Ref.Domain,
		SidecarID:      firstNonEmpty(srcPub.Ref.SidecarID, dst.Ref.SidecarID),
		Nonce:          opts.Nonce,
		TimestampMs:    opts.Now.UnixMilli(),
		ExpiresAtMs:    opts.Now.Add(opts.TTL).UnixMilli(),
		ChainEvidence:  opts.Chain,
	}
	return signPayload(src, p)
}

func SignPayload(src *identity.Private, p Payload) (Signed, error) {
	return signPayload(src, p)
}

func Verify(s Signed, opts VerifyOptions) error {
	if err := validatePayload(s.Payload); err != nil {
		return err
	}
	if opts.ExpectedKind != "" && s.Payload.Kind != opts.ExpectedKind {
		return errors.New("attest envelope: kind mismatch")
	}
	if opts.ExpectedSourceKind != "" && s.Payload.Source.Ref.Kind != opts.ExpectedSourceKind {
		return errors.New("attest envelope: source kind mismatch")
	}
	if opts.ExpectedDestination != nil && opts.ExpectedDestination.Digest() != s.Payload.Destination.Digest() {
		return errors.New("attest envelope: destination mismatch")
	}
	if opts.ExpectedRequestHash != "" && s.Payload.RequestHashHex != strings.ToLower(opts.ExpectedRequestHash) {
		return errors.New("attest envelope: request hash mismatch")
	}
	if opts.ExpectedLicenseMint != "" && s.Payload.LicenseMint != opts.ExpectedLicenseMint {
		return errors.New("attest envelope: license mismatch")
	}
	if opts.ExpectedDomain != "" && s.Payload.Domain != opts.ExpectedDomain {
		return errors.New("attest envelope: domain mismatch")
	}
	if opts.ExpectedSidecarID != "" && s.Payload.SidecarID != opts.ExpectedSidecarID {
		return errors.New("attest envelope: sidecar mismatch")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	skew := opts.ClockSkew
	if skew == 0 {
		skew = 2 * time.Minute
	}
	if s.Payload.TimestampMs > now.Add(skew).UnixMilli() {
		return errors.New("attest envelope: timestamp in future")
	}
	if s.Payload.ExpiresAtMs < now.Add(-skew).UnixMilli() {
		return errors.New("attest envelope: expired")
	}
	if s.SignatureB58 == "" {
		return errors.New("attest envelope: missing signature")
	}
	msg, err := CanonicalPayload(s.Payload)
	if err != nil {
		return err
	}
	hash := SHA256Hex(msg)
	if s.PayloadHash != hash {
		return errors.New("attest envelope: payload hash mismatch")
	}
	sig, err := primitives.DecodeBase58(s.SignatureB58)
	if err != nil {
		return err
	}
	if !s.Payload.Source.Verify(msg, sig) {
		return errors.New("attest envelope: signature invalid")
	}
	if opts.NonceCache != nil {
		scope := s.Payload.Source.DigestHex() + "|" + s.Payload.Destination.DigestHex()
		if !opts.NonceCache.Claim(scope, s.Payload.Nonce, time.UnixMilli(s.Payload.ExpiresAtMs)) {
			return errors.New("attest envelope: nonce replay")
		}
	}
	return nil
}

func CanonicalPayload(p Payload) ([]byte, error) {
	fields := []string{
		fmt.Sprintf("%d", p.Protocol),
		string(p.Kind),
		p.Source.DigestHex(),
		p.Destination.DigestHex(),
		p.RequestHashHex,
		p.BodyHashHex,
		p.CiphertextHashHex,
		p.Method,
		p.Target,
		p.LicenseMint,
		p.Domain,
		p.SidecarID,
		p.Nonce,
		fmt.Sprintf("%d", p.TimestampMs),
		fmt.Sprintf("%d", p.ExpiresAtMs),
		p.ChainEvidence.ChainID,
		p.ChainEvidence.ProgramID,
		fmt.Sprintf("%d", p.ChainEvidence.VerifiedSlot),
		p.ChainEvidence.ReleaseEntryPDA,
		p.ChainEvidence.PearlIdentityPDA,
		p.ChainEvidence.SidecarIdentityPDA,
		p.ChainEvidence.AppSidecarAuthzPDA,
		p.ChainEvidence.AppCapnpAuthzPDA,
		p.ChainEvidence.CrossLicenseHopPDA,
		p.ChainEvidence.SensitivePolicyPDA,
		strings.Join(p.ChainEvidence.AdditionalEvidencePDA, ","),
		p.ApproverSetHashHex,
		p.SensitiveActionHashHex,
	}
	out := make([]byte, 0, 512)
	out = append(out, []byte("melusina-attest-envelope-v1")...)
	for _, f := range fields {
		out = appendLen(out, []byte(f))
	}
	return out, nil
}

func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func RandomNonce() (string, error) {
	b := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (c ChainEvidence) Validate() error {
	if c.ChainID == "" {
		return errors.New("attest envelope: chain evidence chain_id is required")
	}
	if c.ProgramID == "" {
		return errors.New("attest envelope: chain evidence program_id is required")
	}
	if c.VerifiedSlot == 0 {
		return errors.New("attest envelope: chain evidence verified_slot is required")
	}
	return nil
}

func signPayload(src *identity.Private, p Payload) (Signed, error) {
	if src == nil {
		return Signed{}, errors.New("attest envelope: source identity is nil")
	}
	if err := validatePayload(p); err != nil {
		return Signed{}, err
	}
	srcPub := src.Public()
	if srcPub.Digest() != p.Source.Digest() {
		return Signed{}, errors.New("attest envelope: signer does not match payload source")
	}
	msg, err := CanonicalPayload(p)
	if err != nil {
		return Signed{}, err
	}
	sig := src.Sign(msg)
	if len(sig) != ed25519.SignatureSize {
		return Signed{}, errors.New("attest envelope: bad ed25519 signature size")
	}
	return Signed{
		Payload:      p,
		PayloadHash:  SHA256Hex(msg),
		SignatureB58: primitives.EncodeBase58(sig),
	}, nil
}

func validatePayload(p Payload) error {
	if p.Protocol != ProtocolV1 {
		return fmt.Errorf("attest envelope: unsupported protocol %d", p.Protocol)
	}
	if p.Kind == "" {
		return errors.New("attest envelope: kind is required")
	}
	if err := p.Source.Validate(); err != nil {
		return fmt.Errorf("source: %w", err)
	}
	if err := p.Destination.Validate(); err != nil {
		return fmt.Errorf("destination: %w", err)
	}
	if p.LicenseMint == "" || p.LicenseMint != p.Source.Ref.LicenseMint {
		return errors.New("attest envelope: source license binding mismatch")
	}
	if p.Domain == "" || p.Domain != p.Source.Ref.Domain {
		return errors.New("attest envelope: source domain binding mismatch")
	}
	if p.SidecarID != "" &&
		p.Source.Ref.SidecarID != p.SidecarID &&
		p.Destination.Ref.SidecarID != p.SidecarID {
		return errors.New("attest envelope: sidecar binding mismatch")
	}
	if p.Nonce == "" {
		return errors.New("attest envelope: nonce is required")
	}
	if p.TimestampMs <= 0 || p.ExpiresAtMs <= p.TimestampMs {
		return errors.New("attest envelope: invalid timestamp window")
	}
	if err := p.ChainEvidence.Validate(); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"request_hash_hex":          p.RequestHashHex,
		"body_hash_hex":             p.BodyHashHex,
		"ciphertext_hash_hex":       p.CiphertextHashHex,
		"approver_set_hash_hex":     p.ApproverSetHashHex,
		"sensitive_action_hash_hex": p.SensitiveActionHashHex,
	} {
		if value != "" && !isSHA256Hex(value) {
			return fmt.Errorf("attest envelope: %s must be lowercase sha256 hex", name)
		}
	}
	return nil
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func appendLen(dst, b []byte) []byte {
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(b)))
	dst = append(dst, lenBuf[:]...)
	return append(dst, b...)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
