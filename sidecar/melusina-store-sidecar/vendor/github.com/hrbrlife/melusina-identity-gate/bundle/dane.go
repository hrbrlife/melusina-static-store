package bundle

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Sentinel errors raised by DANECrossCheck. Callers branch on these
// via errors.Is to distinguish the "DNS says nothing" path (operator
// hasn't published the TLSA pin yet) from the "DNS says something
// different" path (active mismatch — the bundle MUST be refused).
var (
	// ErrDANENotPublished means the resolver returned NoData / NXDomain
	// for `_443._tcp.<host> TLSA`. Distinct from mismatch — production
	// callers may choose to fail-closed (Inv 5) on missing pins, or
	// log + continue if the install is still in pre-pin-rollout. The
	// helper does NOT make that policy decision; it surfaces the
	// distinction so the caller can.
	ErrDANENotPublished = errors.New("DANE: no TLSA records published")

	// ErrDANEMismatch means at least one TLSA record was published
	// but none of them carries the expected (3, 0|1, 1, fingerprint)
	// shape. This is an active integrity failure — fail closed.
	ErrDANEMismatch = errors.New("DANE: published TLSA does not match LicenseEntry.tls_cert_fingerprint")

	// ErrDANEResolverFailure wraps any DNS lookup error. Treated as
	// fail-closed by the bundle loader's production path (Inv 5: no
	// "last known good" fallback).
	ErrDANEResolverFailure = errors.New("DANE: resolver failure")
)

// daneAcceptedUsage is the only RFC 7671 usage value the comparator
// honours: 3 = "DANE-EE — Domain-Issued Certificate". Other usage
// values may be legal in DNS but are not bound to a Melusina §1
// invariant; treating them as license-pin proofs would let an
// operator-supplied "1 1 1" record (PKIX-CA) bypass the on-chain pin
// in exchange for "any cert under our intermediate". (Inv 5: no
// implicit cross-shape trust.)
const daneAcceptedUsage = 3

// daneAcceptedMatching is matching-type 1 (SHA-256). Selector 0
// (full cert) and selector 1 (SubjectPublicKeyInfo) are both
// accepted — they hash different bytes but each yield 32-byte
// digests. The bundle's tls_cert_fingerprint pin is sha256(cert.DER),
// so selector=0 records compare directly. selector=1 records require
// the install to have advertised the SPKI hash too — covered by
// DANEExpectedFingerprints.
const daneAcceptedMatching = 1

// TLSARecord is the parsed RDATA tuple. Fields mirror the DNS wire
// format exactly so callers (operator UIs) can render the published
// values for inspection.
type TLSARecord struct {
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Data         []byte
}

// Resolver is the minimal DNS-lookup interface DANECrossCheck needs.
// Production callers pass net.DefaultResolver; tests inject a fake.
//
// The signature mirrors net.Resolver.LookupTXT — TLSA is a separate
// RR type, so we expose it through an opaque LookupTLSA method that
// returns parsed records.
type Resolver interface {
	LookupTLSA(ctx context.Context, fqdn string) ([]TLSARecord, error)
}

// DefaultResolver wraps net.Resolver with a TLSA helper built on
// LookupTXT semantics — Go's net package doesn't ship a typed TLSA
// helper, so we issue a raw query via the system resolver's miekg-style
// interface where available, falling back to a TXT lookup of a
// neighbour record only if no TLSA RR is observable from this
// process. In production the caller MAY substitute a richer resolver
// (e.g. github.com/miekg/dns) — keep this fallback dependency-free
// so the identity-gate stays at standard-library + golang.org/x/crypto.
type DefaultResolver struct {
	// Underlying is the net.Resolver used for the initial cgo /
	// pure-Go lookup. nil → net.DefaultResolver.
	Underlying *net.Resolver

	// Timeout caps each lookup; defaults to 5s when zero.
	Timeout time.Duration
}

// LookupTLSA queries `_443._tcp.<fqdn>` for TLSA records. Because
// Go's net.Resolver does not expose TLSA directly, we resolve the
// name to its canonical form and then issue a NS-query-shaped
// LookupNS-style probe — but that does not return RDATA either.
//
// TRADE-OFF: shipping a TLSA-typed lookup without a third-party DNS
// library means we either (a) shell out to `dig` (operationally
// fragile, depends on dig being on PATH inside every consuming
// binary) or (b) issue raw UDP packets ourselves (significant code
// surface for an MVP).
//
// For the MVP we take option (a): fork `dig +short TLSA` against the
// system's configured resolver. The verifier-side cross-check is the
// load-bearing surface; the resolver implementation is a swappable
// boundary. Production callers running inside grain sandboxes (where
// dig is not present) MUST inject a richer resolver via
// DANECrossCheckWithResolver.
func (d *DefaultResolver) LookupTLSA(ctx context.Context, fqdn string) ([]TLSARecord, error) {
	timeout := d.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	subCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return digTLSA(subCtx, fqdn)
}

// DANECrossCheck queries `_443._tcp.<host> TLSA` via the system
// resolver and asserts that at least one record matches the expected
// (3, 0|1, 1, sha256(tls_cert_fingerprint)) shape. Returns
// ErrDANENotPublished if the lookup succeeded but yielded no TLSA
// records, ErrDANEMismatch if records exist but none carry the
// expected fingerprint, and ErrDANEResolverFailure on a transport
// error.
//
// Production paths under `dev_permissive=false` MUST treat all three
// non-nil returns as fail-closed (Inv 5).
func DANECrossCheck(ctx context.Context, host string, tlsCertFingerprint [32]byte) error {
	return DANECrossCheckWithResolver(ctx, &DefaultResolver{}, host, tlsCertFingerprint)
}

// DANECrossCheckWithResolver is the testable / dependency-injectable
// form of DANECrossCheck. Pass a Resolver implementation to make
// the lookup observable in tests or to plug in a richer DNS library
// (github.com/miekg/dns) inside production binaries that cannot
// shell out to `dig`.
func DANECrossCheckWithResolver(ctx context.Context, r Resolver, host string, tlsCertFingerprint [32]byte) error {
	if r == nil {
		return errors.New("DANECrossCheck: nil resolver")
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return errors.New("DANECrossCheck: empty host")
	}
	fqdn := "_443._tcp." + host
	records, err := r.LookupTLSA(ctx, fqdn)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDANEResolverFailure, err)
	}
	if len(records) == 0 {
		return fmt.Errorf("%w: %s", ErrDANENotPublished, fqdn)
	}
	wantHex := hex.EncodeToString(tlsCertFingerprint[:])
	for _, rec := range records {
		if rec.Usage != daneAcceptedUsage {
			continue
		}
		if rec.Selector != 0 && rec.Selector != 1 {
			continue
		}
		if rec.MatchingType != daneAcceptedMatching {
			continue
		}
		if hex.EncodeToString(rec.Data) == wantHex {
			return nil
		}
	}
	// Render the published RDATA tuples for diagnostic output so
	// operators don't have to dig manually to figure out which record
	// disagreed.
	var got []string
	for _, rec := range records {
		got = append(got, fmt.Sprintf("%d %d %d %s",
			rec.Usage, rec.Selector, rec.MatchingType, hex.EncodeToString(rec.Data)))
	}
	return fmt.Errorf("%w: fqdn=%s want=%s published=[%s]",
		ErrDANEMismatch, fqdn, wantHex, strings.Join(got, "; "))
}

// CrossCheckDANE asserts that for each FQDN bound to this install
// (Install.Domain, plus any AllowedHosts), the published TLSA RDATA
// at `_443._tcp.<fqdn>` includes a (3, 0|1, 1, fingerprint) record
// matching the bundle's own TLSFingerprintSHA256 pin. This is the
// runtime cross-check referenced in MVP_AUDIT_PUNCHLIST A5.
//
// `resolver` may be nil — DefaultResolver kicks in. Pass an injected
// Resolver in tests or in sandboxed binaries that cannot fork dig.
//
// Returns nil if every host either matches OR returns
// ErrDANENotPublished AND skipNotPublished is true. Any
// ErrDANEMismatch / ErrDANEResolverFailure is fatal — the bundle
// MUST be refused (Inv 5: fail closed).
//
// The skipNotPublished knob accommodates installs in the middle of
// rolling out DANE pins: an install that has set
// LicenseEntry.tls_cert_fingerprint on chain but hasn't yet
// published the TLSA records will fail with ErrDANENotPublished
// indefinitely otherwise. Production loaders for `dev_permissive=false`
// installs SHOULD pass skipNotPublished=false; staged-rollout
// loaders MAY pass true and treat the missing-pin case as a logged
// warning.
func (l *Loaded) CrossCheckDANE(ctx context.Context, resolver Resolver, skipNotPublished bool) error {
	if l == nil {
		return errors.New("CrossCheckDANE: nil Loaded")
	}
	b := &l.Bundle
	if strings.TrimSpace(b.Install.TLSFingerprintSHA256) == "" {
		return fmt.Errorf("%w: install.tls_fingerprint_sha256",
			ErrCrossCheckMissingField)
	}
	wantBytes, err := hex.DecodeString(strings.ToLower(b.Install.TLSFingerprintSHA256))
	if err != nil || len(wantBytes) != 32 {
		return fmt.Errorf("install.tls_fingerprint_sha256: must be 32-byte hex, got %d bytes (err=%v)",
			len(wantBytes), err)
	}
	var fp [32]byte
	copy(fp[:], wantBytes)

	if resolver == nil {
		resolver = &DefaultResolver{}
	}

	hosts := []string{b.Install.Domain}
	hosts = append(hosts, b.Install.AllowedHosts...)
	seen := map[string]bool{}
	for _, h := range hosts {
		h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		err := DANECrossCheckWithResolver(ctx, resolver, h, fp)
		if err == nil {
			continue
		}
		if errors.Is(err, ErrDANENotPublished) && skipNotPublished {
			continue
		}
		return err
	}
	return nil
}

// digTLSA shells out to `dig +short TLSA <fqdn>` and parses the
// canonical RDATA tuples. dig's +short output for TLSA is one record
// per line, fields space-separated:
//
//   3 1 1 <hex>
//   3 0 1 <hex>
//
// Returns the parsed records or an error suitable for wrapping in
// ErrDANEResolverFailure / ErrDANENotPublished.
func digTLSA(ctx context.Context, fqdn string) ([]TLSARecord, error) {
	out, err := execDig(ctx, fqdn)
	if err != nil {
		return nil, err
	}
	var recs []TLSARecord
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		usage, err := strconv.ParseUint(fields[0], 10, 8)
		if err != nil {
			continue
		}
		selector, err := strconv.ParseUint(fields[1], 10, 8)
		if err != nil {
			continue
		}
		matching, err := strconv.ParseUint(fields[2], 10, 8)
		if err != nil {
			continue
		}
		data, err := hex.DecodeString(strings.ToLower(strings.Join(fields[3:], "")))
		if err != nil {
			continue
		}
		recs = append(recs, TLSARecord{
			Usage:        uint8(usage),
			Selector:     uint8(selector),
			MatchingType: uint8(matching),
			Data:         data,
		})
	}
	return recs, nil
}
