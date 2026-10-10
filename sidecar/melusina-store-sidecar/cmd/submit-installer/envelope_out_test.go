package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerpublish"
)

// envelopeOutFixture is one off-host signing setup: a release publisher key,
// the Store operator identity the envelope is addressed to, one member and a
// listener that records whether anything contacted it.
type envelopeOutFixture struct {
	publisher     *identity.Private
	operator      *identity.Private
	dir           string
	artifact      []byte
	artifactPath  string
	publisherPath string
	operatorPath  string
	envelopePath  string
	server        *httptest.Server
	contacted     bool
}

const (
	envelopeOutClass = "shell"
	envelopeOutName  = "0f343b0931126a20f133d67c2b018a3b5b6f0e5e2a8c1d74b3c0b2b6a7f0e1d2-melusina-installer.tar.xz"
)

func newEnvelopeOutFixture(t *testing.T) *envelopeOutFixture {
	t.Helper()
	publisher, signSeed, boxSeed := testPrivate(t, "release-publisher")
	operator, _, _ := testPrivate(t, "store")
	f := &envelopeOutFixture{publisher: publisher, operator: operator, dir: t.TempDir(),
		artifact: []byte("generation-one installer member bytes")}
	f.server = httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { f.contacted = true }))
	t.Cleanup(f.server.Close)
	f.artifactPath = filepath.Join(f.dir, "member.tar.xz")
	f.publisherPath = filepath.Join(f.dir, "publisher.json")
	f.operatorPath = filepath.Join(f.dir, "operator.json")
	f.envelopePath = filepath.Join(f.dir, "out", "installer-envelope.json")
	if err := os.WriteFile(f.artifactPath, f.artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	publisherJSON, err := json.Marshal(publisherKeyFile{Ref: publisher.Public().Ref,
		SignSeed: hex.EncodeToString(signSeed[:]), BoxSeed: hex.EncodeToString(boxSeed[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.publisherPath, publisherJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	operatorJSON, err := json.Marshal(operator.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.operatorPath, operatorJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *envelopeOutFixture) args(extra ...string) []string {
	args := []string{
		"--store", f.server.URL,
		"--class", envelopeOutClass,
		"--name", envelopeOutName,
		"--artifact", f.artifactPath,
		"--publisher-key", f.publisherPath,
		"--store-pubkey", f.operatorPath,
		"--store-id", "test-store",
		"--store-domain", "store.example",
		"--license-mint", f.operator.Public().Ref.LicenseMint,
		"--program-id", testProgramID,
		"--verified-slot", "123",
		"--envelope-out", f.envelopePath,
	}
	return append(args, extra...)
}

func (f *envelopeOutFixture) artifactSHA256() string {
	sum := sha256.Sum256(f.artifact)
	return hex.EncodeToString(sum[:])
}

type envelopeOutReport struct {
	Status          string `json:"status"`
	EnvelopePath    string `json:"envelopePath"`
	EnvelopeSHA256  string `json:"envelopeSha256"`
	Class           string `json:"class"`
	Name            string `json:"name"`
	ArtifactSHA256  string `json:"artifactSha256"`
	BindingSHA256   string `json:"bindingSha256"`
	SignerPubkeyB58 string `json:"signerPubkeyB58"`
	Target          string `json:"target"`
	ExpiresAtMs     int64  `json:"expiresAtMs"`
}

// Positive: --envelope-out signs the exact /publish/installer envelope the
// Store gate verifies, writes it privately and contacts nothing. The written
// bytes are the multipart "envelope" part, so the Store host sends them as
// they are.
func TestEnvelopeOutSignsWithoutContactingTheStore(t *testing.T) {
	f := newEnvelopeOutFixture(t)
	var stdout bytes.Buffer
	if err := run(f.args("--timeout", "48m"), &stdout); err != nil {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_POSITIVE: %v", err)
	}
	if f.contacted {
		t.Fatal("INSTALLER_ENVELOPE_OUT_CONTACTED_STORE: envelope-only signing reached the Store")
	}
	raw, err := os.ReadFile(f.envelopePath)
	if err != nil {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_NOT_WRITTEN: %v", err)
	}
	info, err := os.Stat(f.envelopePath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_MODE: %v %v", info, err)
	}
	if len(raw) == 0 || len(raw) > maxEnvelopeBytes {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_SIZE: %d bytes", len(raw))
	}
	var report envelopeOutReport
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_REPORT: %v", err)
	}
	rawSum := sha256.Sum256(raw)
	binding, err := installerpublish.Digest(envelopeOutClass, envelopeOutName, f.artifactSHA256(),
		"test-store", "store.example", f.operator.Public().Ref.LicenseMint, testProgramID)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "SIGNED_INSTALLER_ENVELOPE_OK" || report.EnvelopePath != f.envelopePath ||
		report.EnvelopeSHA256 != hex.EncodeToString(rawSum[:]) || report.Class != envelopeOutClass ||
		report.Name != envelopeOutName || report.ArtifactSHA256 != f.artifactSHA256() ||
		report.BindingSHA256 != binding || report.SignerPubkeyB58 != f.publisher.Public().SignPubkeyB58 ||
		report.Target != installerpublish.Target {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_REPORT_MISMATCH: %+v", report)
	}

	// The file is the bare signed envelope (the multipart part), not a
	// wrapper around it: it decodes strictly as envelope.Signed.
	var signed envelope.Signed
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if err := strict.Decode(&signed); err != nil {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_NOT_AN_ENVELOPE: %v", err)
	}
	operator := f.operator.Public()
	if err := envelope.Verify(signed, envelope.VerifyOptions{
		ExpectedKind:            envelope.KindPublishRequest,
		ExpectedSignerPubkeyB58: f.publisher.Public().SignPubkeyB58,
		ExpectedDestination:     &operator,
		ExpectedRequestHash:     f.artifactSHA256(),
		NonceCache:              envelope.NewMemoryNonceCache(),
	}); err != nil {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_DOES_NOT_VERIFY: %v", err)
	}
	if signed.Payload.Method != http.MethodPost || signed.Payload.Target != installerpublish.Target ||
		signed.Payload.BodyHashHex != binding || signed.Payload.RequestHashHex != f.artifactSHA256() {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_BINDING: method=%s target=%s body=%s request=%s",
			signed.Payload.Method, signed.Payload.Target, signed.Payload.BodyHashHex, signed.Payload.RequestHashHex)
	}
	if signed.Payload.ChainEvidence.ProgramID != testProgramID || signed.Payload.ChainEvidence.ChainID != testChainID ||
		signed.Payload.ChainEvidence.VerifiedSlot != 123 {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_CHAIN_EVIDENCE: %+v", signed.Payload.ChainEvidence)
	}
	if lifetime := signed.Payload.ExpiresAtMs - signed.Payload.TimestampMs; lifetime != (50 * time.Minute).Milliseconds() {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_LIFETIME: %d ms, want --timeout 48m plus two minutes", lifetime)
	}
	if report.ExpiresAtMs != signed.Payload.ExpiresAtMs {
		t.Fatalf("INSTALLER_ENVELOPE_OUT_REPORT_EXPIRY: report %d envelope %d", report.ExpiresAtMs, signed.Payload.ExpiresAtMs)
	}
}

// Negative: an absent, empty or unusable input is refused by name before any
// envelope is written and before anything is contacted.
func TestEnvelopeOutRefusesAbsentInputsByName(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(t *testing.T, f *envelopeOutFixture) []string
		want   string
	}{
		"absent-artifact": {func(t *testing.T, f *envelopeOutFixture) []string {
			f.artifactPath = filepath.Join(f.dir, "absent.tar.xz")
			return f.args()
		}, refuseArtifact + ": read --artifact"},
		"empty-artifact": {func(t *testing.T, f *envelopeOutFixture) []string {
			if err := os.WriteFile(f.artifactPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return f.args()
		}, refuseArtifact + ": artifact is empty"},
		"absent-publisher-key": {func(t *testing.T, f *envelopeOutFixture) []string {
			f.publisherPath = filepath.Join(f.dir, "absent-publisher.json")
			return f.args()
		}, refusePublisherKey + ":"},
		"unsigned-publisher-key": {func(t *testing.T, f *envelopeOutFixture) []string {
			raw, err := json.Marshal(map[string]any{"ref": f.publisher.Public().Ref, "box_seed_hex": strings.Repeat("11", 32)})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.publisherPath, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			return f.args()
		}, refusePublisherKey + ": sign_seed_hex"},
		"absent-store-pubkey": {func(t *testing.T, f *envelopeOutFixture) []string {
			f.operatorPath = filepath.Join(f.dir, "absent-operator.json")
			return f.args()
		}, refuseStorePubkey + ":"},
		"lifetime-above-store-ceiling": {func(t *testing.T, f *envelopeOutFixture) []string {
			return f.args("--timeout", "59m")
		}, refuseLifetime + ":"},
		"unwritable-envelope-out": {func(t *testing.T, f *envelopeOutFixture) []string {
			blocker := filepath.Join(f.dir, "not-a-directory")
			if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			f.envelopePath = filepath.Join(blocker, "installer-envelope.json")
			return f.args()
		}, refuseEnvelopeOut + ":"},
		"absent-store-audience": {func(t *testing.T, f *envelopeOutFixture) []string {
			args := f.args()
			for index := range args {
				if args[index] == "--store-domain" {
					return append(append([]string{}, args[:index]...), args[index+2:]...)
				}
			}
			t.Fatal("fixture lost --store-domain")
			return nil
		}, "missing required flag(s): --store-domain"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newEnvelopeOutFixture(t)
			args := tc.mutate(t, f)
			var stdout bytes.Buffer
			err := run(args, &stdout)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("INSTALLER_ENVELOPE_OUT_ABSENT_INPUT_ACCEPTED/%s: error = %v, want %q", name, err, tc.want)
			}
			if _, statErr := os.Stat(f.envelopePath); statErr == nil {
				t.Fatalf("INSTALLER_ENVELOPE_OUT_WRITTEN_ON_REFUSAL/%s: %s exists", name, f.envelopePath)
			}
			if f.contacted || stdout.Len() != 0 {
				t.Fatalf("INSTALLER_ENVELOPE_OUT_REFUSAL_HAD_EFFECT/%s: contacted=%t stdout=%q", name, f.contacted, stdout.String())
			}
		})
	}
}

// Negative: the self-verification refuses, by name, an envelope that is
// unsigned, tampered, signed by another key or validly signed for another
// member. Positive control: the untouched envelope passes and yields the
// Store's binding digest, so every refusal below is the check's own.
func TestEnvelopeSelfVerifyRefusesUnboundOrUnsignedEnvelopes(t *testing.T) {
	f := newEnvelopeOutFixture(t)
	o, err := parseFlags(f.args())
	if err != nil {
		t.Fatal(err)
	}
	operator := f.operator.Public()
	sign := func(t *testing.T, signer *identity.Private, name string) envelope.Signed {
		t.Helper()
		signed, err := installerpublish.Sign(signer, operator, o.class, name, f.artifactSHA256(),
			o.storeID, o.storeDomain, o.licenseMint, o.programID, 123, 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	good := sign(t, f.publisher, o.name)
	binding, err := verifySignedInstallerEnvelope(good, f.publisher.Public(), operator, o, f.artifactSHA256())
	if err != nil {
		t.Fatalf("INSTALLER_ENVELOPE_SELF_VERIFY_POSITIVE: %v", err)
	}
	want, err := installerpublish.Digest(o.class, o.name, f.artifactSHA256(), o.storeID, o.storeDomain, o.licenseMint, o.programID)
	if err != nil || binding != want {
		t.Fatalf("INSTALLER_ENVELOPE_SELF_VERIFY_POSITIVE_BINDING: %s want %s (%v)", binding, want, err)
	}
	other, _, _ := testPrivate(t, "unnamed-publisher")
	unsigned := good
	unsigned.SignatureB58 = ""
	otherTarget := good
	otherTarget.Payload.Target = "/publish/generation"
	otherArtifact := good
	otherArtifact.Payload.RequestHashHex = strings.Repeat("ab", 32)
	tamperedExpiry := good
	tamperedExpiry.Payload.ExpiresAtMs += 1000
	for name, tc := range map[string]struct {
		signed envelope.Signed
		want   string
	}{
		"unsigned": {
			signed: unsigned,
			want:   "carries no signature",
		},
		"other-member": {
			signed: sign(t, f.publisher, "other-member.tar.xz"),
			want:   "does not bind POST",
		},
		"other-target": {
			signed: otherTarget,
			want:   "does not bind POST",
		},
		"other-artifact": {
			signed: otherArtifact,
			want:   "does not bind POST",
		},
		"other-signer": {
			signed: sign(t, other, o.name),
			want:   refuseSelfVerify + ":",
		},
		"tampered-expiry": {
			signed: tamperedExpiry,
			want:   refuseSelfVerify + ":",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := verifySignedInstallerEnvelope(tc.signed, f.publisher.Public(), operator, o, f.artifactSHA256())
			if err == nil || !strings.HasPrefix(err.Error(), refuseSelfVerify+":") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("INSTALLER_ENVELOPE_SELF_VERIFY_ACCEPTED/%s: error = %v, want %q", name, err, tc.want)
			}
		})
	}
}
