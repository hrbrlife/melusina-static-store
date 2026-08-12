// Package runtimecontract validates the release-bound runtime contract carried
// with every new Melusina app publish.
//
// A ReleaseEntry proves the exact SPK+metadata tree that may be served.  It
// deliberately says nothing about whether an app can actually do its job once
// it opens.  This contract fills that separate, operational gap without
// weakening the on-chain artifact gate:
//
//	SPK + metadata --AppHash--> Active ReleaseEntry
//	RELEASE.json --publisher envelope--> runtimeContractSha256
//	RUNTIME-CONTRACT.json --spkSha256--> exact SPK
//
// The contract is a declaration, not a test result.  A catalog must therefore
// label it "declared" until a separate visible-UI acceptance run records the
// real result.  Releases that predate this contract remain installable but are
// explicitly "uncertified"; they are never silently upgraded by this package.
package runtimecontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	// Schema is the stable, versioned contract identifier.  A new shape needs a
	// new identifier and validator; accepting unknown shapes as v1 would turn a
	// release gate into a best-effort hint.
	Schema = "melusina-app-runtime-contract-v1"
	// SchemaURL is served by the Bazaar alongside the catalog schema so humans
	// and tooling can resolve the exact contract shape offline from the store.
	SchemaURL = "https://bazaar.melusina-os.org/schemas/melusina-app-runtime-contract-v1.schema.json"
)

// ErrEmpty is returned only when a RELEASE.json claims a runtime contract but
// the corresponding raw artifact is absent. Callers may use it to quarantine
// that already-unservable historical selection; they must never treat it as an
// uncertified legacy release or synthesize contract bytes.
var ErrEmpty = errors.New("runtime contract is empty")

var (
	hex64RE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sidecarIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	// Canonical sidecar names are deliberately a closed address family.  A
	// contract may select the documented target tier for the deployment, but it
	// cannot redirect a grain to an arbitrary Internet hostname, IP, localhost,
	// wildcard, URL path, or query string.
	hostRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.sidecar\.(?:host|hypervisor(?:\.shared)?|local|remote(?:\.shared)?)$`)
)

// Contract is deliberately small and declarative.  It contains no credential,
// URL query, bearer token, or opaque "run this command" field.  Actual QA uses
// the recorded visible actions and controlled fixtures after installation.
type Contract struct {
	SchemaURL   string       `json:"$schema"`
	Schema      string       `json:"schema"`
	App         App          `json:"app"`
	Sidecars    []Sidecar    `json:"sidecars"`
	LaunchProbe VisibleProbe `json:"launchProbe"`
	Fixtures    []Fixture    `json:"fixtures"`
	Cleanup     Cleanup      `json:"cleanup"`
}

type App struct {
	AppID     string `json:"appId"`
	Version   string `json:"version"`
	SPKSHA256 string `json:"spkSha256"`
	AppHash   string `json:"appHash"`
}

// Sidecar names one required target. The endpoint is the explicit tuple
// https://Host:Port, not a free-form URL: no path, query, fragment, wildcard,
// IP address, localhost alias, or insecure TLS escape hatch can be smuggled
// into a release contract. Host is restricted to the deployment's documented
// canonical sidecar name tiers (.host, .hypervisor, .hypervisor.shared, .local,
// .remote, or .remote.shared).
type Sidecar struct {
	ID           string         `json:"id"`
	Host         string         `json:"host"`
	Port         int            `json:"port"`
	Transport    string         `json:"transport"`
	TLS          TLSRequirement `json:"tls"`
	Capabilities []string       `json:"capabilities"`
	SafeProbe    SidecarProbe   `json:"safeProbe"`
}

type TLSRequirement struct {
	Required       bool   `json:"required"`
	ServerName     string `json:"serverName"`
	Trust          string `json:"trust"`
	MinimumVersion string `json:"minimumVersion"`
}

// VisibleProbe is a browser-visible launch proof.  It intentionally contains
// no hidden API endpoint or direct database action: the acceptance runner must
// exercise the same UI an administrator uses.
type VisibleProbe struct {
	Kind           string      `json:"kind"`
	Steps          []ProbeStep `json:"steps"`
	ExpectedResult string      `json:"expectedResult"`
}

type ProbeStep struct {
	Action         string `json:"action"`
	ExpectedResult string `json:"expectedResult"`
}

type SidecarProbe struct {
	Action         string `json:"action"`
	ExpectedResult string `json:"expectedResult"`
}

type Fixture struct {
	Name    string `json:"name"`
	Purpose string `json:"purpose"`
	Setup   string `json:"setup"`
}

type Cleanup struct {
	Steps []string `json:"steps"`
}

// Binding is the release/app material that must agree with a contract.  SPK is
// optional only for serve-time validation: the serve gate already recomputes
// the AppHash from the exact streamed SPK, so it may validate the signed
// contract claim without eagerly buffering a large package a second time.
type Binding struct {
	SPK                   []byte
	Metadata              []byte
	AppHash               string
	Version               string
	ReleaseContractSHA256 string
	ReleaseContractSchema string
}

// RequiresContract reports whether a release claims a runtime contract.  A
// half-populated claim is invalid, not a legacy exception.
func RequiresContract(b Binding) bool {
	return strings.TrimSpace(b.ReleaseContractSHA256) != "" || strings.TrimSpace(b.ReleaseContractSchema) != ""
}

// Validate verifies the complete publication-time binding, including
// sha256(SPK).  It is called before a new release is persisted.
func Validate(raw []byte, b Binding) (Contract, error) {
	c, err := ValidateClaim(raw, b)
	if err != nil {
		return Contract{}, err
	}
	if len(b.SPK) == 0 {
		return Contract{}, errors.New("spk is required for publication-time runtime-contract validation")
	}
	got := sha256.Sum256(b.SPK)
	if c.App.SPKSHA256 != hex.EncodeToString(got[:]) {
		return Contract{}, fmt.Errorf("app.spkSha256 %s does not match sha256(spk) %x", c.App.SPKSHA256, got)
	}
	return c, nil
}

// ValidateClaim verifies the signed ReleaseJSON-to-contract binding plus all
// declarative constraints.  It intentionally does not read SPK bytes so a
// serve-time caller can remain streaming; its simultaneous AppHash gate proves
// that the exact served SPK+metadata tree is the ReleaseEntry-bound one.
func ValidateClaim(raw []byte, b Binding) (Contract, error) {
	if !RequiresContract(b) {
		return Contract{}, errors.New("release does not bind a runtime contract")
	}
	if strings.TrimSpace(b.ReleaseContractSchema) != Schema {
		return Contract{}, fmt.Errorf("release.runtimeContractSchema must be %q", Schema)
	}
	wantHash := strings.TrimSpace(b.ReleaseContractSHA256)
	if !isLowerHex64(wantHash) {
		return Contract{}, errors.New("release.runtimeContractSha256 must be 64 lowercase hex characters")
	}
	if len(raw) == 0 {
		return Contract{}, ErrEmpty
	}
	gotHash := sha256.Sum256(raw)
	if wantHash != hex.EncodeToString(gotHash[:]) {
		return Contract{}, fmt.Errorf("sha256(runtime contract)=%x != release.runtimeContractSha256=%s", gotHash, wantHash)
	}

	c, err := decode(raw)
	if err != nil {
		return Contract{}, err
	}
	if err := validateShape(c); err != nil {
		return Contract{}, err
	}
	if err := validateBinding(c, b); err != nil {
		return Contract{}, err
	}
	return c, nil
}

func decode(raw []byte) (Contract, error) {
	var c Contract
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return Contract{}, fmt.Errorf("decode runtime contract: %w", err)
	}
	// json.Decoder accepts one valid JSON value followed by another.  Contracts
	// are signed by their raw hash, so reject trailing values instead of leaving
	// two meanings for different consumers.
	if err := d.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return Contract{}, errors.New("decode runtime contract: trailing JSON value")
		}
		return Contract{}, fmt.Errorf("decode runtime contract trailing data: %w", err)
	}
	return c, nil
}

func validateShape(c Contract) error {
	if c.SchemaURL != SchemaURL {
		return fmt.Errorf("$schema must be %q", SchemaURL)
	}
	if c.Schema != Schema {
		return fmt.Errorf("schema must be %q", Schema)
	}
	if invalidText(c.App.AppID) {
		return errors.New("app.appId is required")
	}
	if invalidText(c.App.Version) {
		return errors.New("app.version is required")
	}
	if !isLowerHex64(c.App.SPKSHA256) {
		return errors.New("app.spkSha256 must be 64 lowercase hex characters")
	}
	if !isLowerHex64(c.App.AppHash) {
		return errors.New("app.appHash must be 64 lowercase hex characters")
	}
	// nil distinguishes omitted from an explicit [] declaration.  A no-sidecar
	// app must say "sidecars": []; it cannot obtain an accidental certification
	// simply by leaving the dependency question unanswered.
	if c.Sidecars == nil {
		return errors.New("sidecars must be present (use [] when none are required)")
	}
	seenIDs := map[string]bool{}
	seenHosts := map[string]bool{}
	for i, s := range c.Sidecars {
		prefix := fmt.Sprintf("sidecars[%d]", i)
		if !sidecarIDRE.MatchString(s.ID) {
			return fmt.Errorf("%s.id must be a lower-case sidecar identifier", prefix)
		}
		if seenIDs[s.ID] {
			return fmt.Errorf("%s.id %q is duplicated", prefix, s.ID)
		}
		seenIDs[s.ID] = true
		if !hostRE.MatchString(s.Host) {
			return fmt.Errorf("%s.host must be an exact lower-case canonical sidecar name", prefix)
		}
		if seenHosts[s.Host] {
			return fmt.Errorf("%s.host %q is duplicated", prefix, s.Host)
		}
		seenHosts[s.Host] = true
		if s.Port < 1 || s.Port > 65535 {
			return fmt.Errorf("%s.port must be an explicit TCP port from 1 through 65535", prefix)
		}
		if s.Transport != "https" {
			return fmt.Errorf("%s.transport must be https", prefix)
		}
		if !s.TLS.Required || s.TLS.ServerName != s.Host || s.TLS.Trust != "system-ca" ||
			(s.TLS.MinimumVersion != "TLS1.2" && s.TLS.MinimumVersion != "TLS1.3") {
			return fmt.Errorf("%s.tls must require system-ca TLS for exactly %s:%d (TLS1.2 or TLS1.3)", prefix, s.Host, s.Port)
		}
		if s.Capabilities == nil || !contains(s.Capabilities, "http-out") {
			return fmt.Errorf("%s.capabilities must explicitly include http-out", prefix)
		}
		if err := validateCapabilityList(s.Capabilities, prefix); err != nil {
			return err
		}
		if invalidText(s.SafeProbe.Action) || invalidText(s.SafeProbe.ExpectedResult) {
			return fmt.Errorf("%s.safeProbe requires non-empty action and expectedResult", prefix)
		}
	}
	if c.LaunchProbe.Kind != "visible-ui" {
		return errors.New("launchProbe.kind must be visible-ui")
	}
	if len(c.LaunchProbe.Steps) == 0 || invalidText(c.LaunchProbe.ExpectedResult) {
		return errors.New("launchProbe requires at least one visible step and an expectedResult")
	}
	for i, step := range c.LaunchProbe.Steps {
		if invalidText(step.Action) || invalidText(step.ExpectedResult) {
			return fmt.Errorf("launchProbe.steps[%d] requires non-empty action and expectedResult", i)
		}
	}
	if c.Fixtures == nil {
		return errors.New("fixtures must be present (use [] when no fixture is needed)")
	}
	for i, f := range c.Fixtures {
		if invalidText(f.Name) || invalidText(f.Purpose) || invalidText(f.Setup) {
			return fmt.Errorf("fixtures[%d] requires non-empty name, purpose, and setup", i)
		}
	}
	if len(c.Cleanup.Steps) == 0 {
		return errors.New("cleanup.steps must explicitly state how test data is removed or why none is retained")
	}
	for i, step := range c.Cleanup.Steps {
		if invalidText(step) {
			return fmt.Errorf("cleanup.steps[%d] is empty", i)
		}
	}
	return nil
}

func validateBinding(c Contract, b Binding) error {
	appID, err := metadataAppID(b.Metadata)
	if err != nil {
		return err
	}
	if c.App.AppID != appID {
		return fmt.Errorf("app.appId %q != metadata.appId %q", c.App.AppID, appID)
	}
	if c.App.Version != strings.TrimSpace(b.Version) {
		return fmt.Errorf("app.version %q != release.version %q", c.App.Version, strings.TrimSpace(b.Version))
	}
	appHash := strings.TrimSpace(b.AppHash)
	if !isLowerHex64(appHash) {
		return errors.New("release.appHash must be 64 lowercase hex characters")
	}
	if c.App.AppHash != appHash {
		return fmt.Errorf("app.appHash %q != release.appHash %q", c.App.AppHash, appHash)
	}
	return nil
}

func metadataAppID(metadata []byte) (string, error) {
	var m struct {
		AppID string `json:"appId"`
	}
	if err := json.Unmarshal(metadata, &m); err != nil {
		return "", fmt.Errorf("parse metadata.json for runtime contract: %w", err)
	}
	m.AppID = strings.TrimSpace(m.AppID)
	if m.AppID == "" {
		return "", errors.New("metadata.json appId is required for runtime contract")
	}
	return m.AppID, nil
}

func isLowerHex64(v string) bool { return hex64RE.MatchString(v) }

func invalidText(v string) bool { return len(strings.TrimSpace(v)) < 3 }

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func validateCapabilityList(values []string, prefix string) error {
	seen := map[string]bool{}
	for _, value := range values {
		if !sidecarIDRE.MatchString(value) {
			return fmt.Errorf("%s.capabilities contains invalid capability %q", prefix, value)
		}
		if seen[value] {
			return fmt.Errorf("%s.capabilities duplicates %q", prefix, value)
		}
		seen[value] = true
	}
	return nil
}
