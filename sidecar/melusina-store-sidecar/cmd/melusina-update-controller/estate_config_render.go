package main

// Profile-bound renderer for this controller's two root-owned trust files.
//
// A new estate's controller needs config.json and component-registry.json.
// Neither may be copied from the retiring estate's templates, and neither may
// be hand-composed. The owner-signed estate profile supplies every estate
// fact: the Store's operator key, Store ID and public origin, the
// license-registry program and the master mint. A private mode-0600 input
// supplies only the facts the profile deliberately does not hold: the target
// licence, trusted RPC endpoints and this host's component recipes.
//
// Two values are never inputs. autoApply is always false (owner-safety gate
// F-358): the controller checks, verifies and notifies, and applies nothing
// on its own. And the Store binary is never a component. Enrollment binds the
// running Store ELF's hash (store-enrollment-facts-mismatch:binarySha256,
// estate_enrollment_state.go:81), so a controller swap of that binary can only
// stop the Store; the binary changes through the owner-signed successor
// enrollment instead (estate_enroll_successor.go). A component that is the
// Store binary by id, unit, path or command is refused by name.
//
// The renderer reads no chain state, contacts no endpoint, installs nothing,
// enables no unit and never replaces an existing file. It validates both
// candidates with the controller's own loaders before publishing either.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/hostupdate"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/rootstore"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	estateControllerConfigRenderCommand = "estate-update-controller-config-render"

	controllerRenderInputSchema  = "melusina.update-controller-render-input.v1"
	controllerRenderInputKind    = "update-controller-render-input"
	controllerRenderReportSchema = "melusina.update-controller-render-report.v1"

	maxControllerRenderInputJSON    = 64 << 10
	maxControllerRenderRegistryJSON = 256 << 10

	// The on-host locations the rendered config binds (DEPLOYMENT-CONTRACT
	// item 8). The installer places the files; the config names them.
	controllerRenderConfigDir    = "/etc/melusina/update-controller"
	controllerRenderConfigName   = "config.json"
	controllerRenderRegistryName = "component-registry.json"
	controllerRenderProfileName  = "estate-profile.json"
	controllerRenderStateDir     = "/var/lib/melusina/update-controller"

	refusalControllerRenderAutoApply    = "update-controller-render-auto-apply-forbidden"
	refusalControllerRenderStoreBinary  = "update-controller-render-store-binary-is-not-a-controller-component"
	refusalControllerRenderOutputExists = "update-controller-render-output-exists"
	refusalControllerRenderMismatch     = "update-controller-render-candidate-mismatch"

	// storeBinaryComponentID is the component ID the Store's /release-info
	// reports (runtime_release_info.go storeRuntimeComponentID).
	storeBinaryComponentID = "melusina-store-sidecar"
	// storeConfigRoot holds the Store's config, TLS files and attest shards.
	storeConfigRoot = "/etc/melusina/store"
)

var (
	controllerRenderConfigPath   = filepath.Join(controllerRenderConfigDir, controllerRenderConfigName)
	controllerRenderRegistryPath = filepath.Join(controllerRenderConfigDir, controllerRenderRegistryName)
	controllerRenderProfilePath  = filepath.Join(controllerRenderConfigDir, controllerRenderProfileName)
)

type controllerRenderOptions struct {
	profilePath string
	inputPath   string
	outDir      string
}

// controllerRenderInput is closed. It has no autoApply, timing, one-shot,
// origin, Store ID, operator key, program or mint field: the first four are
// fixed here, the rest come from the verified profile.
type controllerRenderInput struct {
	ProfileSHA256   string
	LicenseNFTMint  string
	RPCURL          string
	RPCFallbackURLs []string
	RPCAttempts     int
	Components      []componentrelease.ComponentInstall
}

type controllerRenderInstallPaths struct {
	Config            string `json:"config"`
	ComponentRegistry string `json:"componentRegistry"`
	EstateProfile     string `json:"estateProfile"`
}

// controllerRenderReport omits the RPC endpoints, which often carry API keys.
type controllerRenderReport struct {
	Schema                  string                       `json:"schema"`
	Status                  string                       `json:"status"`
	EstateID                string                       `json:"estateId"`
	ProfileSHA256           string                       `json:"profileSha256"`
	ProfileRevision         uint64                       `json:"profileRevision"`
	ConfigSHA256            string                       `json:"configSha256"`
	ComponentRegistrySHA256 string                       `json:"componentRegistrySha256"`
	AutoApply               bool                         `json:"autoApply"`
	ComponentIDs            []string                     `json:"componentIds"`
	InstallPaths            controllerRenderInstallPaths `json:"installPaths"`
	ProfileBoundFields      []string                     `json:"profileBoundFields"`
	OperatorInputFields     []string                     `json:"operatorInputFields"`
	FixedFields             []string                     `json:"fixedFields"`
	DoesNotEstablish        []string                     `json:"doesNotEstablish"`
}

func runEstateControllerConfigRenderSubcommand(args []string) {
	fs := flag.NewFlagSet(estateControllerConfigRenderCommand, flag.ExitOnError)
	opts := controllerRenderOptions{}
	fs.StringVar(&opts.profilePath, "estate-profile", "", "required absolute path to the owner-signed EstateProfileV1 JSON")
	fs.StringVar(&opts.inputPath, "input", "", "required absolute path to the mode-0600 controller render input JSON")
	fs.StringVar(&opts.outDir, "out-dir", "", "required absolute path to an existing owned directory; config.json and component-registry.json must not exist in it")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		log.Fatalf("%s: unexpected positional arguments: %v", estateControllerConfigRenderCommand, fs.Args())
	}
	if strings.TrimSpace(opts.profilePath) == "" || strings.TrimSpace(opts.inputPath) == "" || strings.TrimSpace(opts.outDir) == "" {
		log.Fatalf("%s: -estate-profile, -input and -out-dir are required", estateControllerConfigRenderCommand)
	}
	report, err := renderEstateControllerConfig(opts)
	if err != nil {
		log.Fatalf("%s: %v", estateControllerConfigRenderCommand, err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		log.Fatalf("%s report: %v", estateControllerConfigRenderCommand, err)
	}
}

func renderEstateControllerConfig(opts controllerRenderOptions) (controllerRenderReport, error) {
	profilePath, err := cleanControllerRenderPath(opts.profilePath, "estate-profile")
	if err != nil {
		return controllerRenderReport{}, err
	}
	inputPath, err := cleanControllerRenderPath(opts.inputPath, "input")
	if err != nil {
		return controllerRenderReport{}, err
	}
	outDir, err := cleanControllerRenderPath(opts.outDir, "out-dir")
	if err != nil {
		return controllerRenderReport{}, err
	}
	profile, profileSHA256, err := loadVerifiedControllerRenderProfile(profilePath)
	if err != nil {
		return controllerRenderReport{}, err
	}
	input, err := loadControllerRenderInput(inputPath)
	if err != nil {
		return controllerRenderReport{}, err
	}
	if input.ProfileSHA256 != profileSHA256 {
		return controllerRenderReport{}, errors.New("update-controller-render-profile-sha256-mismatch")
	}
	cfg, registry, err := buildControllerRenderCandidate(profile, profileSHA256, input)
	if err != nil {
		return controllerRenderReport{}, err
	}
	if err := requireControllerRenderCandidate(cfg, registry, profile, profileSHA256); err != nil {
		return controllerRenderReport{}, err
	}
	configRaw, err := marshalControllerRenderFile(cfg, maxControllerConfigBytes)
	if err != nil {
		return controllerRenderReport{}, err
	}
	registryRaw, err := marshalControllerRenderFile(registry, maxControllerRenderRegistryJSON)
	if err != nil {
		return controllerRenderReport{}, err
	}
	files := []controllerRenderFile{
		// The registry is published first: a registry with no config is inert,
		// and the controller reads the config before anything else.
		{name: controllerRenderRegistryName, raw: registryRaw},
		{name: controllerRenderConfigName, raw: configRaw},
	}
	verify := func(temporaries map[string]string) error {
		return verifyControllerRenderTemporaries(temporaries, profile, profileSHA256, profilePath)
	}
	if err := writeControllerRenderFiles(outDir, files, verify); err != nil {
		return controllerRenderReport{}, err
	}

	ids := make([]string, 0, len(registry.Components))
	for id := range registry.Components {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	configDigest := sha256.Sum256(configRaw)
	registryDigest := sha256.Sum256(registryRaw)
	return controllerRenderReport{
		Schema:                  controllerRenderReportSchema,
		Status:                  "profile-bound-update-controller-config-written",
		EstateID:                profile.EstateID,
		ProfileSHA256:           profileSHA256,
		ProfileRevision:         profile.Revision,
		ConfigSHA256:            hex.EncodeToString(configDigest[:]),
		ComponentRegistrySHA256: hex.EncodeToString(registryDigest[:]),
		AutoApply:               cfg.AutoApply,
		ComponentIDs:            ids,
		InstallPaths: controllerRenderInstallPaths{
			Config:            controllerRenderConfigPath,
			ComponentRegistry: controllerRenderRegistryPath,
			EstateProfile:     controllerRenderProfilePath,
		},
		ProfileBoundFields: []string{
			"operatorPubkey<-store.operatorKey", "expectedStoreId<-store.storeId",
			"bundleOrigin<-store.rootDomain", "storeGenerationUrl<-store.rootDomain",
			"programId<-programs.license-registry.programId", "masterNftMint<-anchors.masterMint",
			"estateProfileSha256<-profile digest",
		},
		OperatorInputFields: []string{
			"licenseNftMint", "solanaRpcUrl", "solanaRpcFallbackUrls", "solanaRpcAttempts", "components",
		},
		FixedFields: []string{
			"autoApply=false", "pollIntervalSeconds", "deepStableSeconds", "promoteDeadlineSeconds",
			"componentRegistryPath", "estateProfilePath", "stateDir", "receiptDir", "no oneShotApply",
		},
		DoesNotEstablish: []string{
			"an installed controller, an enabled timer or a started unit",
			"the controller binary's Active InstallerReleaseEntry",
			"the estate profile at installPaths.estateProfile; the controller refuses any file whose digest is not profileSha256",
			"a reachable RPC endpoint reporting the profile genesis",
			"any Store binary change: the Store binary is never a controller component and changes only through owner-signed successor enrollment",
			"the Store's /release-info runtime tuple",
			"that each component's host actions are correct beyond the registry's own validation",
		},
	}, nil
}

func loadVerifiedControllerRenderProfile(path string) (estateprofile.EstateProfileV1, string, error) {
	raw, err := readControllerRenderRegular(path, estateprofile.MaxProfileJSONBytes, false)
	if err != nil {
		return estateprofile.EstateProfileV1{}, "", fmt.Errorf("update-controller-render-profile-read: %w", err)
	}
	profile, err := estateprofile.DecodeProfile(raw)
	if err != nil {
		return estateprofile.EstateProfileV1{}, "", fmt.Errorf("update-controller-render-profile-invalid: %w", err)
	}
	digest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		return estateprofile.EstateProfileV1{}, "", fmt.Errorf("update-controller-render-profile-invalid: %w", err)
	}
	return profile, digest, nil
}

var controllerRenderInputFields = []string{
	"schema", "kind", "profileSha256", "licenseNftMint",
	"solanaRpcUrl", "solanaRpcFallbackUrls", "solanaRpcAttempts", "components",
}

func loadControllerRenderInput(path string) (controllerRenderInput, error) {
	var input controllerRenderInput
	raw, err := readControllerRenderRegular(path, maxControllerRenderInputJSON, true)
	if err != nil {
		return input, fmt.Errorf("update-controller-render-input-read: %w", err)
	}
	// Exact duplicate keys at any depth: json's last-wins must never pick a
	// value the operator did not see.
	if err := assertNoDuplicateTopLevelKeys(raw); err != nil {
		return input, fmt.Errorf("update-controller-render-input-invalid: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return input, fmt.Errorf("update-controller-render-input-invalid: %w", err)
	}
	if err := requireExactControllerRenderFields(fields, controllerRenderInputFields, "update-controller-render-input"); err != nil {
		return input, err
	}
	var schema, kind string
	if schema, err = controllerRenderString(fields, "schema"); err != nil {
		return input, err
	}
	if kind, err = controllerRenderString(fields, "kind"); err != nil {
		return input, err
	}
	if schema != controllerRenderInputSchema || kind != controllerRenderInputKind {
		return input, errors.New("update-controller-render-input-schema-unsupported")
	}
	if input.ProfileSHA256, err = controllerRenderString(fields, "profileSha256"); err != nil {
		return input, err
	}
	if !isLowerHex64Value(input.ProfileSHA256) {
		return input, errors.New("update-controller-render-input-invalid:profileSha256")
	}
	licence, err := controllerRenderString(fields, "licenseNftMint")
	if err != nil {
		return input, err
	}
	key, err := primitives.PubkeyFromBase58(licence)
	if err != nil {
		return input, errors.New("update-controller-render-input-invalid:licenseNftMint")
	}
	input.LicenseNFTMint = key.Base58()
	if input.RPCURL, err = controllerRenderString(fields, "solanaRpcUrl"); err != nil {
		return input, err
	}
	if err := json.Unmarshal(fields["solanaRpcFallbackUrls"], &input.RPCFallbackURLs); err != nil || input.RPCFallbackURLs == nil {
		return input, errors.New("update-controller-render-input-invalid:solanaRpcFallbackUrls")
	}
	if err := json.Unmarshal(fields["solanaRpcAttempts"], &input.RPCAttempts); err != nil || input.RPCAttempts <= 0 {
		return input, errors.New("update-controller-render-input-invalid:solanaRpcAttempts")
	}
	// The controller's own endpoint rule; its errors never echo an endpoint.
	primary, fallbacks, attempts, err := normalizeControllerRPCEndpoints(input.RPCURL, input.RPCFallbackURLs, input.RPCAttempts)
	if err != nil {
		return input, fmt.Errorf("update-controller-render-input-rpc: %w", err)
	}
	for _, endpoint := range append([]string{primary}, fallbacks...) {
		if parsed, err := url.Parse(endpoint); err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return input, errors.New("update-controller-render-input-rpc-must-use-https")
		}
	}
	input.RPCURL, input.RPCFallbackURLs, input.RPCAttempts = primary, fallbacks, attempts
	if input.Components, err = decodeControllerRenderComponents(fields["components"]); err != nil {
		return input, err
	}
	return input, nil
}

// componentInstallFields is the exact key set of a registry entry, taken from
// the ComponentInstall JSON tags so the input can never name a field the
// registry does not have. Exact matching also refuses a case variant that
// encoding/json would otherwise fold onto a real field.
func componentInstallFields() []string {
	typ := reflect.TypeOf(componentrelease.ComponentInstall{})
	fields := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			fields = append(fields, name)
		}
	}
	return fields
}

func decodeControllerRenderComponents(raw json.RawMessage) ([]componentrelease.ComponentInstall, error) {
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) == 0 {
		return nil, errors.New("update-controller-render-input-invalid:components: a non-empty array of component recipes is required")
	}
	allowed := componentInstallFields()
	seen := map[string]bool{}
	components := make([]componentrelease.ComponentInstall, 0, len(entries))
	for index, entry := range entries {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(entry, &fields); err != nil {
			return nil, fmt.Errorf("update-controller-render-input-invalid:components[%d]: not an object", index)
		}
		if err := requireKnownControllerRenderFields(fields, allowed, fmt.Sprintf("update-controller-render-input-component[%d]", index)); err != nil {
			return nil, err
		}
		var install componentrelease.ComponentInstall
		if err := json.Unmarshal(entry, &install); err != nil {
			return nil, fmt.Errorf("update-controller-render-input-invalid:components[%d]: %w", index, err)
		}
		if err := refuseStoreBinaryComponent(install); err != nil {
			return nil, err
		}
		if seen[install.ComponentID] {
			return nil, fmt.Errorf("update-controller-render-input-duplicate-component:%s", install.ComponentID)
		}
		seen[install.ComponentID] = true
		components = append(components, install)
	}
	return components, nil
}

func buildControllerRenderCandidate(profile estateprofile.EstateProfileV1, profileSHA256 string, input controllerRenderInput) (ControllerConfig, componentrelease.ComponentRegistry, error) {
	programID, ok := installerrelease.LicenseRegistryProgramID(profile)
	if !ok {
		return ControllerConfig{}, componentrelease.ComponentRegistry{}, errors.New("update-controller-render-profile-missing:programs.license-registry")
	}
	origin := controllerRenderOrigin(profile)
	// The timing values are the package's safe defaults, not inputs.
	timing := hostupdate.DefaultUpdatePolicy()
	cfg := ControllerConfig{
		Schema:                 controllerConfigSchema,
		AutoApply:              false,
		PollIntervalSeconds:    timing.PollIntervalSeconds,
		DeepStableSeconds:      timing.DeepStableSeconds,
		PromoteDeadlineSeconds: timing.PromoteDeadlineSeconds,
		OperatorPubkey:         profile.Store.OperatorKey,
		ExpectedStoreID:        profile.Store.StoreID,
		BundleOrigin:           origin,
		StoreGenerationURL:     origin + "/update/generation.json",
		ComponentRegistryPath:  controllerRenderRegistryPath,
		ProgramID:              programID,
		MasterNftMint:          profile.Anchors.MasterMint,
		LicenseNftMint:         input.LicenseNFTMint,
		SolanaRPCURL:           input.RPCURL,
		SolanaRPCFallbackURLs:  append([]string(nil), input.RPCFallbackURLs...),
		SolanaRPCAttempts:      input.RPCAttempts,
		EstateProfilePath:      controllerRenderProfilePath,
		EstateProfileSha256:    profileSHA256,
		StateDir:               controllerRenderStateDir,
		ReceiptDir:             filepath.Join(controllerRenderStateDir, "receipts"),
	}
	registry := componentrelease.ComponentRegistry{
		Schema:     componentrelease.ComponentRegistrySchema,
		Components: map[string]componentrelease.ComponentInstall{},
	}
	for _, install := range input.Components {
		registry.Components[install.ComponentID] = install
	}
	if err := registry.Validate(); err != nil {
		return ControllerConfig{}, componentrelease.ComponentRegistry{}, fmt.Errorf("update-controller-render-input-invalid:components: %w", err)
	}
	return cfg, registry, nil
}

func controllerRenderOrigin(profile estateprofile.EstateProfileV1) string {
	return "https://" + profile.Store.RootDomain
}

// requireControllerRenderCandidate is checked on the built candidate and again
// on the bytes read back from disk, so a builder defect cannot publish.
func requireControllerRenderCandidate(cfg ControllerConfig, registry componentrelease.ComponentRegistry, profile estateprofile.EstateProfileV1, profileSHA256 string) error {
	if cfg.AutoApply {
		return fmt.Errorf("%s: owner-safety gate F-358 keeps the controller at autoApply=false; it notifies and never applies on its own", refusalControllerRenderAutoApply)
	}
	if cfg.OneShotApply != nil {
		return fmt.Errorf("%s:oneShotApply", refusalControllerRenderMismatch)
	}
	programID, _ := installerrelease.LicenseRegistryProgramID(profile)
	origin := controllerRenderOrigin(profile)
	timing := hostupdate.DefaultUpdatePolicy()
	for _, check := range []struct {
		field     string
		got, want any
	}{
		{"schema", cfg.Schema, controllerConfigSchema},
		{"pollIntervalSeconds", cfg.PollIntervalSeconds, timing.PollIntervalSeconds},
		{"deepStableSeconds", cfg.DeepStableSeconds, timing.DeepStableSeconds},
		{"promoteDeadlineSeconds", cfg.PromoteDeadlineSeconds, timing.PromoteDeadlineSeconds},
		{"operatorPubkey", cfg.OperatorPubkey, profile.Store.OperatorKey},
		{"expectedStoreId", cfg.ExpectedStoreID, profile.Store.StoreID},
		{"bundleOrigin", cfg.BundleOrigin, origin},
		{"storeGenerationUrl", cfg.StoreGenerationURL, origin + "/update/generation.json"},
		{"programId", cfg.ProgramID, programID},
		{"masterNftMint", cfg.MasterNftMint, profile.Anchors.MasterMint},
		{"estateProfileSha256", cfg.EstateProfileSha256, profileSHA256},
		{"estateProfilePath", cfg.EstateProfilePath, controllerRenderProfilePath},
		{"componentRegistryPath", cfg.ComponentRegistryPath, controllerRenderRegistryPath},
		{"stateDir", cfg.StateDir, controllerRenderStateDir},
		{"receiptDir", cfg.ReceiptDir, filepath.Join(controllerRenderStateDir, "receipts")},
		{"stagingRoot", cfg.StagingRoot, ""},
		{"notifyPath", cfg.NotifyPath, ""},
	} {
		if check.got != check.want {
			return fmt.Errorf("%s:%s", refusalControllerRenderMismatch, check.field)
		}
	}
	if registry.Schema != componentrelease.ComponentRegistrySchema || len(registry.Components) == 0 {
		return fmt.Errorf("%s:componentRegistry", refusalControllerRenderMismatch)
	}
	for _, install := range registry.Components {
		if err := refuseStoreBinaryComponent(install); err != nil {
			return err
		}
	}
	return nil
}

// refuseStoreBinaryComponent refuses a recipe that installs, restarts, stages
// into or reports through the Store binary. Any one field is enough.
func refuseStoreBinaryComponent(install componentrelease.ComponentInstall) error {
	field := storeBinaryComponentField(install)
	if field == "" {
		return nil
	}
	return fmt.Errorf("%s:%s (component %q): enrollment binds the Store binary hash, so only an owner-signed successor enrollment may change it", refusalControllerRenderStoreBinary, field, install.ComponentID)
}

func storeBinaryComponentField(install componentrelease.ComponentInstall) string {
	if install.ComponentID == storeBinaryComponentID || install.ComponentID == rootstore.SidecarID || isStoreName(install.ComponentID) {
		return "componentId"
	}
	if isStoreName(install.ServiceUnit) {
		return "serviceUnit"
	}
	for _, path := range []struct{ field, value string }{
		{"installRoot", install.InstallRoot},
		{"currentSymlink", install.CurrentSymlink},
		{"stagingDir", install.StagingDir},
		{"runtimeEnvFile", install.RuntimeEnvFile},
	} {
		if isStoreOwnedPath(path.value) {
			return path.field
		}
	}
	for _, argv := range []struct {
		field string
		args  []string
	}{
		{"restartCommand", install.RestartCommand},
		{"healthCommand", install.HealthCommand},
		{"runtimeProofCommand", install.RuntimeProofCommand},
	} {
		for _, arg := range argv.args {
			if isStoreName(arg) || isStoreOwnedPath(arg) {
				return argv.field
			}
		}
	}
	return ""
}

// isStoreName matches the Store's unit, binary and state-directory names:
// melusina-store-sidecar(.service), melusina-store-listing-signer.service,
// /opt/melusina-store, /var/lib/melusina-store-private and every later
// melusina-store-* sibling.
func isStoreName(name string) bool {
	name = strings.TrimSpace(name)
	return name == "melusina-store" || strings.HasPrefix(name, "melusina-store-") || strings.HasPrefix(name, "melusina-store.")
}

// isStoreOwnedPath reports an absolute path inside the Store's config root or
// with any path element named like the Store (release tree, state roots, a
// copied Store ELF, a staging directory for it).
func isStoreOwnedPath(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}
	path = filepath.Clean(path)
	if path == storeConfigRoot || strings.HasPrefix(path, storeConfigRoot+"/") {
		return true
	}
	for _, element := range strings.Split(path, "/") {
		if isStoreName(element) {
			return true
		}
	}
	return false
}

func marshalControllerRenderFile(value any, limit int) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if len(raw) > limit {
		return nil, errors.New("update-controller-render-output-too-large")
	}
	return raw, nil
}

// verifyControllerRenderTemporaries reads both fsynced temporaries back
// through the controller's own loaders before either is published.
func verifyControllerRenderTemporaries(temporaries map[string]string, profile estateprofile.EstateProfileV1, profileSHA256, profilePath string) error {
	loaded, err := loadControllerConfigOwned(temporaries[controllerRenderConfigName], uint32(os.Geteuid()))
	if err != nil {
		return fmt.Errorf("update-controller-render-candidate-invalid: config: %w", err)
	}
	registryRaw, err := readControllerRenderRegular(temporaries[controllerRenderRegistryName], maxControllerRenderRegistryJSON, true)
	if err != nil {
		return fmt.Errorf("update-controller-render-candidate-invalid: registry: %w", err)
	}
	registry, err := componentrelease.ParseComponentRegistry(registryRaw)
	if err != nil {
		return fmt.Errorf("update-controller-render-candidate-invalid: registry: %w", err)
	}
	if err := requireControllerRenderCandidate(loaded, registry, profile, profileSHA256); err != nil {
		return err
	}
	// The chain gate the controller constructs at startup, reading this
	// profile file: its program and master-mint pins must be the profile's.
	// The installed config names installPaths.estateProfile instead.
	probe := loaded
	probe.EstateProfilePath = profilePath
	if _, err := newSolanaChainGate(probe); err != nil {
		return fmt.Errorf("update-controller-render-candidate-invalid: chain gate: %w", err)
	}
	return nil
}

type controllerRenderFile struct {
	name string
	raw  []byte
}

// writeControllerRenderFiles publishes new files only. Each temporary is
// fsynced, verified and then hard-linked into place: link(2), unlike rename(2),
// cannot replace a file or a symlink that appeared meanwhile. On a later
// failure it removes only links this run made.
func writeControllerRenderFiles(dir string, files []controllerRenderFile, verify func(map[string]string) error) error {
	uid := uint32(os.Geteuid())
	if err := requireControllerRenderOutputDirectory(dir, uid); err != nil {
		return fmt.Errorf("update-controller-render-output-directory: %w", err)
	}
	for _, file := range files {
		if _, err := os.Lstat(filepath.Join(dir, file.name)); err == nil {
			return fmt.Errorf("%s:%s", refusalControllerRenderOutputExists, file.name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("update-controller-render-output-target:%s: %w", file.name, err)
		}
	}
	temporaries := map[string]string{}
	defer func() {
		for _, temporary := range temporaries {
			_ = os.Remove(temporary)
		}
	}()
	for _, file := range files {
		temporary, err := writeControllerRenderTemporary(dir, file)
		if err != nil {
			return err
		}
		temporaries[file.name] = temporary
	}
	if err := verify(temporaries); err != nil {
		return err
	}
	var published []string
	for _, file := range files {
		final := filepath.Join(dir, file.name)
		if err := os.Link(temporaries[file.name], final); err != nil {
			for _, name := range published {
				removeOwnControllerRenderLink(filepath.Join(dir, name), temporaries[name])
			}
			if errors.Is(err, os.ErrExist) {
				return fmt.Errorf("%s:%s", refusalControllerRenderOutputExists, file.name)
			}
			return err
		}
		published = append(published, file.name)
	}
	if err := fsyncDir(dir); err != nil {
		return err
	}
	for name, temporary := range temporaries {
		if err := os.Remove(temporary); err != nil {
			return err
		}
		delete(temporaries, name)
	}
	return fsyncDir(dir)
}

func removeOwnControllerRenderLink(final, temporary string) {
	finalInfo, err := os.Lstat(final)
	if err != nil {
		return
	}
	temporaryInfo, err := os.Lstat(temporary)
	if err != nil || !os.SameFile(finalInfo, temporaryInfo) {
		return
	}
	_ = os.Remove(final)
}

func writeControllerRenderTemporary(dir string, file controllerRenderFile) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return "", err
		}
		path := filepath.Join(dir, "."+file.name+".new-"+hex.EncodeToString(nonce[:]))
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := f.Write(file.raw); err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return "", err
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return "", err
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(path)
			return "", err
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || controllerRenderUID(info) != uint32(os.Geteuid()) {
			_ = os.Remove(path)
			return "", errors.New("update-controller-render-temporary-mode-or-owner-mismatch")
		}
		return path, nil
	}
	return "", errors.New("update-controller-render-could-not-allocate-temporary")
}

func cleanControllerRenderPath(path, flagName string) (string, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) || path == string(filepath.Separator) {
		return "", fmt.Errorf("update-controller-render-%s-path-must-be-absolute", flagName)
	}
	return path, nil
}

// readControllerRenderRegular opens without following a final symlink and
// checks the opened file is the path's regular file. An input must be the
// caller's own mode-0600 file; the public profile must merely not be
// group- or world-writable.
func readControllerRenderRegular(path string, limit int, requireOwned0600 bool) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, pathInfo) || !info.Mode().IsRegular() {
		return nil, errors.New("not a regular non-symlink file")
	}
	if requireOwned0600 {
		if info.Mode().Perm() != 0o600 || controllerRenderUID(info) != uint32(os.Geteuid()) {
			return nil, errors.New("must be owned mode 0600")
		}
	} else if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("must not be group or world writable")
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > limit {
		return nil, errors.New("exceeds bounded read limit")
	}
	return raw, nil
}

func requireControllerRenderOutputDirectory(path string, uid uint32) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, pathInfo) || !info.IsDir() {
		return errors.New("not a real directory")
	}
	if controllerRenderUID(info) != uid || info.Mode().Perm()&0o022 != 0 {
		return errors.New("directory must be owned and not group or world writable")
	}
	return nil
}

func controllerRenderUID(info os.FileInfo) uint32 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ^uint32(0)
	}
	return stat.Uid
}

func controllerRenderString(fields map[string]json.RawMessage, field string) (string, error) {
	var value string
	if err := json.Unmarshal(fields[field], &value); err != nil || strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n\t") {
		return "", fmt.Errorf("update-controller-render-input-invalid:%s", field)
	}
	return value, nil
}

// requireExactControllerRenderFields refuses an unknown key first, then a
// missing one, each by name.
func requireExactControllerRenderFields(fields map[string]json.RawMessage, allowed []string, prefix string) error {
	if err := requireKnownControllerRenderFields(fields, allowed, prefix); err != nil {
		return err
	}
	for _, field := range allowed {
		if _, ok := fields[field]; !ok {
			return fmt.Errorf("%s-missing:%s", prefix, field)
		}
	}
	return nil
}

func requireKnownControllerRenderFields(fields map[string]json.RawMessage, allowed []string, prefix string) error {
	known := map[string]bool{}
	for _, field := range allowed {
		known[field] = true
	}
	names := make([]string, 0, len(fields))
	for field := range fields {
		names = append(names, field)
	}
	sort.Strings(names)
	for _, field := range names {
		if !known[field] {
			return fmt.Errorf("%s-unknown-field:%s", prefix, field)
		}
	}
	return nil
}
