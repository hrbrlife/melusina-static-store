package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/storerecovery"
)

// storeStateFixture is a write-capable, enrolled root Store laid out the way
// the profile-bound renderer lays one out: six state roots side by side in
// one owner-only directory. Genesis sealed its trust root under the writer
// lock, and one app was staged and promoted through the production router,
// so every root holds real Store state.
type storeStateFixture struct {
	cfg          Config
	parent       string
	opts         storeStateOptions
	bootstrap    catalogBootstrapOptions
	operator     *identity.Private
	chain        *mockChainReader
	router       http.Handler
	stageBody    []byte
	promoteBody  []byte
	packagePath  string
	pointerPath  string
	indexBytes   []byte
	packageBytes []byte
	pointerBytes []byte
	current      string
}

func newStoreStateFixture(t *testing.T) storeStateFixture {
	t.Helper()
	root := t.TempDir()
	parent := filepath.Join(root, "var-lib-melusina-store")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Domain: "state-backup.store.example.org", StoreID: "state-backup-store", LicenseNFTMint: randPubkeyB58(t),
		DistDir:                  filepath.Join(parent, "dist-publish"),
		PrivateStageDir:          filepath.Join(parent, "private-app-candidates"),
		CatalogGenerationRoot:    filepath.Join(parent, "app-catalog-generations"),
		CatalogMigrationStateDir: filepath.Join(parent, "migrations"),
		CatalogRepoRoot:          filepath.Join(parent, "catalog-source"),
		ReleaseSquadsAuthority: ReleaseSquadsAuthority{
			Multisig: testStoreAuthority, Vault: testStoreAuthority, ProgramID: testStoreAuthority,
			Threshold: defaultBazaarSquadsThreshold, MemberCount: defaultBazaarSquadsMemberCount,
		},
		ServeVerifyTTLSeconds: -1,
	}
	configureReleaseAuthorityFixtureForBuild(&cfg, root)
	cfg.EstateEnrollmentStatePath = filepath.Join(parent, "estate-enrollment.json")
	for _, dir := range []string{cfg.DistDir, cfg.PrivateStageDir, cfg.CatalogMigrationStateDir, cfg.CatalogRepoRoot} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, namespace := range appCatalogNamespaces {
		if err := os.Mkdir(filepath.Join(cfg.DistDir, namespace), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(cfg.DistDir, "apps", "index.json"), []byte("{\"apps\":[]}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { makeTreeWritable(root) })

	operator := newTestIdentity(t, "state-backup-operator", cfg.LicenseNFTMint, cfg.Domain)
	cfg.StoreAuthority = operator.Public().SignPubkeyB58
	publisher := newTestIdentity(t, "state-backup-publisher", randPubkeyB58(t), "publisher.example.org")
	cfg.Policy.AcceptPublishers = []string{publisher.Public().SignPubkeyB58}
	writeStoreStateEnrollment(t, cfg.EstateEnrollmentStatePath, operator)

	operatorKey, err := operator.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	bootstrap := catalogBootstrapOptions{
		expectedUID: uid, expectedGID: gid, nonce: defaultPublishNonceLedgerOptions(),
		operatorPublicKey: ed25519.PublicKey(operatorKey), operator: operator,
	}
	bootstrap.nonce.Now = time.Now
	if _, err := runCatalogGenesisBootstrapUnderWriterLock(cfg, bootstrap); err != nil {
		t.Fatalf("genesis: %v", err)
	}
	runtime, err := bootstrapCatalogRuntimeWithOptions(cfg, true, bootstrap)
	if err != nil {
		t.Fatalf("bootstrap after genesis: %v", err)
	}

	fixture := buildValidFixture(t, cfg, randPubkeyB58(t))
	release := mustJSON(t, fixture.rel)
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "state-backup", "app", fixture.metadata)
	chain := newMockChainReader()
	fixture.pinAccept(chain, operatorSignPub32(t, operator))
	fixture.pinServeListingActive(chain)
	router := newRouterWithCatalogRuntime(cfg, operator, chain, nil, runtime)
	now := time.Now().UTC()
	stageBody := exactPublishBody(t, signPublishForRoute(t, publisher, operator.Public(), fixture.spk, release, "/publish/stage", now, 5*time.Minute, "state-backup-stage"), release, fixture.spk, fixture.metadata)
	promoteBody := exactPublishBody(t, signPublishForRoute(t, publisher, operator.Public(), fixture.spk, release, "/publish", now, 5*time.Minute, "state-backup-promote"), release, fixture.spk, fixture.metadata)
	if got := exactRequest(router, http.MethodPost, "/publish/stage", stageBody); got.Code != http.StatusOK {
		t.Fatalf("stage = %d: %s", got.Code, got.Body.String())
	}
	if got := exactRequest(router, http.MethodPost, "/publish", promoteBody); got.Code != http.StatusOK {
		t.Fatalf("promote = %d: %s", got.Code, got.Body.String())
	}

	f := storeStateFixture{
		cfg: cfg, parent: parent, bootstrap: bootstrap, operator: operator, chain: chain, router: router,
		stageBody: stageBody, promoteBody: promoteBody,
		opts:        storeStateOptions{expectedUID: uid, expectedGID: gid, now: time.Now},
		packagePath: "/packages/" + metadataPackageID(fixture.metadata),
		pointerPath: "/apps/pointers/" + metadataAppID(fixture.metadata) + ".json",
	}
	f.indexBytes = exactGETOK(t, router, "/apps/index.json")
	f.packageBytes = exactGETOK(t, router, f.packagePath)
	f.pointerBytes = exactGETOK(t, router, f.pointerPath)
	if !bytes.Equal(f.packageBytes, fixture.spk) || !bytes.Contains(f.indexBytes, []byte(metadataAppID(fixture.metadata))) {
		t.Fatal("fixture: the promoted app is not served")
	}
	current, err := runtime.catalogGenerations.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	f.current = current.ID
	return f
}

// writeStoreStateEnrollment writes an owner-signed enrollment state that
// names operator as the Store operator.
func writeStoreStateEnrollment(t *testing.T, path string, operator *identity.Private) {
	t.Helper()
	profile := storeEstateProfileFixture(t)
	profile.Store.OperatorKey = operator.Public().SignPubkeyB58
	profile = signStoreEnrollmentRuntimeProfile(t, profile)
	profileDigest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := estateprofile.StoreEnrollmentV1{
		Schema: estateprofile.StoreEnrollmentSchema, Kind: estateprofile.StoreEnrollmentKind, Purpose: estateprofile.StoreEnrollmentPurpose,
		EstateID: profile.EstateID, ProfileSHA256: profileDigest, ProfileRevision: profile.Revision,
		NetworkGenesisHash: profile.Network.GenesisHash, RootDomain: profile.Store.RootDomain, RootDomainSHA256: profile.Store.RootDomainSHA256,
		StoreID: profile.Store.StoreID, StoreOperatorKey: profile.Store.OperatorKey, StoreBoxKey: operator.Public().BoxPubkeyB58,
		LicenseNFTMint: randPubkeyB58(t), LicenseRegistryID: storeEnrollmentStateProgramID(t, profile, estateprofile.ProgramRoleLicenseRegistry),
		SidecarID: "store", BindingKeyVersion: 1, OperatorKeyVersion: 1, OperatorDomain: "operator.state-backup.invalid",
		SidecarIdentityPDA: randPubkeyB58(t), TLSCertFingerprint: storeEnrollmentStateDigest("state-backup-tls"),
		BinarySHA256: storeEnrollmentStateDigest("state-backup-binary"), IssuedAt: "2026-09-20T01:00:00Z", ExpiresAt: "2026-09-20T02:00:00Z",
		EnrollmentNonce: storeEnrollmentStateDigest("state-backup-nonce"),
	}
	digest, err := estateprofile.StoreEnrollmentSHA256(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	for _, keyID := range []string{"owner-a", "owner-b"} {
		enrollment.Signatures = append(enrollment.Signatures, estateprofile.SignatureV1{
			KeyID:     keyID,
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(storeEnrollmentStatePrivate(profile.OwnerPolicy.PolicyID, keyID), []byte(digest))),
		})
	}
	state, err := newStoreEnrollmentState(profile, enrollment, storeEnrollmentStateNow)
	if err != nil {
		t.Fatalf("enrollment state: %v", err)
	}
	if err := writeStoreEnrollmentStateNew(path, state, uint32(os.Geteuid())); err != nil {
		t.Fatalf("write enrollment state: %v", err)
	}
}

func makeTreeWritable(root string) {
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
}

func (f storeStateFixture) export(t *testing.T) ([]byte, storerecovery.StateSummary) {
	t.Helper()
	var out bytes.Buffer
	summary, err := exportStoreState(f.cfg, f.operator, &out, f.opts)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	return out.Bytes(), summary
}

// destroyHost moves the whole Store directory aside, as if the host were
// lost, and leaves an empty owner-only directory at the same path.
func (f storeStateFixture) destroyHost(t *testing.T) string {
	t.Helper()
	aside := f.parent + ".destroyed"
	if err := os.Rename(f.parent, aside); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.parent, 0o700); err != nil {
		t.Fatal(err)
	}
	return aside
}

// A Store exported, lost and imported onto empty roots at the same paths
// starts through the ordinary startup path and serves the identical
// generation: the same current generation, index, pointer and package bytes.
// The nonce ledger came back with it, so the envelopes the lost Store
// accepted are still refused as replays.
func TestStoreRestoreServesIdenticalGeneration(t *testing.T) {
	f := newStoreStateFixture(t)
	raw, exported := f.export(t)
	if exported.Manifest.CurrentGeneration != f.current || exported.Manifest.OperatorKey != f.operator.Public().SignPubkeyB58 {
		t.Fatalf("export describes %+v, want current %s", exported.Manifest, f.current)
	}
	roots := map[string]bool{}
	for _, root := range exported.Manifest.Roots {
		roots[root.Name] = true
	}
	for _, name := range storeStateRootConfigFields {
		if !roots[name] {
			t.Fatalf("the stream carries no %s root", name)
		}
	}
	for _, member := range exported.Manifest.Members {
		if strings.Contains(member.Path, "shard") {
			t.Fatalf("the stream carries %s", member.Path)
		}
	}

	f.destroyHost(t)
	imported, err := importStoreState(f.cfg, bytes.NewReader(raw), f.operator.Public().SignPubkeyB58, f.opts)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if imported.StreamSHA256 != exported.StreamSHA256 {
		t.Fatalf("imported stream %s, exported %s", imported.StreamSHA256, exported.StreamSHA256)
	}
	// Before it first starts, the restored Store is the lost one bit for bit:
	// it exports to the very stream it was restored from.
	if again, _ := f.export(t); !bytes.Equal(again, raw) {
		t.Fatal("the restored Store does not export to the stream it was restored from")
	}

	runtime, err := bootstrapCatalogRuntimeWithOptions(f.cfg, true, f.bootstrap)
	if err != nil {
		t.Fatalf("restored Store startup: %v", err)
	}
	current, err := runtime.catalogGenerations.ResolveCurrent()
	if err != nil || current.ID != f.current {
		t.Fatalf("restored current = %q, %v; want %s", current.ID, err, f.current)
	}
	restored := newRouterWithCatalogRuntime(f.cfg, f.operator, f.chain, nil, runtime)
	for path, want := range map[string][]byte{"/apps/index.json": f.indexBytes, f.packagePath: f.packageBytes, f.pointerPath: f.pointerBytes} {
		if got := exactGETOK(t, restored, path); !bytes.Equal(got, want) {
			t.Fatalf("restored Store serves different bytes at %s", path)
		}
	}
	for path, body := range map[string][]byte{"/publish/stage": f.stageBody, "/publish": f.promoteBody} {
		got := exactRequest(restored, http.MethodPost, path, body)
		if got.Code != http.StatusUnauthorized || !bytes.Contains(got.Body.Bytes(), []byte("nonce already consumed")) {
			t.Fatalf("replay of %s on the restored Store = %d: %s", path, got.Code, got.Body.String())
		}
	}
}

// The nonce sentinel binds the ledger to the private stage it was created
// at, so the state restores only onto the same private_stage_dir. Another
// path is refused by name before anything reaches a root.
func TestStoreStateImportRefusesAnotherPrivateStage(t *testing.T) {
	f := newStoreStateFixture(t)
	raw, _ := f.export(t)
	f.destroyHost(t)
	moved := f.cfg
	moved.PrivateStageDir = filepath.Join(f.parent, "private-app-candidates-elsewhere")
	_, err := importStoreState(moved, bytes.NewReader(raw), f.operator.Public().SignPubkeyB58, f.opts)
	if storerecovery.RefusalName(err) != refusalStoreStateLedgerPathMismatch {
		t.Fatalf("import onto another private stage = %v, want %s", err, refusalStoreStateLedgerPathMismatch)
	}
	requireEmptyStoreParent(t, f.parent)
	// Positive control: the same stream onto the original paths is accepted.
	if _, err := importStoreState(f.cfg, bytes.NewReader(raw), f.operator.Public().SignPubkeyB58, f.opts); err != nil {
		t.Fatalf("positive control: %v", err)
	}
}

func requireEmptyStoreParent(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("a refused import left %s behind", entries[0].Name())
	}
}

// The import re-verifies the catalog it restores: a stream that is genuinely
// signed by the operator but whose state is not servable (here a rollout that
// no longer matches the signed catalog pointer) is refused, and nothing
// reaches a root. The export refuses the same state before writing a byte.
func TestStoreStateImportVerifiesTheCatalogItRestores(t *testing.T) {
	f := newStoreStateFixture(t)
	rolloutDir := rolloutStateDir(f.cfg)
	entries, err := os.ReadDir(rolloutDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("fixture rollouts: %v, %v", entries, err)
	}
	rolloutPath := filepath.Join(rolloutDir, entries[0].Name())
	rawRollout, err := os.ReadFile(rolloutPath)
	if err != nil {
		t.Fatal(err)
	}
	var rollout map[string]any
	if err := json.Unmarshal(rawRollout, &rollout); err != nil {
		t.Fatal(err)
	}
	rollout["currentVersion"] = "9.9.9"
	edited, err := json.Marshal(rollout)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rolloutPath, edited, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := exportStoreState(f.cfg, f.operator, &bytes.Buffer{}, f.opts); storerecovery.RefusalName(err) != refusalStoreStateCatalogUnverified {
		t.Fatalf("export of an unservable state = %v, want %s", err, refusalStoreStateCatalogUnverified)
	}
	// Sign the same unservable state directly, bypassing the export check.
	roots, err := storeStateRoots(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	var signed bytes.Buffer
	if _, err := storerecovery.ExportState(&signed, roots, storerecovery.StateHeader{StoreID: f.cfg.StoreID, OperatorKey: f.operator.Public().SignPubkeyB58, CurrentGeneration: f.current}, f.operator.Sign); err != nil {
		t.Fatal(err)
	}
	f.destroyHost(t)
	_, err = importStoreState(f.cfg, bytes.NewReader(signed.Bytes()), f.operator.Public().SignPubkeyB58, f.opts)
	if storerecovery.RefusalName(err) != refusalStoreStateCatalogUnverified {
		t.Fatalf("import of an unservable state = %v, want %s", err, refusalStoreStateCatalogUnverified)
	}
	requireEmptyStoreParent(t, f.parent)
}

func TestStoreStateExportRefusesWhileTheStoreHoldsTheWriterLock(t *testing.T) {
	f := newStoreStateFixture(t)
	lock, err := acquireExistingWriterLockOwned(filepath.Join(f.cfg.CatalogMigrationStateDir, storeWriterLockName), f.opts.expectedUID, f.opts.expectedGID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = exportStoreState(f.cfg, f.operator, &bytes.Buffer{}, f.opts)
	if storerecovery.RefusalName(err) != refusalStoreStateWriterExclusion {
		t.Fatalf("export beside a running Store = %v, want %s", err, refusalStoreStateWriterExclusion)
	}
	lock.Close()
	if _, err := exportStoreState(f.cfg, f.operator, &bytes.Buffer{}, f.opts); err != nil {
		t.Fatalf("positive control after the Store stopped: %v", err)
	}
}

func TestStoreStateExportRefusesAnotherOperatorsState(t *testing.T) {
	f := newStoreStateFixture(t)
	stranger := newTestIdentity(t, "state-backup-stranger", f.cfg.LicenseNFTMint, f.cfg.Domain)
	_, err := exportStoreState(f.cfg, stranger, &bytes.Buffer{}, f.opts)
	if name := storerecovery.RefusalName(err); name != refusalStoreStateCatalogUnverified && name != refusalStoreStateEnrollmentOperator {
		t.Fatalf("export signed by another operator = %v", err)
	}
	if _, err := exportStoreState(f.cfg, nil, &bytes.Buffer{}, f.opts); storerecovery.RefusalName(err) != refusalStoreStateRequiresOperator {
		t.Fatalf("export without an operator = %v", err)
	}
	unenrolled := f.cfg
	unenrolled.EstateEnrollmentStatePath = ""
	if _, err := exportStoreState(unenrolled, f.operator, &bytes.Buffer{}, f.opts); storerecovery.RefusalName(err) != refusalStoreStateRequiresEnrollment {
		t.Fatalf("export of an unenrolled Store = %v", err)
	}
}

// The enrollment in the state must name the operator that signs it. The
// state's catalog verifies under this operator here, so the only fault is the
// enrollment.
func TestStoreStateRefusesAnEnrollmentOfAnotherOperator(t *testing.T) {
	f := newStoreStateFixture(t)
	stranger := newTestIdentity(t, "state-backup-stranger", f.cfg.LicenseNFTMint, f.cfg.Domain)
	if err := os.Remove(f.cfg.EstateEnrollmentStatePath); err != nil {
		t.Fatal(err)
	}
	writeStoreStateEnrollment(t, f.cfg.EstateEnrollmentStatePath, stranger)
	_, err := exportStoreState(f.cfg, f.operator, &bytes.Buffer{}, f.opts)
	if storerecovery.RefusalName(err) != refusalStoreStateEnrollmentOperator {
		t.Fatalf("export with another operator's enrollment = %v, want %s", err, refusalStoreStateEnrollmentOperator)
	}
}

// storeStatePathFields lists every path-valued Config field by JSON name,
// walking nested structs, so a new field cannot escape classification.
func storeStatePathFields(t *testing.T) []string {
	t.Helper()
	var fields []string
	var walk func(reflect.Type, string)
	walk = func(typ reflect.Type, prefix string) {
		for index := 0; index < typ.NumField(); index++ {
			field := typ.Field(index)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if !field.IsExported() || name == "" || name == "-" {
				continue
			}
			switch field.Type.Kind() {
			case reflect.Struct:
				walk(field.Type, prefix+name+".")
			case reflect.String:
				for _, suffix := range []string{"_dir", "_root", "_path", "_socket"} {
					if strings.HasSuffix(name, suffix) {
						fields = append(fields, prefix+name)
					}
				}
			}
		}
	}
	walk(reflect.TypeOf(Config{}), "")
	sort.Strings(fields)
	return fields
}

func TestStoreStateClassifiesEveryConfigPath(t *testing.T) {
	fields := storeStatePathFields(t)
	// Positive control: the walk reaches top-level and nested path fields.
	for _, want := range []string{"dist_dir", "boot_identity.shards_dir", "store_link_control_mtls.key_path"} {
		if !contains(fields, want) {
			t.Fatalf("the Config walk does not reach %s; it proves nothing", want)
		}
	}
	for _, field := range fields {
		_, root := storeStateRootConfigFields[field]
		_, excluded := storeStateExcludedConfigFields[field]
		if root == excluded {
			t.Errorf("store-state-config-path-unclassified:%s must be exactly one of a state root or an excluded path", field)
		}
	}
	for _, classes := range []map[string]string{storeStateRootConfigFields, storeStateExcludedConfigFields} {
		for field := range classes {
			if !contains(fields, field) {
				t.Errorf("store-state-config-path-stale:%s is classified but Config has no such path field", field)
			}
		}
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// setConfigPath sets one path field of cfg by its JSON name.
func setConfigPath(t *testing.T, cfg *Config, jsonPath, value string) {
	t.Helper()
	target := reflect.ValueOf(cfg).Elem()
	for _, part := range strings.Split(jsonPath, ".") {
		found := false
		for index := 0; index < target.NumField(); index++ {
			if strings.Split(target.Type().Field(index).Tag.Get("json"), ",")[0] == part {
				target, found = target.Field(index), true
				break
			}
		}
		if !found {
			t.Fatalf("Config has no field %s", jsonPath)
		}
	}
	target.SetString(value)
}

// Every excluded path, placed inside a state root, refuses the export by its
// own field name before a byte is written; outside the roots it is accepted.
func TestStoreStateRefusesEverySecretInsideARoot(t *testing.T) {
	f := newStoreStateFixture(t)
	if _, err := storeStateRoots(f.cfg); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	fields := make([]string, 0, len(storeStateExcludedConfigFields))
	for field := range storeStateExcludedConfigFields {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			outside := f.cfg
			setConfigPath(t, &outside, field, filepath.Join(filepath.Dir(f.parent), "secrets", "x"))
			if _, err := storeStateRoots(outside); err != nil {
				t.Fatalf("an excluded path outside every root was refused: %v", err)
			}
			inside := f.cfg
			setConfigPath(t, &inside, field, filepath.Join(f.cfg.PrivateStageDir, "planted"))
			_, err := storeStateRoots(inside)
			if storerecovery.RefusalName(err) != refusalStoreStateSecretInsideRoot || !strings.Contains(err.Error(), field) {
				t.Fatalf("%s inside the private stage = %v, want %s naming the field", field, err, refusalStoreStateSecretInsideRoot)
			}
			if _, err := exportStoreState(inside, f.operator, &bytes.Buffer{}, f.opts); storerecovery.RefusalName(err) != refusalStoreStateSecretInsideRoot {
				t.Fatalf("export with %s inside a root = %v", field, err)
			}
		})
	}
}

func TestStoreStateOutputIsNeverReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.tar")
	if err := writeNewStoreStateFile(path, func(w io.Writer) error { _, err := w.Write([]byte("first")); return err }); err != nil {
		t.Fatal(err)
	}
	err := writeNewStoreStateFile(path, func(w io.Writer) error { _, err := w.Write([]byte("second")); return err })
	if storerecovery.RefusalName(err) != refusalStoreStateOutputExists {
		t.Fatalf("second write = %v, want %s", err, refusalStoreStateOutputExists)
	}
	if got, _ := os.ReadFile(path); string(got) != "first" {
		t.Fatalf("output replaced: %q", got)
	}
	failed := filepath.Join(dir, "failed.tar")
	if err := writeNewStoreStateFile(failed, func(io.Writer) error { return storerecovery.Refuse("export-refused", "") }); err == nil {
		t.Fatal("a failed export reported success")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("a failed export left %d files", len(entries))
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode %v", info.Mode())
	}
}

// The export file is written outside every state root: a file growing inside
// a root would be part of the state it records.
func TestStoreStateExportFileIsOutsideTheRootsAndVerifies(t *testing.T) {
	f := newStoreStateFixture(t)
	for _, inside := range []string{filepath.Join(f.cfg.DistDir, "state.tar"), filepath.Join(f.cfg.PrivateStageDir, "rollouts", "state.tar")} {
		if _, err := exportStoreStateToFile(f.cfg, f.operator, inside, f.opts); storerecovery.RefusalName(err) != refusalStoreStateOutputInsideRoot {
			t.Fatalf("export into %s = %v, want %s", inside, err, refusalStoreStateOutputInsideRoot)
		}
		if _, err := os.Lstat(inside); !os.IsNotExist(err) {
			t.Fatalf("a refused export wrote %s", inside)
		}
	}
	out := filepath.Join(t.TempDir(), "state.tar")
	summary, err := exportStoreStateToFile(f.cfg, f.operator, out, f.opts)
	if err != nil {
		t.Fatalf("positive control: %v", err)
	}
	file, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	verified, err := storerecovery.VerifyState(file, f.operator.Public().SignPubkeyB58, f.cfg.StoreID)
	if err != nil || verified.StreamSHA256 != summary.StreamSHA256 || verified.StreamBytes != summary.StreamBytes {
		t.Fatalf("the exported file does not verify as the reported stream: %+v, %v", verified, err)
	}
	if _, err := exportStoreStateToFile(f.cfg, f.operator, out, f.opts); storerecovery.RefusalName(err) != refusalStoreStateOutputExists {
		t.Fatalf("a second export onto the same file = %v", err)
	}
}

// A new estate's Store has a genesis trust root. A state that carries a
// catalog migration record is not a new estate's state and is refused.
func TestStoreStateRefusesALegacyMigrationTrustRoot(t *testing.T) {
	f := newStoreStateFixture(t)
	if _, err := exportStoreState(f.cfg, f.operator, &bytes.Buffer{}, f.opts); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	if err := os.WriteFile(filepath.Join(f.cfg.CatalogMigrationStateDir, catalogMigrationStateName), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := exportStoreState(f.cfg, f.operator, &bytes.Buffer{}, f.opts); storerecovery.RefusalName(err) != refusalStoreStateTrustRootNotGenesis {
		t.Fatalf("export beside a migration record = %v, want %s", err, refusalStoreStateTrustRootNotGenesis)
	}
}

// A stream is restored only as the generation it names: an operator-signed
// stream whose manifest names another current generation is refused.
func TestStoreStateImportRefusesAStreamNamingAnotherCurrent(t *testing.T) {
	f := newStoreStateFixture(t)
	roots, err := storeStateRoots(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	other := appCatalogGenerationPrefix + strings.Repeat("f", 32)
	if other == f.current {
		t.Fatal("fixture: the other generation is the current one")
	}
	var signed bytes.Buffer
	if _, err := storerecovery.ExportState(&signed, roots, storerecovery.StateHeader{StoreID: f.cfg.StoreID, OperatorKey: f.operator.Public().SignPubkeyB58, CurrentGeneration: other}, f.operator.Sign); err != nil {
		t.Fatal(err)
	}
	f.destroyHost(t)
	_, err = importStoreState(f.cfg, bytes.NewReader(signed.Bytes()), f.operator.Public().SignPubkeyB58, f.opts)
	if storerecovery.RefusalName(err) != refusalStoreStateCurrentMismatch {
		t.Fatalf("import of a stream naming another current = %v, want %s", err, refusalStoreStateCurrentMismatch)
	}
	requireEmptyStoreParent(t, f.parent)
}
