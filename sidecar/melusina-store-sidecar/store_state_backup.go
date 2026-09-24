package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/storerecovery"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// Store state as a backup subject (M25 of the off-box backup, restore and
// recovery kit spec).
//
// store-state-export writes one store-state-tar-v1 stream of every durable
// Store root the configuration names, signed by the enrolled operator, under
// the Store's writer exclusion: the serving Store holds that lock for its
// whole life, so the export runs while the Store is stopped. Before it writes
// a byte it verifies the state exactly as a restore will: a committed genesis
// trust root, the nonce sentinel bound to this private stage, the current
// catalog generation verified against every durable rollout, and an
// owner-signed enrollment naming this operator. A state that could not be
// restored is never backed up.
//
// store-state-import restores such a stream onto a replacement host's empty
// roots. The stream must be signed by the operator key the caller already
// trusts (the recovery kit's rootStore.operatorKey), and the same verification
// runs against the staged state before anything is moved onto a root. It
// derives no operator and writes no chain state; the restored Store then
// passes the ordinary startup gate, which re-verifies its enrollment, identity
// and every catalog selection against the chain.
//
// The deployer carries the stream: it seals it with backupcrypto into a
// RemoteBak namespace of subject kind store-state
// (storerecovery.StateNamespace), and on restore hands back the exact bytes.
const (
	storeStateRootCatalogGenerations    = "catalog-generations"
	storeStateRootCatalogMigrationState = "catalog-migration-state"
	storeStateRootCatalogRepo           = "catalog-repo"
	storeStateRootDist                  = "dist"
	storeStateRootEstateEnrollment      = "estate-enrollment-state"
	storeStateRootPrivateStage          = "private-stage"

	refusalStoreStateRequiresEnrollment   = "store-state-requires-enrollment"
	refusalStoreStateRequiresOperator     = "store-state-requires-operator"
	refusalStoreStateSecretInsideRoot     = "store-state-secret-inside-root"
	refusalStoreStateWriterExclusion      = "store-state-writer-exclusion"
	refusalStoreStateTrustRootNotGenesis  = "store-state-trust-root-not-genesis"
	refusalStoreStateTrustRootUncommitted = "store-state-trust-root-uncommitted"
	refusalStoreStateLedgerPathMismatch   = "store-state-ledger-path-mismatch"
	refusalStoreStateCurrentMismatch      = "store-state-current-generation-mismatch"
	refusalStoreStateCatalogUnverified    = "store-state-catalog-unverified"
	refusalStoreStateEnrollmentOperator   = "store-state-enrollment-operator-mismatch"
	refusalStoreStateOutputExists         = "store-state-output-exists"
	refusalStoreStateOutputInsideRoot     = "store-state-output-inside-root"
)

// storeStateRootConfigFields are the Config fields whose paths are Store state
// roots, by JSON name. storeStateExcludedConfigFields are every other
// path-valued field, with the reason it is not state. Together they classify
// every path in Config; TestStoreStateClassifiesEveryConfigPath fails by field
// name when a new path field has no class.
var storeStateRootConfigFields = map[string]string{
	"catalog_generation_root":      storeStateRootCatalogGenerations,
	"catalog_migration_state_dir":  storeStateRootCatalogMigrationState,
	"catalog_repo_root":            storeStateRootCatalogRepo,
	"dist_dir":                     storeStateRootDist,
	"estate_enrollment_state_path": storeStateRootEstateEnrollment,
	"private_stage_dir":            storeStateRootPrivateStage,
}

var storeStateExcludedConfigFields = map[string]string{
	"boot_identity.shards_dir":               "secret: the operator shards leave the host only through shard-wise identity escrow",
	"boot_identity.tls_cert_path":            "host-bound: a replacement host binds its own certificate through an owner-signed enrollment successor",
	"tls.cert_path":                          "host-bound: a replacement host binds its own certificate through an owner-signed enrollment successor",
	"tls.key_path":                           "secret: a TLS private key is never backed up",
	"store_link_control_mtls.cert_path":      "host-bound: the control listener certificate is issued to the host",
	"store_link_control_mtls.key_path":       "secret: a TLS private key is never backed up",
	"store_link_control_mtls.client_ca_path": "host-bound trust input, provisioned with the host",
	"listing_signer_socket":                  "runtime socket, created by the listing signer at start",
	"served_snapshot_dir":                    "transient: unnamed per-request copies of served artifacts; the Store recreates the empty directory at start",
}

type storeStateOptions struct {
	expectedUID uint32
	expectedGID uint32
	now         func() time.Time
}

func productionStoreStateOptions() storeStateOptions {
	opts := productionCatalogBootstrapOptions()
	return storeStateOptions{expectedUID: opts.expectedUID, expectedGID: opts.expectedGID, now: time.Now}
}

func (cfg Config) withStoreStateRoots(paths map[string]string) Config {
	at := cfg
	at.CatalogGenerationRoot = paths[storeStateRootCatalogGenerations]
	at.CatalogMigrationStateDir = paths[storeStateRootCatalogMigrationState]
	at.CatalogRepoRoot = paths[storeStateRootCatalogRepo]
	at.DistDir = paths[storeStateRootDist]
	at.EstateEnrollmentStatePath = paths[storeStateRootEstateEnrollment]
	at.PrivateStageDir = paths[storeStateRootPrivateStage]
	return at
}

// storeStateRoots is the complete set of durable Store roots, named for the
// stream. Every root must be an absolute clean path; an enrolled Store names
// all six.
func storeStateRoots(cfg Config) ([]storerecovery.Root, error) {
	if strings.TrimSpace(cfg.EstateEnrollmentStatePath) == "" {
		return nil, storerecovery.Refuse(refusalStoreStateRequiresEnrollment, "estate_enrollment_state_path")
	}
	fields := []struct {
		field, name, path string
		kind              storerecovery.RootKind
	}{
		{"catalog_generation_root", storeStateRootCatalogGenerations, cfg.CatalogGenerationRoot, storerecovery.RootDirectory},
		{"catalog_migration_state_dir", storeStateRootCatalogMigrationState, cfg.CatalogMigrationStateDir, storerecovery.RootDirectory},
		{"catalog_repo_root", storeStateRootCatalogRepo, cfg.CatalogRepoRoot, storerecovery.RootDirectory},
		{"dist_dir", storeStateRootDist, cfg.DistDir, storerecovery.RootDirectory},
		{"estate_enrollment_state_path", storeStateRootEstateEnrollment, cfg.EstateEnrollmentStatePath, storerecovery.RootFile},
		{"private_stage_dir", storeStateRootPrivateStage, cfg.PrivateStageDir, storerecovery.RootDirectory},
	}
	roots := make([]storerecovery.Root, 0, len(fields))
	for _, field := range fields {
		if !filepath.IsAbs(field.path) || filepath.Clean(field.path) != field.path || field.path == string(filepath.Separator) {
			return nil, storerecovery.Refuse(storerecovery.RefusalStateRootInvalid, field.field+" must be an absolute clean path")
		}
		roots = append(roots, storerecovery.Root{Name: field.name, Kind: field.kind, Path: field.path})
	}
	if err := requireStoreSecretsOutsideState(cfg, roots); err != nil {
		return nil, err
	}
	return roots, nil
}

// storeStateExcludedPath returns the configured value of one excluded field.
func storeStateExcludedPath(cfg Config, field string) (string, bool) {
	switch field {
	case "boot_identity.shards_dir":
		return cfg.BootIdentity.ShardsDir, true
	case "boot_identity.tls_cert_path":
		return cfg.BootIdentity.TLSCertPath, true
	case "tls.cert_path":
		return cfg.TLS.CertPath, true
	case "tls.key_path":
		return cfg.TLS.KeyPath, true
	case "store_link_control_mtls.cert_path":
		return cfg.StoreLinkControlMTLS.CertPath, true
	case "store_link_control_mtls.key_path":
		return cfg.StoreLinkControlMTLS.KeyPath, true
	case "store_link_control_mtls.client_ca_path":
		return cfg.StoreLinkControlMTLS.ClientCAPath, true
	case "listing_signer_socket":
		return cfg.ListingSignerSocket, true
	case "served_snapshot_dir":
		return cfg.ServedSnapshotDir, true
	}
	return "", false
}

// requireStoreSecretsOutsideState refuses a configuration that keeps a secret
// or host-bound path inside a state root, where the export would carry it.
func requireStoreSecretsOutsideState(cfg Config, roots []storerecovery.Root) error {
	for field := range storeStateExcludedConfigFields {
		path, handled := storeStateExcludedPath(cfg, field)
		if !handled {
			return storerecovery.Refuse(refusalStoreStateSecretInsideRoot, field+" has no check")
		}
		if strings.TrimSpace(path) == "" {
			continue
		}
		absolute, err := filepath.Abs(strings.TrimSpace(path))
		if err != nil {
			return storerecovery.Refuse(refusalStoreStateSecretInsideRoot, field)
		}
		for _, root := range roots {
			if pathContains(root.Path, absolute) {
				return storerecovery.Refuse(refusalStoreStateSecretInsideRoot, field+" is inside "+root.Name)
			}
		}
	}
	return nil
}

// exportStoreState writes the stream for cfg while holding the Store's
// writer exclusion. The operator must be the enrolled operator.
func exportStoreState(cfg Config, operator *identity.Private, out io.Writer, opts storeStateOptions) (storerecovery.StateSummary, error) {
	if operator == nil {
		return storerecovery.StateSummary{}, storerecovery.Refuse(refusalStoreStateRequiresOperator, "")
	}
	roots, err := storeStateRoots(cfg)
	if err != nil {
		return storerecovery.StateSummary{}, err
	}
	lock, err := acquireExistingWriterLockOwned(filepath.Join(cfg.CatalogMigrationStateDir, storeWriterLockName), opts.expectedUID, opts.expectedGID)
	if err != nil {
		return storerecovery.StateSummary{}, storerecovery.Refuse(refusalStoreStateWriterExclusion, err.Error())
	}
	defer lock.Close()
	public := operator.Public()
	operatorKey, err := public.SignPublicKey()
	if err != nil {
		return storerecovery.StateSummary{}, storerecovery.Refuse(refusalStoreStateRequiresOperator, err.Error())
	}
	current, err := verifyStoreStateAt(cfg, cfg, operatorKey, "", opts)
	if err != nil {
		return storerecovery.StateSummary{}, err
	}
	return storerecovery.ExportState(out, roots, storerecovery.StateHeader{StoreID: cfg.StoreID, OperatorKey: public.SignPubkeyB58, CurrentGeneration: current}, operator.Sign)
}

// importStoreState restores a stream onto cfg's roots, which must be empty.
func importStoreState(cfg Config, in io.Reader, operatorKeyB58 string, opts storeStateOptions) (storerecovery.StateSummary, error) {
	roots, err := storeStateRoots(cfg)
	if err != nil {
		return storerecovery.StateSummary{}, err
	}
	operatorKey, err := parseStoreOperatorKey(operatorKeyB58)
	if err != nil {
		return storerecovery.StateSummary{}, err
	}
	return storerecovery.ImportState(in, storerecovery.ImportOptions{
		OperatorKey: operatorKeyB58, StoreID: cfg.StoreID, Targets: roots,
		BeforeCommit: func(manifest storerecovery.StateManifestV1, staged map[string]string) error {
			if manifest.CurrentGeneration == "" {
				return storerecovery.Refuse(refusalStoreStateCurrentMismatch, "the stream names no current generation")
			}
			_, err := verifyStoreStateAt(cfg, cfg.withStoreStateRoots(staged), operatorKey, manifest.CurrentGeneration, opts)
			return err
		},
	})
}

func parseStoreOperatorKey(value string) (ed25519.PublicKey, error) {
	key, err := primitives.PubkeyFromBase58(strings.TrimSpace(value))
	if err != nil || key.Base58() != value {
		return nil, storerecovery.Refuse(storerecovery.RefusalStateOperatorMismatch, "the operator key is not a canonical base58 Ed25519 key")
	}
	return ed25519.PublicKey(append([]byte(nil), key[:]...)), nil
}

// verifyStoreStateAt checks the state whose roots are at, for the Store cfg
// describes, without writing: the paths at may be the live roots (export) or
// a restore's staging (import). cfg supplies the final private stage the nonce
// sentinel must bind, the serving domain and the release authority. It returns
// the verified current generation.
func verifyStoreStateAt(cfg, at Config, operatorKey ed25519.PublicKey, expectedCurrent string, opts storeStateOptions) (string, error) {
	migrationExists, err := lstatExists(filepath.Join(at.CatalogMigrationStateDir, catalogMigrationStateName))
	if err != nil {
		return "", storerecovery.Refuse(refusalStoreStateTrustRootNotGenesis, err.Error())
	}
	if migrationExists {
		return "", storerecovery.Refuse(refusalStoreStateTrustRootNotGenesis, "a catalog migration record is present")
	}
	genesis, err := readCatalogGenesisState(filepath.Join(at.CatalogMigrationStateDir, catalogGenesisStateName), opts.expectedUID)
	if err != nil {
		return "", storerecovery.Refuse(refusalStoreStateTrustRootNotGenesis, err.Error())
	}
	if err := validateCatalogGenesisState(genesis); err != nil {
		return "", storerecovery.Refuse(refusalStoreStateTrustRootNotGenesis, err.Error())
	}
	if genesis.State != "committed" {
		return "", storerecovery.Refuse(refusalStoreStateTrustRootUncommitted, genesis.State)
	}

	// The sentinel binds the nonce ledger to its absolute path on the Store
	// that created it, so the state restores only onto that same private stage.
	finalLedgerRoot := filepath.Join(cfg.PrivateStageDir, publishNonceLedgerDirName)
	raw, err := readOwnedRegular(filepath.Join(at.CatalogGenerationRoot, catalogNonceSentinelName), 0o600, opts.expectedUID, maxCatalogBootstrapJSON)
	if err != nil {
		return "", storerecovery.Refuse(refusalStoreStateTrustRootUncommitted, "nonce sentinel: "+err.Error())
	}
	var sentinel catalogNonceSentinel
	if err := decodeCatalogStrictJSON(raw, &sentinel); err != nil {
		return "", storerecovery.Refuse(refusalStoreStateTrustRootUncommitted, "nonce sentinel: "+err.Error())
	}
	if sentinel.LedgerPathSHA256 != desiredCatalogSentinel(finalLedgerRoot, genesis.LedgerID).LedgerPathSHA256 {
		return "", storerecovery.Refuse(refusalStoreStateLedgerPathMismatch, "the state's nonce ledger was created at another private_stage_dir")
	}
	if err := validateCatalogSentinel(at.CatalogGenerationRoot, finalLedgerRoot, genesis.LedgerID, opts.expectedUID); err != nil {
		return "", storerecovery.Refuse(refusalStoreStateTrustRootUncommitted, err.Error())
	}

	if err := requireOwnedSecureDirectory(rolloutStateDir(at), 0o700, opts.expectedUID); err != nil {
		return "", storerecovery.Refuse(refusalStoreStateCatalogUnverified, "rollout state: "+err.Error())
	}
	classified, err := classifyRolloutStatesAt(at, opts.now().UTC())
	if err != nil {
		return "", storerecovery.Refuse(refusalStoreStateCatalogUnverified, err.Error())
	}
	generations := AppCatalogGenerationStore{Root: at.CatalogGenerationRoot}
	current, err := generations.ResolveCurrent()
	if err != nil {
		return "", storerecovery.Refuse(refusalStoreStateCatalogUnverified, err.Error())
	}
	if expectedCurrent != "" && current.ID != expectedCurrent {
		return "", storerecovery.Refuse(refusalStoreStateCurrentMismatch, current.ID)
	}
	authority, err := cfg.sharedSquadsAuthority()
	if err != nil {
		return "", storerecovery.Refuse(refusalStoreStateCatalogUnverified, err.Error())
	}
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	if err := verifyAppCatalogGeneration(current, classified.serving, operatorKey, hex.EncodeToString(domainHash[:]), at.PrivateStageDir, authority, opts.expectedUID, opts.expectedGID); err != nil {
		return "", storerecovery.Refuse(refusalStoreStateCatalogUnverified, current.ID+": "+err.Error())
	}

	enrollment, err := readStoreEnrollmentState(at.EstateEnrollmentStatePath, opts.expectedUID)
	if err != nil {
		return "", storerecovery.Refuse(refusalStoreStateEnrollmentOperator, err.Error())
	}
	if enrollment.Enrollment.StoreOperatorKey != primitives.EncodeBase58(operatorKey) {
		return "", storerecovery.Refuse(refusalStoreStateEnrollmentOperator, enrollment.Enrollment.StoreOperatorKey)
	}
	return current.ID, nil
}

// exportStoreStateToFile exports into a new file outside every state root:
// a file being written inside a root would be part of the state it records.
func exportStoreStateToFile(cfg Config, operator *identity.Private, path string, opts storeStateOptions) (storerecovery.StateSummary, error) {
	roots, err := storeStateRoots(cfg)
	if err != nil {
		return storerecovery.StateSummary{}, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return storerecovery.StateSummary{}, err
	}
	for _, root := range roots {
		if pathContains(root.Path, absolute) {
			return storerecovery.StateSummary{}, storerecovery.Refuse(refusalStoreStateOutputInsideRoot, root.Name)
		}
	}
	var summary storerecovery.StateSummary
	err = writeNewStoreStateFile(absolute, func(w io.Writer) error {
		var exportErr error
		summary, exportErr = exportStoreState(cfg, operator, w, opts)
		return exportErr
	})
	return summary, err
}

// writeNewStoreStateFile runs write against a new mode-0600 temporary file in
// path's directory, syncs it and links it to path, which must not exist. A
// failed export leaves nothing at path.
func writeNewStoreStateFile(path string, write func(io.Writer) error) error {
	path = filepath.Clean(path)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return storerecovery.Refuse(refusalStoreStateOutputExists, path)
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".partial-"+hex.EncodeToString(nonce[:]))
	f, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := write(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Link(temporary, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return storerecovery.Refuse(refusalStoreStateOutputExists, path)
		}
		return err
	}
	return publishNonceSyncDir(filepath.Dir(path))
}

type storeStateReport struct {
	Schema            string `json:"schema"`
	Action            string `json:"action"`
	Format            string `json:"format"`
	SubjectKind       string `json:"subjectKind"`
	StoreID           string `json:"storeId"`
	OperatorKey       string `json:"operatorKey"`
	CurrentGeneration string `json:"currentGeneration"`
	Members           int    `json:"members"`
	ManifestSHA256    string `json:"manifestSha256"`
	StreamSHA256      string `json:"streamSha256"`
	StreamBytes       int64  `json:"streamBytes"`
}

func printStoreStateReport(action string, summary storerecovery.StateSummary) {
	report := storeStateReport{
		Schema: "melusina.store-state-report.v1", Action: action,
		Format: storerecovery.StateFormat, SubjectKind: storerecovery.StateSubjectKind,
		StoreID: summary.Manifest.StoreID, OperatorKey: summary.Manifest.OperatorKey,
		CurrentGeneration: summary.Manifest.CurrentGeneration, Members: len(summary.Manifest.Members),
		ManifestSHA256: summary.ManifestSHA256, StreamSHA256: summary.StreamSHA256, StreamBytes: summary.StreamBytes,
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("%s: encode report: %v", action, err)
	}
	fmt.Println(string(encoded))
}

// runStoreStateExportSubcommand acts with the operator key, so it passes the
// enrollment gate first; its first action beyond the gate is the writer
// exclusion, which a running Store holds.
func runStoreStateExportSubcommand(args []string) {
	fs := flag.NewFlagSet("store-state-export", flag.ExitOnError)
	configPath := fs.String("config", "store.config.json", "path to operator config (JSON)")
	outPath := fs.String("out", "", "new file to write the store-state-tar-v1 stream to (refused if it exists)")
	_ = fs.Parse(args)
	if strings.TrimSpace(*outPath) == "" {
		log.Fatalf("store-state-export: -out is required")
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := setProgramIDFromConfig(cfg.ProgramID); err != nil {
		log.Fatalf("config: %v", err)
	}
	var cr chainReader
	if cfg.RPCURL != "" {
		cr = newConfiguredStoreRPCReader(cfg)
	}
	bootCtx, bootCancel := context.WithTimeout(context.Background(), 30*time.Second)
	operator, err := deriveEnrolledOperator(bootCtx, cfg, *configPath, cr)
	bootCancel()
	if err != nil {
		log.Fatalf("store-state-export: %v", err)
	}
	summary, err := exportStoreStateToFile(cfg, operator, *outPath, productionStoreStateOptions())
	if err != nil {
		log.Fatalf("store-state-export: %v", err)
	}
	printStoreStateReport("store-state-export", summary)
}

// runStoreStateVerifySubcommand checks a stream offline and writes nothing.
func runStoreStateVerifySubcommand(args []string) {
	fs := flag.NewFlagSet("store-state-verify", flag.ExitOnError)
	inPath := fs.String("in", "", "store-state-tar-v1 stream to verify")
	operatorKey := fs.String("operator-key", "", "base58 Store operator key the stream must be signed by (the recovery kit's rootStore.operatorKey)")
	storeID := fs.String("store-id", "", "Store ID the stream must belong to")
	_ = fs.Parse(args)
	if *inPath == "" || *operatorKey == "" || *storeID == "" {
		log.Fatalf("store-state-verify: -in, -operator-key and -store-id are required")
	}
	f, err := os.Open(*inPath)
	if err != nil {
		log.Fatalf("store-state-verify: %v", err)
	}
	defer f.Close()
	summary, err := storerecovery.VerifyState(f, *operatorKey, *storeID)
	if err != nil {
		log.Fatalf("store-state-verify: %v", err)
	}
	printStoreStateReport("store-state-verify", summary)
}

// runStoreStateImportSubcommand restores a stream onto this host's empty
// roots. It derives no operator; the restored Store passes the startup gate.
func runStoreStateImportSubcommand(args []string) {
	fs := flag.NewFlagSet("store-state-import", flag.ExitOnError)
	configPath := fs.String("config", "store.config.json", "path to the replacement host's operator config (JSON)")
	inPath := fs.String("in", "", "store-state-tar-v1 stream to restore")
	operatorKey := fs.String("operator-key", "", "base58 Store operator key the stream must be signed by (the recovery kit's rootStore.operatorKey)")
	_ = fs.Parse(args)
	if *inPath == "" || *operatorKey == "" {
		log.Fatalf("store-state-import: -in and -operator-key are required")
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := setProgramIDFromConfig(cfg.ProgramID); err != nil {
		log.Fatalf("config: %v", err)
	}
	f, err := os.Open(*inPath)
	if err != nil {
		log.Fatalf("store-state-import: %v", err)
	}
	defer f.Close()
	summary, err := importStoreState(cfg, f, *operatorKey, productionStoreStateOptions())
	if err != nil {
		log.Fatalf("store-state-import: %v", err)
	}
	printStoreStateReport("store-state-import", summary)
}
