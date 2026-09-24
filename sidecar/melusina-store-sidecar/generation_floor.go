package main

// A generation floor for a restored Store (seam audit round 2, finding 2;
// Store commit 9 of the first-install spec).
//
// A Store-state restore brings update/generation.json back at the generation
// the Store had when the backup was taken. Tenant controllers may already hold
// a later generation, committed or Pending. They refuse a lower id as a
// downgrade and the same id with other bytes as equivocation
// (internal/hostupdate.AcceptAgainstCursor and PollOnce's Pending check). Any
// forward gap is accepted. The promote path used to move only to current + 1,
// so a restored Store could not get past those cursors.
//
// store-generation-floor records one operator-signed floor F, bound to the
// exact current generation: its id, its generationHash and the SHA-256 of its
// served bytes. The next promote then chains from the floor, with
// previousGeneration F and generationId F + 1. It must not chain from the
// restored current, because a tenant whose cursor is past the backup refuses a
// successor behind that cursor as a fork. The stale-promote check on
// expectedCurrentGeneration is unchanged, and that one promotion may carry the
// current components forward with no update. After it, the current generation
// no longer matches the record's binding, so the floor is spent without
// deleting anything. Every record stays in the journal directory as evidence,
// and a later floor must be above every floor already recorded there: a
// recorded floor F may have produced a served generation F + 1.
//
// The operator chooses F from the recovery kit's last promoted generation and
// from every committed and Pending generation the tenants report at restore
// time. A margin is allowed, because a gap is legal.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	desiredGenerationFloorSchema     = "melusina-desired-generation-floor-v1"
	desiredGenerationFloorDirName    = "desired-generation-floors-v1"
	maxDesiredGenerationFloorRecords = 256
	maxDesiredGenerationFloorJSON    = 16 << 10
	// A floor keeps F + 1 at or below 2^53 - 1, so the generation it produces
	// is an exact JSON number for every consumer, not only for Go's uint64. A
	// mistyped floor can waste ids but cannot wrap them.
	maxDesiredGenerationFloorID uint64 = 1<<53 - 2

	refusalGenerationFloorOptions           = "generation-floor-options"
	refusalGenerationFloorOutOfRange        = "generation-floor-out-of-range"
	refusalGenerationFloorNoCurrent         = "generation-floor-no-current"
	refusalGenerationFloorCurrentUnverified = "generation-floor-current-unverified"
	refusalGenerationFloorCurrentMismatch   = "generation-floor-current-mismatch"
	refusalGenerationFloorNotAboveCurrent   = "generation-floor-not-above-current"
	refusalGenerationFloorNotAboveJournal   = "generation-floor-not-above-journal"
	refusalGenerationFloorJournalInvalid    = "generation-floor-journal-invalid"
)

// desiredGenerationFloor is one journal record. The operator signs every field
// except the signature.
type desiredGenerationFloor struct {
	Schema                string `json:"schema"`
	StoreID               string `json:"storeId"`
	FloorGenerationID     uint64 `json:"floorGenerationId"`
	CurrentGenerationID   uint64 `json:"currentGenerationId"`
	CurrentGenerationHash string `json:"currentGenerationHash"`
	CurrentRawSHA256      string `json:"currentRawSha256"`
	Reason                string `json:"reason"`
	EvidenceSHA256        string `json:"evidenceSha256"`
	RecordedAtUnix        int64  `json:"recordedAtUnix"`
	OperatorPubkey        string `json:"operatorPubkey"`
	OperatorSignature     string `json:"operatorSignature"`
}

func (r desiredGenerationFloor) signingPayload() ([]byte, error) {
	type payload struct {
		Schema                string `json:"schema"`
		StoreID               string `json:"storeId"`
		FloorGenerationID     uint64 `json:"floorGenerationId"`
		CurrentGenerationID   uint64 `json:"currentGenerationId"`
		CurrentGenerationHash string `json:"currentGenerationHash"`
		CurrentRawSHA256      string `json:"currentRawSha256"`
		Reason                string `json:"reason"`
		EvidenceSHA256        string `json:"evidenceSha256"`
		RecordedAtUnix        int64  `json:"recordedAtUnix"`
		OperatorPubkey        string `json:"operatorPubkey"`
	}
	return json.Marshal(payload{
		Schema: r.Schema, StoreID: r.StoreID, FloorGenerationID: r.FloorGenerationID,
		CurrentGenerationID: r.CurrentGenerationID, CurrentGenerationHash: r.CurrentGenerationHash,
		CurrentRawSHA256: r.CurrentRawSHA256, Reason: r.Reason, EvidenceSHA256: r.EvidenceSHA256,
		RecordedAtUnix: r.RecordedAtUnix, OperatorPubkey: r.OperatorPubkey,
	})
}

func validGenerationFloorReason(reason string) bool {
	return strings.TrimSpace(reason) != "" && strings.TrimSpace(reason) == reason && len(reason) <= maxCatalogRetirementText
}

// validate checks the record's fields and its signature under the operator key
// that signs this Store's generations.
func (r desiredGenerationFloor) validate(storeID string, operatorKey ed25519.PublicKey) error {
	if r.Schema != desiredGenerationFloorSchema {
		return fmt.Errorf("schema %q", r.Schema)
	}
	if strings.TrimSpace(storeID) == "" || r.StoreID != storeID {
		return fmt.Errorf("storeId %q is not this Store's %q", r.StoreID, storeID)
	}
	if r.CurrentGenerationID == 0 || r.FloorGenerationID <= r.CurrentGenerationID {
		return fmt.Errorf("floor %d is not above its current generation %d", r.FloorGenerationID, r.CurrentGenerationID)
	}
	if r.FloorGenerationID > maxDesiredGenerationFloorID {
		return fmt.Errorf("floor %d exceeds %d", r.FloorGenerationID, maxDesiredGenerationFloorID)
	}
	if !isLowerHex(r.CurrentGenerationHash, 64) || !isLowerHex(r.CurrentRawSHA256, 64) || !isLowerHex(r.EvidenceSHA256, 64) {
		return errors.New("a digest is not 64 lowercase hex characters")
	}
	if !validGenerationFloorReason(r.Reason) || r.RecordedAtUnix <= 0 {
		return errors.New("reason or recordedAtUnix is malformed")
	}
	if len(operatorKey) != ed25519.PublicKeySize || r.OperatorPubkey != primitives.EncodeBase58(operatorKey) {
		return errors.New("signer is not this Store's operator")
	}
	sig, err := primitives.DecodeBase58(r.OperatorSignature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("operator signature is malformed")
	}
	payload, err := r.signingPayload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(operatorKey, payload, sig) {
		return errors.New("operator signature is invalid")
	}
	return nil
}

// bindsCurrent reports whether this record was made against exactly the
// generation the Store now serves.
func (r desiredGenerationFloor) bindsCurrent(current componentrelease.DesiredGeneration, currentRaw []byte) bool {
	sum := sha256.Sum256(currentRaw)
	return r.CurrentGenerationID == current.GenerationID &&
		r.CurrentGenerationHash == current.GenerationHash &&
		r.CurrentRawSHA256 == hex.EncodeToString(sum[:])
}

func desiredGenerationFloorDir(cfg Config) string {
	return filepath.Join(cfg.CatalogMigrationStateDir, desiredGenerationFloorDirName)
}

func desiredGenerationFloorName(floor uint64) string {
	return fmt.Sprintf("floor-%020d.json", floor)
}

// parseDesiredGenerationFloorName accepts exactly the names
// desiredGenerationFloorName writes.
func parseDesiredGenerationFloorName(name string) (uint64, bool) {
	digits, ok := strings.CutPrefix(name, "floor-")
	if !ok {
		return 0, false
	}
	digits, ok = strings.CutSuffix(digits, ".json")
	if !ok || len(digits) != 20 {
		return 0, false
	}
	floor, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || desiredGenerationFloorName(floor) != name {
		return 0, false
	}
	return floor, true
}

// readDesiredGenerationFloors returns every journal record in floor order. A
// Store with no migration state directory, or no journal yet, has none. Any
// member that is not a valid record signed by operatorKey for storeID refuses
// the whole journal by name: this is operator-signed state, and a member that
// does not verify is not something to skip.
func readDesiredGenerationFloors(cfg Config, storeID string, operatorKey ed25519.PublicKey) ([]desiredGenerationFloor, error) {
	if strings.TrimSpace(cfg.CatalogMigrationStateDir) == "" {
		return nil, nil
	}
	refuse := func(format string, args ...any) error {
		return fmt.Errorf("%s: %s", refusalGenerationFloorJournalInvalid, fmt.Sprintf(format, args...))
	}
	dir := desiredGenerationFloorDir(cfg)
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, refuse("%v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, refuse("%s is not a mode-0700 real directory", dir)
	}
	entries, err := readDirBounded(dir, maxDesiredGenerationFloorRecords)
	if err != nil {
		return nil, refuse("%v", err)
	}
	records := make([]desiredGenerationFloor, 0, len(entries))
	for _, entry := range entries {
		floor, ok := parseDesiredGenerationFloorName(entry.Name())
		if !ok || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, refuse("unexpected member %s", entry.Name())
		}
		body, err := readDesiredGenerationFloorFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, refuse("%s: %v", entry.Name(), err)
		}
		if err := assertNoDuplicateJSONKeys(body); err != nil {
			return nil, refuse("%s: %v", entry.Name(), err)
		}
		var record desiredGenerationFloor
		if err := decodeCatalogStrictJSON(body, &record); err != nil {
			return nil, refuse("%s: %v", entry.Name(), err)
		}
		if record.FloorGenerationID != floor {
			return nil, refuse("%s names floor %d", entry.Name(), record.FloorGenerationID)
		}
		if err := record.validate(storeID, operatorKey); err != nil {
			return nil, refuse("%s: %v", entry.Name(), err)
		}
		records = append(records, record)
	}
	return records, nil
}

func readDesiredGenerationFloorFile(path string) ([]byte, error) {
	f, size, err := openDistRegularNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm() != 0o600 || size <= 0 || size > maxDesiredGenerationFloorJSON {
		return nil, fmt.Errorf("not a bounded mode-0600 regular file (mode %s, %d bytes)", info.Mode().Perm(), size)
	}
	body, err := io.ReadAll(io.LimitReader(f, maxDesiredGenerationFloorJSON+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != size {
		return nil, errors.New("file changed while it was read")
	}
	return body, nil
}

// desiredGenerationFloorFor returns the floor the next promote chains from:
// the highest recorded floor bound to exactly this current generation, or 0.
// The journal is read and verified on every promote, with or without a
// current generation, so a damaged journal is never silently bypassed.
func (s *publishService) desiredGenerationFloorFor(current *componentrelease.DesiredGeneration, currentRaw []byte) (uint64, error) {
	operatorKey, err := operatorSignPublicKey(s.operator)
	if err != nil {
		return 0, fmt.Errorf("%s: %v", refusalGenerationFloorJournalInvalid, err)
	}
	records, err := readDesiredGenerationFloors(s.cfg, s.cfg.StoreID, operatorKey)
	if err != nil || current == nil {
		return 0, err
	}
	var floor uint64
	for _, record := range records {
		if record.bindsCurrent(*current, currentRaw) && record.FloorGenerationID > floor {
			floor = record.FloorGenerationID
		}
	}
	return floor, nil
}

func writeDesiredGenerationFloor(cfg Config, record desiredGenerationFloor, operatorKey ed25519.PublicKey) (string, []byte, error) {
	if err := record.validate(cfg.StoreID, operatorKey); err != nil {
		return "", nil, err
	}
	if err := requireSecureDirectory(cfg.CatalogMigrationStateDir, 0o700); err != nil {
		return "", nil, fmt.Errorf("catalog_migration_state_dir: %w", err)
	}
	dir := desiredGenerationFloorDir(cfg)
	if info, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return "", nil, err
		}
		if err := syncDir(cfg.CatalogMigrationStateDir); err != nil {
			return "", nil, err
		}
	} else if err != nil {
		return "", nil, err
	} else if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return "", nil, fmt.Errorf("%s: %s is not a mode-0700 real directory", refusalGenerationFloorJournalInvalid, dir)
	}
	body, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return "", nil, err
	}
	body = append(body, '\n')
	if len(body) > maxDesiredGenerationFloorJSON {
		return "", nil, errors.New("generation floor record exceeds its size limit")
	}
	path := filepath.Join(dir, desiredGenerationFloorName(record.FloorGenerationID))
	if err := writeSyncedFile(path, body, 0o600); err != nil {
		return "", nil, err
	}
	if err := syncDir(dir); err != nil {
		return "", nil, err
	}
	return path, body, nil
}

type storeGenerationFloorOptions struct {
	floor                     uint64
	expectedCurrentGeneration uint64
	reason                    string
	evidenceSHA256            string
	dryRun                    bool
	apply                     bool
}

func (o storeGenerationFloorOptions) validate() error {
	if o.dryRun == o.apply {
		return fmt.Errorf("%s: pass exactly one of -dry-run or -apply", refusalGenerationFloorOptions)
	}
	if o.floor == 0 || o.expectedCurrentGeneration == 0 {
		return fmt.Errorf("%s: -floor and -expected-current-generation must be positive", refusalGenerationFloorOptions)
	}
	if o.floor > maxDesiredGenerationFloorID {
		return fmt.Errorf("%s: -floor %d exceeds %d", refusalGenerationFloorOutOfRange, o.floor, maxDesiredGenerationFloorID)
	}
	if !validGenerationFloorReason(o.reason) {
		return fmt.Errorf("%s: -reason must be non-empty, without surrounding spaces and at most %d bytes", refusalGenerationFloorOptions, maxCatalogRetirementText)
	}
	if !isLowerHex(o.evidenceSHA256, 64) {
		return fmt.Errorf("%s: -evidence-sha256 must be 64 lowercase hex characters", refusalGenerationFloorOptions)
	}
	return nil
}

type storeGenerationFloorReport struct {
	State               string `json:"state"`
	StoreID             string `json:"storeId"`
	CurrentGenerationID uint64 `json:"currentGenerationId"`
	CurrentRawSHA256    string `json:"currentRawSha256"`
	FloorGenerationID   uint64 `json:"floorGenerationId"`
	NextGenerationID    uint64 `json:"nextGenerationId"`
	RecordPath          string `json:"recordPath,omitempty"`
	RecordSHA256        string `json:"recordSha256,omitempty"`
}

func runStoreGenerationFloorSubcommand(args []string) {
	fs := flag.NewFlagSet("store-generation-floor", flag.ExitOnError)
	opts := storeGenerationFloorOptions{}
	configPath := fs.String("config", "store.config.json", "path to store config")
	fs.Uint64Var(&opts.floor, "floor", 0, "generation the next promote chains from; it must be at least every generation tenants hold and the recovery kit's last promoted generation")
	fs.Uint64Var(&opts.expectedCurrentGeneration, "expected-current-generation", 0, "required id of the generation this Store serves now (the restored one)")
	fs.StringVar(&opts.reason, "reason", "", "durable reason for the floor")
	fs.StringVar(&opts.evidenceSHA256, "evidence-sha256", "", "SHA-256 of the restore evidence the floor was chosen from")
	fs.BoolVar(&opts.dryRun, "dry-run", false, "verify the floor without recording it")
	fs.BoolVar(&opts.apply, "apply", false, "record the signed floor")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		log.Fatalf("store-generation-floor: %s: unexpected arguments %v", refusalGenerationFloorOptions, fs.Args())
	}
	if err := opts.validate(); err != nil {
		log.Fatalf("store-generation-floor: %v", err)
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("store-generation-floor config: %v", err)
	}
	if err := validateCatalogStorageRoots(cfg); err != nil {
		log.Fatalf("store-generation-floor config: %v", err)
	}
	if err := setProgramIDFromConfig(cfg.ProgramID); err != nil {
		log.Fatalf("store-generation-floor config: %v", err)
	}
	cr := newConfiguredStoreRPCReader(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	operator, err := deriveEnrolledOperator(ctx, cfg, *configPath, cr)
	cancel()
	if err != nil {
		log.Fatalf("store-generation-floor: %v", err)
	}
	if operator == nil {
		log.Fatalf("store-generation-floor requires the enrolled boot operator (boot_identity.shards_dir is unset)")
	}
	// The serving Store holds writer.lock for its whole life, so a floor is
	// recorded only while the Store is stopped, never under a live promote.
	lock, err := acquireExistingWriterLock(filepath.Join(cfg.CatalogMigrationStateDir, storeWriterLockName))
	if err != nil {
		log.Fatalf("store-generation-floor writer exclusion: %v", err)
	}
	defer lock.Close()

	report, err := runStoreGenerationFloor(cfg, operator, opts, time.Now().UTC())
	if err != nil {
		log.Fatalf("store-generation-floor: %v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		log.Fatalf("store-generation-floor report: %v", err)
	}
}

// runStoreGenerationFloor checks and, with apply, records one floor. The
// caller holds the writer lock and passes the enrolled operator.
func runStoreGenerationFloor(cfg Config, operator *identity.Private, opts storeGenerationFloorOptions, now time.Time) (storeGenerationFloorReport, error) {
	var report storeGenerationFloorReport
	if err := opts.validate(); err != nil {
		return report, err
	}
	operatorKey, err := operatorSignPublicKey(operator)
	if err != nil {
		return report, fmt.Errorf("%s: %v", refusalGenerationFloorCurrentUnverified, err)
	}
	current, raw, err := loadCurrentGeneration(cfg.DistDir)
	if errors.Is(err, os.ErrNotExist) {
		return report, fmt.Errorf("%s: this Store has no signed generation to raise a floor over", refusalGenerationFloorNoCurrent)
	}
	if err != nil {
		return report, fmt.Errorf("%s: %v", refusalGenerationFloorCurrentUnverified, err)
	}
	if err := componentrelease.Verify(operatorKey, cfg.StoreID, current); err != nil {
		return report, fmt.Errorf("%s: %v", refusalGenerationFloorCurrentUnverified, err)
	}
	if current.GenerationID != opts.expectedCurrentGeneration {
		return report, fmt.Errorf("%s: the Store serves generation %d, not the expected %d", refusalGenerationFloorCurrentMismatch, current.GenerationID, opts.expectedCurrentGeneration)
	}
	if opts.floor <= current.GenerationID {
		return report, fmt.Errorf("%s: floor %d must be above the current generation %d", refusalGenerationFloorNotAboveCurrent, opts.floor, current.GenerationID)
	}
	records, err := readDesiredGenerationFloors(cfg, cfg.StoreID, operatorKey)
	if err != nil {
		return report, err
	}
	for _, record := range records {
		if opts.floor <= record.FloorGenerationID {
			return report, fmt.Errorf("%s: floor %d must be above the recorded floor %d, which may already have produced generation %d", refusalGenerationFloorNotAboveJournal, opts.floor, record.FloorGenerationID, record.FloorGenerationID+1)
		}
	}
	rawSum := sha256.Sum256(raw)
	report = storeGenerationFloorReport{
		State: "planned", StoreID: cfg.StoreID,
		CurrentGenerationID: current.GenerationID, CurrentRawSHA256: hex.EncodeToString(rawSum[:]),
		FloorGenerationID: opts.floor, NextGenerationID: opts.floor + 1,
	}
	if opts.dryRun {
		return report, nil
	}
	record := desiredGenerationFloor{
		Schema: desiredGenerationFloorSchema, StoreID: cfg.StoreID, FloorGenerationID: opts.floor,
		CurrentGenerationID: current.GenerationID, CurrentGenerationHash: current.GenerationHash,
		CurrentRawSHA256: report.CurrentRawSHA256, Reason: opts.reason, EvidenceSHA256: opts.evidenceSHA256,
		RecordedAtUnix: now.UTC().Unix(), OperatorPubkey: primitives.EncodeBase58(operatorKey),
	}
	payload, err := record.signingPayload()
	if err != nil {
		return report, err
	}
	record.OperatorSignature = primitives.EncodeBase58(operator.Sign(payload))
	path, body, err := writeDesiredGenerationFloor(cfg, record, operatorKey)
	if err != nil {
		return report, err
	}
	bodySum := sha256.Sum256(body)
	report.State = "recorded"
	report.RecordPath = path
	report.RecordSHA256 = hex.EncodeToString(bodySum[:])
	return report, nil
}
