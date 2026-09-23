package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

// Day-two enrollment. An enrolled Store binds its executable hash, TLS leaf
// and SidecarIdentityEntry binding, and every start refuses a value its
// enrollment did not bind (store-enrollment-facts-mismatch:<field>). A
// governed binary update or certificate renewal therefore goes through an
// owner-signed StoreEnrollmentSuccessorV1:
//
//  1. the governed chain step moves the SidecarIdentityEntry to the new value
//     (update_sidecar_identity for a binary, a new key_version entry for a
//     certificate), since boot identity refuses anything else;
//  2. the NEW executable runs estate-enrollment-successor-request, which reads
//     the held state, re-derives the facts and emits the unsigned successor;
//  3. the profile owners review, sign and assemble it out of process, exactly
//     as for the initial enrollment;
//  4. with the Store stopped, the new executable runs estate-enroll-successor,
//     which takes the Store's writer lock, verifies the successor and the local
//     facts, and atomically replaces the state. The next start verifies it.
//
// Nothing here writes to the chain, opens a listener, or accepts a changed
// value because it was observed.

const (
	storeEstateEnrollSuccessorReportSchema = "melusina-store-estate-enroll-successor-report.v1"
	storeEnrollmentSuccessorRecallReason   = "superseded by root-Store enrollment sequence %d"
)

type estateEnrollmentSuccessorRequestOptions struct {
	configPath string
	lifetime   time.Duration
}

type estateEnrollSuccessorOptions struct {
	configPath     string
	enrollmentPath string
	// writerLockUID and writerLockGID are the owner the running Store demands
	// of writer.lock. The subcommand sets them to the server's own values;
	// they are not flags.
	writerLockUID uint32
	writerLockGID uint32
}

// storeEstateEnrollSuccessorReport contains only public pins.
type storeEstateEnrollSuccessorReport struct {
	Schema                       string `json:"schema"`
	Status                       string `json:"status"`
	EstateID                     string `json:"estateId"`
	ProfileSHA256                string `json:"profileSha256"`
	ProfileRevision              uint64 `json:"profileRevision"`
	InitialEnrollmentSHA256      string `json:"initialEnrollmentSha256"`
	SupersededEnrollmentSHA256   string `json:"supersededEnrollmentSha256"`
	SupersededEnrollmentSequence uint64 `json:"supersededEnrollmentSequence"`
	EnrollmentSHA256             string `json:"enrollmentSha256"`
	EnrollmentSequence           uint64 `json:"enrollmentSequence"`
	BindingKeyVersion            uint32 `json:"bindingKeyVersion"`
	SidecarIdentityPDA           string `json:"sidecarIdentityPda"`
	TLSCertFingerprint           string `json:"tlsCertFingerprint"`
	BinarySHA256                 string `json:"binarySha256"`
	ObservedGenesisHash          string `json:"observedGenesisHash"`
}

func runEstateEnrollmentSuccessorRequestSubcommand(args []string) {
	fs := flag.NewFlagSet("estate-enrollment-successor-request", flag.ExitOnError)
	opts := estateEnrollmentSuccessorRequestOptions{}
	fs.StringVar(&opts.configPath, "config", "store.config.json", "path to the enrolled Store's JSON configuration")
	fs.DurationVar(&opts.lifetime, "valid-for", storeEnrollmentRequestDefaultLifetime, "owner-signing window from issuance (1m through 24h, whole seconds)")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		log.Fatalf("estate-enrollment-successor-request: unexpected positional arguments: %v", fs.Args())
	}
	candidate, err := createStoreEnrollmentSuccessorRequest(opts, time.Now().UTC())
	if err != nil {
		log.Fatalf("estate-enrollment-successor-request: %v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(candidate); err != nil {
		log.Fatalf("estate-enrollment-successor-request output: %v", err)
	}
}

func runEstateEnrollSuccessorSubcommand(args []string) {
	fs := flag.NewFlagSet("estate-enroll-successor", flag.ExitOnError)
	// The running server takes writer.lock as root:root (acquireExistingWriterLock);
	// the successor writer demands the same owner.
	opts := estateEnrollSuccessorOptions{writerLockUID: 0, writerLockGID: 0}
	fs.StringVar(&opts.configPath, "config", "store.config.json", "path to the enrolled Store's JSON configuration")
	fs.StringVar(&opts.enrollmentPath, "enrollment", "", "required path to the owner-signed StoreEnrollmentSuccessorV1 JSON")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		log.Fatalf("estate-enroll-successor: unexpected positional arguments: %v", fs.Args())
	}
	if strings.TrimSpace(opts.enrollmentPath) == "" {
		log.Fatalf("estate-enroll-successor: --enrollment is required")
	}
	report, err := enrollStoreEstateSuccessor(opts, time.Now().UTC())
	if err != nil {
		log.Fatalf("estate-enroll-successor: %v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		log.Fatalf("estate-enroll-successor report: %v", err)
	}
}

// createStoreEnrollmentSuccessorRequest writes nothing. It requires a held,
// valid enrollment state, re-derives this executable's facts through the same
// boot-identity ceremony as startup, and emits the unsigned successor.
func createStoreEnrollmentSuccessorRequest(opts estateEnrollmentSuccessorRequestOptions, now time.Time) (estateprofile.StoreEnrollmentSuccessorV1, error) {
	if strings.TrimSpace(opts.configPath) == "" {
		return estateprofile.StoreEnrollmentSuccessorV1{}, errors.New("store-estate-profile-config-read: config path is required")
	}
	cfg, err := LoadConfig(opts.configPath)
	if err != nil {
		return estateprofile.StoreEnrollmentSuccessorV1{}, err
	}
	declaration, err := loadStoreEstateDeclaration(opts.configPath)
	if err != nil {
		return estateprofile.StoreEnrollmentSuccessorV1{}, err
	}
	if err := requireLoadedConfigMatchesStoreDeclaration(cfg, declaration); err != nil {
		return estateprofile.StoreEnrollmentSuccessorV1{}, err
	}
	// The registry is pinned from the validated config before anything that
	// could read it, as every other Store entry point does.
	if err := setProgramIDFromConfig(cfg.ProgramID); err != nil {
		return estateprofile.StoreEnrollmentSuccessorV1{}, err
	}
	state, err := readHeldStoreEnrollmentState(cfg)
	if err != nil {
		return estateprofile.StoreEnrollmentSuccessorV1{}, err
	}
	chain := newConfiguredStoreRPCReader(cfg)
	genesisReader, ok := chain.(genesisHashReader)
	if !ok {
		return estateprofile.StoreEnrollmentSuccessorV1{}, errors.New("store estate enrollment successor request chain reader does not support getGenesisHash")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	identity, err := deriveVerifiedBootIdentity(ctx, cfg, chain)
	if err != nil {
		return estateprofile.StoreEnrollmentSuccessorV1{}, err
	}
	if identity == nil {
		return estateprofile.StoreEnrollmentSuccessorV1{}, fmt.Errorf("%w: boot_identity.shards_dir is required", errStoreEstateProfileNotEnrolled)
	}
	nonce := make([]byte, sha256.Size)
	if _, err := rand.Read(nonce); err != nil {
		return estateprofile.StoreEnrollmentSuccessorV1{}, fmt.Errorf("store estate enrollment successor request nonce: %w", err)
	}
	return prepareStoreEnrollmentSuccessorCandidate(ctx, cfg, declaration, state, identity, genesisReader, now, opts.lifetime, nonce)
}

func readHeldStoreEnrollmentState(cfg Config) (storeEnrollmentState, error) {
	if strings.TrimSpace(cfg.EstateEnrollmentStatePath) == "" {
		return storeEnrollmentState{}, errStoreEstateProfileNotEnrolled
	}
	state, err := readStoreEnrollmentState(cfg.EstateEnrollmentStatePath, uint32(os.Geteuid()))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return storeEnrollmentState{}, fmt.Errorf("%w: enrollment state is absent", errStoreEstateProfileNotEnrolled)
		}
		return storeEnrollmentState{}, err
	}
	return state, nil
}

// prepareStoreEnrollmentSuccessorCandidate is pure with respect to Store
// state. Identity fields come from the verified runtime and the held profile,
// never from the held enrollment, so a Store whose identity drifted cannot even
// ask its owners for a successor: the advance check refuses it by name.
func prepareStoreEnrollmentSuccessorCandidate(ctx context.Context, cfg Config, declaration storeEstateDeclaration, state storeEnrollmentState, identity *verifiedBootIdentity, genesisReader genesisHashReader, now time.Time, lifetime time.Duration, nonce []byte) (estateprofile.StoreEnrollmentSuccessorV1, error) {
	if err := validateStoreEnrollmentState(state); err != nil {
		return estateprofile.StoreEnrollmentSuccessorV1{}, err
	}
	if _, err := verifyStoreEstateDeclaration(declaration, state.Profile); err != nil {
		return estateprofile.StoreEnrollmentSuccessorV1{}, err
	}
	if err := requireLoadedConfigMatchesStoreDeclaration(cfg, declaration); err != nil {
		return estateprofile.StoreEnrollmentSuccessorV1{}, err
	}
	if lifetime < time.Minute || lifetime > estateprofile.StoreEnrollmentMaxLifetime || lifetime%time.Second != 0 {
		return estateprofile.StoreEnrollmentSuccessorV1{}, errors.New("store estate enrollment successor request valid-for must be a whole number of seconds from 1m through 24h")
	}
	if len(nonce) != sha256.Size {
		return estateprofile.StoreEnrollmentSuccessorV1{}, errors.New("store estate enrollment successor request nonce must be 32 bytes")
	}
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() || now.Unix() <= 0 {
		return estateprofile.StoreEnrollmentSuccessorV1{}, errors.New("store estate enrollment successor request issuance time is invalid")
	}
	facts, err := storeEnrollmentRuntimeFacts(declaration, identity)
	if err != nil {
		return estateprofile.StoreEnrollmentSuccessorV1{}, err
	}
	sequence := state.sequence() + 1
	predecessor := state.currentSHA256()
	candidate := estateprofile.StoreEnrollmentSuccessorV1{
		Schema:                      estateprofile.StoreEnrollmentSuccessorSchema,
		Kind:                        estateprofile.StoreEnrollmentSuccessorKind,
		Purpose:                     estateprofile.StoreEnrollmentSuccessorPurpose,
		EstateID:                    state.Profile.EstateID,
		ProfileSHA256:               state.ProfilePin.ProfileSHA256,
		ProfileRevision:             state.Profile.Revision,
		NetworkGenesisHash:          state.Profile.Network.GenesisHash,
		InitialEnrollmentSHA256:     state.EnrollmentSHA256,
		EnrollmentSequence:          sequence,
		PredecessorEnrollmentSHA256: predecessor,
		Recalls: []estateprofile.RecallV1{{
			SHA256: predecessor,
			Reason: fmt.Sprintf(storeEnrollmentSuccessorRecallReason, sequence),
		}},
		RootDomain:         facts.RootDomain,
		RootDomainSHA256:   facts.RootDomainSHA256,
		StoreID:            facts.StoreID,
		StoreOperatorKey:   facts.StoreOperatorKey,
		StoreBoxKey:        facts.StoreBoxKey,
		LicenseNFTMint:     facts.LicenseNFTMint,
		LicenseRegistryID:  facts.LicenseRegistryID,
		SidecarID:          facts.SidecarID,
		BindingKeyVersion:  facts.BindingKeyVersion,
		OperatorKeyVersion: facts.OperatorKeyVersion,
		OperatorDomain:     facts.OperatorDomain,
		SidecarIdentityPDA: facts.SidecarIdentityPDA,
		TLSCertFingerprint: facts.TLSCertFingerprint,
		BinarySHA256:       facts.BinarySHA256,
		IssuedAt:           now.Format(time.RFC3339),
		ExpiresAt:          now.Add(lifetime).Format(time.RFC3339),
		EnrollmentNonce:    hex.EncodeToString(nonce),
		Signatures:         []estateprofile.SignatureV1{},
	}
	if _, err := estateprofile.StoreEnrollmentSuccessorSHA256(candidate); err != nil {
		return estateprofile.StoreEnrollmentSuccessorV1{}, fmt.Errorf("store estate enrollment successor request candidate: %w", err)
	}
	// The profile projection must hold, so owner signatures are the only thing
	// the candidate lacks.
	if _, err := estateprofile.VerifyStoreEnrollmentSuccessorAuthorization(state.Profile, candidate); estateprofile.RefusalName(err) != estateprofile.RefusalStoreEnrollmentSignaturesInsufficient {
		if err == nil {
			return estateprofile.StoreEnrollmentSuccessorV1{}, errors.New("unsigned store estate enrollment successor unexpectedly satisfied the owner threshold")
		}
		return estateprofile.StoreEnrollmentSuccessorV1{}, err
	}
	if err := estateprofile.RequireStoreEnrollmentSuccessorAdvance(state.held(), candidate); err != nil {
		return estateprofile.StoreEnrollmentSuccessorV1{}, err
	}
	if err := estateprofile.RequireStoreEnrollmentSuccessorFacts(candidate, facts); err != nil {
		return estateprofile.StoreEnrollmentSuccessorV1{}, err
	}
	if _, err := verifyStoreEnrollmentGenesis(ctx, state.Enrollment, genesisReader); err != nil {
		return estateprofile.StoreEnrollmentSuccessorV1{}, err
	}
	return candidate, nil
}

// enrollStoreEstateSuccessor is the only successor state writer. Owner
// authority, forward sequence and recall are decided before any chain read;
// the executable's facts are then derived and compared, and only then is the
// state replaced. It holds the Store's writer lock throughout, so it refuses
// to run beside a serving Store or a concurrent successor writer.
func enrollStoreEstateSuccessor(opts estateEnrollSuccessorOptions, now time.Time) (storeEstateEnrollSuccessorReport, error) {
	var report storeEstateEnrollSuccessorReport
	if strings.TrimSpace(opts.configPath) == "" {
		return report, errors.New("store-estate-profile-config-read: config path is required")
	}
	cfg, err := LoadConfig(opts.configPath)
	if err != nil {
		return report, err
	}
	if strings.TrimSpace(cfg.EstateEnrollmentStatePath) == "" {
		return report, errStoreEstateProfileNotEnrolled
	}
	declaration, err := loadStoreEstateDeclaration(opts.configPath)
	if err != nil {
		return report, err
	}
	successor, err := loadStoreEnrollmentSuccessorDocument(opts.enrollmentPath)
	if err != nil {
		return report, err
	}
	if err := requireLoadedConfigMatchesStoreDeclaration(cfg, declaration); err != nil {
		return report, err
	}
	if err := setProgramIDFromConfig(cfg.ProgramID); err != nil {
		return report, err
	}
	lock, err := acquireStoreEnrollmentSuccessorWriterLock(cfg, opts.writerLockUID, opts.writerLockGID)
	if err != nil {
		return report, err
	}
	defer lock.Close()
	state, err := readHeldStoreEnrollmentState(cfg)
	if err != nil {
		return report, err
	}
	// Owner authority, sequence and recall are decided before a chain reader
	// exists.
	if _, err := advanceStoreEnrollmentState(state, successor, now); err != nil {
		return report, err
	}
	chain := newConfiguredStoreRPCReader(cfg)
	genesisReader, ok := chain.(genesisHashReader)
	if !ok {
		return report, errors.New("store estate enrollment successor chain reader does not support getGenesisHash")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	identity, err := deriveVerifiedBootIdentity(ctx, cfg, chain)
	if err != nil {
		return report, err
	}
	if identity == nil {
		return report, fmt.Errorf("%w: boot_identity.shards_dir is required", errStoreEstateProfileNotEnrolled)
	}
	return commitStoreEnrollmentSuccessor(ctx, cfg, declaration, state, identity, genesisReader, successor, now, uint32(os.Geteuid()))
}

func loadStoreEnrollmentSuccessorDocument(path string) (estateprofile.StoreEnrollmentSuccessorV1, error) {
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return estateprofile.StoreEnrollmentSuccessorV1{}, fmt.Errorf("store-enrollment-successor-read: %w", err)
	}
	successor, err := estateprofile.DecodeStoreEnrollmentSuccessor(raw)
	if err != nil {
		return estateprofile.StoreEnrollmentSuccessorV1{}, fmt.Errorf("store-enrollment-successor-invalid: %w", err)
	}
	return successor, nil
}

// acquireStoreEnrollmentSuccessorWriterLock takes the same process-lifetime
// exclusion a serving Store holds. It never creates the lock: an enrolled Store
// that has never been started has nothing to protect a successor from, and a
// missing lock is a refusal rather than a file this command invents.
func acquireStoreEnrollmentSuccessorWriterLock(cfg Config, uid, gid uint32) (*os.File, error) {
	dir := strings.TrimSpace(cfg.CatalogMigrationStateDir)
	if dir == "" || !filepath.IsAbs(dir) {
		return nil, errors.New("store estate enrollment successor requires an absolute catalog_migration_state_dir holding writer.lock")
	}
	lock, err := acquireExistingWriterLockOwned(filepath.Join(filepath.Clean(dir), storeWriterLockName), uid, gid)
	if err != nil {
		return nil, fmt.Errorf("store estate enrollment successor requires the stopped Store's writer lock: %w", err)
	}
	return lock, nil
}

// commitStoreEnrollmentSuccessor re-decides the advance from the held state,
// proves the runtime facts against the successor, and replaces the state. The
// caller holds the writer lock and read held under it.
func commitStoreEnrollmentSuccessor(ctx context.Context, cfg Config, declaration storeEstateDeclaration, held storeEnrollmentState, identity *verifiedBootIdentity, genesisReader genesisHashReader, successor estateprofile.StoreEnrollmentSuccessorV1, now time.Time, stateUID uint32) (storeEstateEnrollSuccessorReport, error) {
	next, err := advanceStoreEnrollmentState(held, successor, now)
	if err != nil {
		return storeEstateEnrollSuccessorReport{}, err
	}
	observedGenesis, err := verifyStoreEnrollmentRuntime(ctx, cfg, declaration, next, identity, genesisReader)
	if err != nil {
		return storeEstateEnrollSuccessorReport{}, err
	}
	if err := replaceStoreEnrollmentState(cfg.EstateEnrollmentStatePath, held, next, stateUID); err != nil {
		return storeEstateEnrollSuccessorReport{}, err
	}
	return storeEstateEnrollSuccessorReport{
		Schema:                       storeEstateEnrollSuccessorReportSchema,
		Status:                       "store-estate-enrollment-succeeded",
		EstateID:                     next.Profile.EstateID,
		ProfileSHA256:                next.ProfilePin.ProfileSHA256,
		ProfileRevision:              next.Profile.Revision,
		InitialEnrollmentSHA256:      next.EnrollmentSHA256,
		SupersededEnrollmentSHA256:   held.currentSHA256(),
		SupersededEnrollmentSequence: held.sequence(),
		EnrollmentSHA256:             next.SuccessorSHA256,
		EnrollmentSequence:           next.sequence(),
		BindingKeyVersion:            next.Successor.BindingKeyVersion,
		SidecarIdentityPDA:           next.Successor.SidecarIdentityPDA,
		TLSCertFingerprint:           next.Successor.TLSCertFingerprint,
		BinarySHA256:                 next.Successor.BinarySHA256,
		ObservedGenesisHash:          observedGenesis,
	}, nil
}
