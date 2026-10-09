package main

// The foundation operator can authorize a one-time holder handoff before
// enrollment only by proving the original private shards still derive the
// operator pinned by the owners' signed profile and the escrow manifest.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/hrbrlife/melusina-attest/derive"
	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/storerecovery"
)

const foundationRestoreRequestSchema = "melusina-restore-session-request-v1"
const foundationRestoreRequestDomain = "MELUSINA_HOLDER_RESTORE_SESSION_REQUEST_V1\n"

type foundationRestoreRequest struct {
	Schema           string `json:"schema"`
	Store            string `json:"store"`
	Role             string `json:"role"`
	SessionRecipient string `json:"sessionRecipient"`
	Expires          string `json:"expires"`
	Signature        string `json:"signature"`
}

type foundationRestoreRequestOptions struct {
	profilePath, manifestPath, shardsDir, role, sessionRecipient, expires, outPath string
}

func runStoreIdentityFoundationRestoreRequestSubcommand(args []string) {
	fs := flag.NewFlagSet("store-identity-foundation-restore-request", flag.ExitOnError)
	var value foundationRestoreRequestOptions
	fs.StringVar(&value.profilePath, "estate-profile", "", "verified owner-signed estate profile")
	fs.StringVar(&value.manifestPath, "manifest", "", "operator-signed original identity escrow manifest")
	fs.StringVar(&value.shardsDir, "shards-dir", "", "original mode-0700 shard directory")
	fs.StringVar(&value.role, "role", "", "exact shard role")
	fs.StringVar(&value.sessionRecipient, "session-recipient", "", "replacement host's one-time x25519 recipient")
	fs.StringVar(&value.expires, "expires", "", "RFC3339 expiry")
	fs.StringVar(&value.outPath, "out", "", "new request file")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		log.Fatal("store-identity-foundation-restore-request: positional input refused")
	}
	report, err := signFoundationRestoreRequest(value)
	if err != nil {
		log.Fatalf("store-identity-foundation-restore-request: %v", err)
	}
	printJSONReport("store-identity-foundation-restore-request", report)
}

func signFoundationRestoreRequest(value foundationRestoreRequestOptions) (map[string]any, error) {
	for _, path := range []string{value.profilePath, value.manifestPath, value.outPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, errors.New("foundation-restore-request-path-invalid")
		}
	}
	if err := requireFoundationPrivateShards(value.shardsDir); err != nil {
		return nil, err
	}
	if value.role != "author" && value.role != "host-observation" && value.role != "release" {
		return nil, errors.New("foundation-restore-request-role-invalid")
	}
	if _, err := storerecovery.ParseRecipient(value.sessionRecipient); err != nil {
		return nil, errors.New("foundation-restore-request-recipient-invalid")
	}
	end, err := time.Parse(time.RFC3339, value.expires)
	if err != nil || !end.After(time.Now()) || end.After(time.Now().Add(24*time.Hour)) {
		return nil, errors.New("foundation-restore-request-expiry-invalid")
	}
	profileRaw, err := readBoundedInput(value.profilePath, estateprofile.MaxProfileJSONBytes)
	if err != nil {
		return nil, err
	}
	profile, err := estateprofile.DecodeProfile(profileRaw)
	if err != nil {
		return nil, err
	}
	if _, err := estateprofile.VerifyProfile(profile); err != nil {
		return nil, err
	}
	if !profile.Store.IsRoot {
		return nil, errors.New("foundation-restore-request-root-store-required")
	}
	manifestRaw, err := readBoundedInput(value.manifestPath, maxStoreIdentityInputBytes)
	if err != nil {
		return nil, err
	}
	manifest, _, err := storerecovery.VerifyIdentityEscrowManifest(manifestRaw, profile.Store.OperatorKey)
	if err != nil {
		return nil, err
	}
	if manifest.StoreID != profile.Store.StoreID {
		return nil, errors.New("foundation-restore-request-store-profile-mismatch")
	}
	ref := manifest.OperatorRef
	registry := ""
	for _, program := range profile.Programs {
		if program.Role == estateprofile.ProgramRoleLicenseRegistry {
			registry = program.ProgramID
		}
	}
	if ref.Kind != "sidecar" || ref.SidecarID != "store" || ref.KeyVersion != 1 ||
		ref.ChainID != "solana:"+profile.Network.Label || ref.Domain != profile.Store.RootDomain ||
		registry == "" || ref.ProgramID != registry {
		return nil, errors.New("foundation-restore-request-ref-profile-mismatch")
	}
	shards, err := loadSidecarShards(value.shardsDir)
	if err != nil {
		return nil, err
	}
	defer func() {
		clear(shards.AuthorShard[:])
		clear(shards.HostObservationShard[:])
		clear(shards.ReleaseShard[:])
	}()
	operator, err := derive.DeriveSidecar(ref, shards)
	if err != nil {
		return nil, err
	}
	if operator.Public().SignPubkeyB58 != profile.Store.OperatorKey || operator.Public().BoxPubkeyB58 != manifest.BoxKey {
		return nil, errors.New("foundation-restore-request-operator-profile-mismatch")
	}
	request := foundationRestoreRequest{Schema: foundationRestoreRequestSchema, Store: manifest.StoreID,
		Role: value.role, SessionRecipient: value.sessionRecipient, Expires: value.expires}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	body = append(body, '\n')
	request.Signature = base64.RawURLEncoding.EncodeToString(operator.Sign(append([]byte(foundationRestoreRequestDomain), body...)))
	if len(request.Signature) == 0 {
		return nil, errors.New("foundation-restore-request-signature-absent")
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if err := writeNewFoundationRestoreRequest(value.outPath, append(raw, '\n')); err != nil {
		return nil, err
	}
	return map[string]any{"schema": foundationRestoreRequestSchema, "store": request.Store,
		"role": request.Role, "sessionRecipient": request.SessionRecipient,
		"out": value.outPath, "operatorKey": profile.Store.OperatorKey}, nil
}

func writeNewFoundationRestoreRequest(path string, raw []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("foundation-restore-request-output-invalid: %w", err)
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
