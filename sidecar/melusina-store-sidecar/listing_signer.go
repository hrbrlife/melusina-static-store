package main

// Local listing signer adapter.
//
// The operator key that creates StoreReleaseListing records is deliberately
// separated from the serving process when listing_signer_socket is configured.
// This is not a transaction proxy: the protocol accepts a single typed release
// intent, re-derives every chain/local fact in the signer, and can build only
// register_store_release_listing.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	listingSignerSchema     = "melusina-store-listing-signer-v1"
	listingSignerMaxMessage = 1 << 20
	listingSignerSocketMode = 0o600
)

type listingTransactionSigner interface {
	Prepare(context.Context, listingRegistrationState, listingRegistrationIntent) (preparedListingBootstrapTransaction, error)
}

type inProcessListingSigner struct {
	operator *identity.Private
	rpc      *listingBootstrapRPC
}

func (s *inProcessListingSigner) Prepare(ctx context.Context, state listingRegistrationState, _ listingRegistrationIntent) (preparedListingBootstrapTransaction, error) {
	if s == nil || s.operator == nil || s.rpc == nil {
		return preparedListingBootstrapTransaction{}, errors.New("listing signer is not initialized")
	}
	if err := validateListingRegistrationState(state); err != nil {
		return preparedListingBootstrapTransaction{}, err
	}
	storeAuthority, err := primitives.PubkeyFromBase58(state.StoreAuthority)
	if err != nil {
		return preparedListingBootstrapTransaction{}, err
	}
	authzPDA, err := primitives.PubkeyFromBase58(state.OperatorAuthorization)
	if err != nil {
		return preparedListingBootstrapTransaction{}, err
	}
	licenseMint, err := primitives.PubkeyFromBase58(state.LicenseNFTMint)
	if err != nil {
		return preparedListingBootstrapTransaction{}, err
	}
	domainHash, err := listingHex32(state.StoreDomainHash)
	if err != nil {
		return preparedListingBootstrapTransaction{}, err
	}
	certFingerprint, err := listingHex32(state.StoreCertFingerprint)
	if err != nil {
		return preparedListingBootstrapTransaction{}, err
	}
	return prepareListingBootstrapTransaction(ctx, s.rpc, s.operator, storeAuthority, authzPDA, licenseMint, domainHash, certFingerprint, state.Item)
}

type unixListingSignerClient struct {
	path string
}

func (c *unixListingSignerClient) Prepare(ctx context.Context, state listingRegistrationState, intent listingRegistrationIntent) (preparedListingBootstrapTransaction, error) {
	if c == nil {
		return preparedListingBootstrapTransaction{}, errors.New("listing signer client is not initialized")
	}
	if err := verifyListingSignerSocket(c.path); err != nil {
		return preparedListingBootstrapTransaction{}, err
	}
	dialer := net.Dialer{}
	raw, err := dialer.DialContext(ctx, "unix", c.path)
	if err != nil {
		return preparedListingBootstrapTransaction{}, fmt.Errorf("connect local listing signer: %w", err)
	}
	conn, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return preparedListingBootstrapTransaction{}, errors.New("local listing signer did not return a Unix connection")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(listingRPCTimeout))
	request := listingSignerRequest{Schema: listingSignerSchema, Intent: intent, State: state}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return preparedListingBootstrapTransaction{}, fmt.Errorf("write local listing signer request: %w", err)
	}
	var response listingSignerResponse
	decoder := json.NewDecoder(io.LimitReader(conn, listingSignerMaxMessage))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return preparedListingBootstrapTransaction{}, fmt.Errorf("read local listing signer response: %w", err)
	}
	if response.Schema != listingSignerSchema {
		return preparedListingBootstrapTransaction{}, errors.New("local listing signer response has an unknown schema")
	}
	if response.Error != "" {
		return preparedListingBootstrapTransaction{}, errors.New(response.Error)
	}
	wire, err := base64.StdEncoding.DecodeString(response.WireB64)
	if err != nil || len(wire) == 0 || len(wire) > listingSignerMaxMessage {
		return preparedListingBootstrapTransaction{}, errors.New("local listing signer returned invalid transaction bytes")
	}
	if strings.TrimSpace(response.Signature) == "" || strings.TrimSpace(response.RecentBlockhash) == "" {
		return preparedListingBootstrapTransaction{}, errors.New("local listing signer omitted transaction provenance")
	}
	return preparedListingBootstrapTransaction{Wire: wire, Signature: response.Signature, RecentBlockhash: response.RecentBlockhash}, nil
}

type listingSignerRequest struct {
	Schema string                    `json:"schema"`
	Intent listingRegistrationIntent `json:"intent"`
	State  listingRegistrationState  `json:"state"`
}

type listingSignerResponse struct {
	Schema          string `json:"schema"`
	WireB64         string `json:"wireB64,omitempty"`
	Signature       string `json:"signature,omitempty"`
	RecentBlockhash string `json:"recentBlockhash,omitempty"`
	Error           string `json:"error,omitempty"`
}

func newListingTransactionSigner(cfg Config, cr chainReader, operator *identity.Private) listingTransactionSigner {
	if strings.TrimSpace(cfg.ListingSignerSocket) != "" {
		return &unixListingSignerClient{path: cfg.ListingSignerSocket}
	}
	return &inProcessListingSigner{operator: operator, rpc: newListingBootstrapRPC(cfg)}
}

func verifyListingSignerSocket(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("listing signer socket is not an absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("listing signer socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != listingSignerSocketMode {
		return errors.New("listing signer socket must be mode-0600")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return errors.New("listing signer socket must be owned by this store user")
	}
	return nil
}

func runListingSignerSubcommand(args []string) {
	configPath := "store.config.json"
	if len(args) == 2 && args[0] == "-config" {
		configPath = args[1]
	} else if len(args) != 0 {
		panic("listing-signer accepts only -config PATH")
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		panic("listing-signer config: " + err.Error())
	}
	if strings.TrimSpace(cfg.ListingSignerSocket) == "" {
		panic("listing-signer requires config.listing_signer_socket")
	}
	setProgramIDFromConfig(cfg.ProgramID)
	if cfg.RPCURL == "" {
		panic("listing-signer requires rpc_url")
	}
	cr := newConfiguredStoreRPCReader(cfg)
	bootCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	operator, err := deriveOperatorIdentity(bootCtx, cfg, cr)
	cancel()
	if err != nil || operator == nil {
		panic(fmt.Sprintf("listing-signer boot identity: %v", err))
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := serveListingSignerSocket(ctx, cfg, cr, operator); err != nil && !errors.Is(err, context.Canceled) {
		panic("listing-signer: " + err.Error())
	}
}

func serveListingSignerSocket(ctx context.Context, cfg Config, cr chainReader, operator *identity.Private) error {
	if operator == nil || cr == nil {
		return errors.New("listing signer requires a verified operator and chain reader")
	}
	path := cfg.ListingSignerSocket
	if !filepath.IsAbs(path) {
		return errors.New("listing signer socket must be an absolute path")
	}
	if info, err := os.Lstat(path); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if info.Mode()&os.ModeSocket == 0 || !ok || int(stat.Uid) != os.Getuid() {
			return errors.New("refusing to replace an unsafe listing signer socket path")
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close(); _ = os.Remove(path) }()
	if err := os.Chmod(path, listingSignerSocketMode); err != nil {
		return err
	}
	for {
		if err := listener.SetDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			return err
		}
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					continue
				}
			}
			return err
		}
		go serveListingSignerConnection(conn, cfg, cr, operator)
	}
}

func serveListingSignerConnection(conn *net.UnixConn, cfg Config, cr chainReader, operator *identity.Private) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(listingRPCTimeout))
	respond := func(response listingSignerResponse) { _ = json.NewEncoder(conn).Encode(response) }
	if err := requireListingSignerPeer(conn); err != nil {
		respond(listingSignerResponse{Schema: listingSignerSchema, Error: err.Error()})
		return
	}
	var request listingSignerRequest
	decoder := json.NewDecoder(io.LimitReader(conn, listingSignerMaxMessage))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.Schema != listingSignerSchema {
		respond(listingSignerResponse{Schema: listingSignerSchema, Error: "invalid listing signer request"})
		return
	}
	if err := validateListingSignerStagedIntent(cfg, request.Intent); err != nil {
		respond(listingSignerResponse{Schema: listingSignerSchema, Error: err.Error()})
		return
	}
	validator := &boundedListingRegistrar{cfg: cfg, cr: cr, operator: operator}
	expected, _, _, _, _, err := validator.expectedState(context.Background(), request.Intent)
	if err != nil {
		respond(listingSignerResponse{Schema: listingSignerSchema, Error: err.Error()})
		return
	}
	if !sameListingSigningTarget(expected, request.State) {
		respond(listingSignerResponse{Schema: listingSignerSchema, Error: "listing signer request does not match independently derived target"})
		return
	}
	prepared, err := (&inProcessListingSigner{operator: operator, rpc: newListingBootstrapRPC(cfg)}).Prepare(context.Background(), expected, request.Intent)
	if err != nil {
		respond(listingSignerResponse{Schema: listingSignerSchema, Error: err.Error()})
		return
	}
	respond(listingSignerResponse{Schema: listingSignerSchema, WireB64: base64.StdEncoding.EncodeToString(prepared.Wire), Signature: prepared.Signature, RecentBlockhash: prepared.RecentBlockhash})
}

func requireListingSignerPeer(conn *net.UnixConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var peer *syscall.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		peer, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if controlErr != nil || peer == nil || int(peer.Uid) != os.Getuid() {
		return errors.New("listing signer peer is not the local store user")
	}
	return nil
}

func validateListingSignerStagedIntent(cfg Config, intent listingRegistrationIntent) error {
	if _, err := listingHex32(intent.StageID); err != nil || !isSafePathSegment(intent.AppID) {
		return errors.New("listing signer intent has invalid stage or app")
	}
	staged, _, _, releaseBytes, _, err := loadStagedAppWithRuntimeContract(cfg.PrivateStageDir, intent.StageID)
	if err != nil {
		return fmt.Errorf("load staged candidate: %w", err)
	}
	if staged.AppID != intent.AppID || !strings.EqualFold(staged.AppHash, intent.AppHash) {
		return errors.New("listing signer intent does not match the staged candidate")
	}
	rel, ok := parseReleaseClaim(releaseBytes)
	if !ok || !strings.EqualFold(rel.AppHash, intent.AppHash) || strings.TrimSpace(rel.MasterNftMint) != strings.TrimSpace(intent.MasterNFTMint) {
		return errors.New("listing signer intent does not match the staged release")
	}
	return nil
}

func sameListingSigningTarget(a, b listingRegistrationState) bool {
	return a.Schema == b.Schema && a.StageID == b.StageID && a.StoreAuthority == b.StoreAuthority && a.LicenseNFTMint == b.LicenseNFTMint && a.StoreDomainHash == b.StoreDomainHash && a.StoreCertFingerprint == b.StoreCertFingerprint && a.OperatorAuthorization == b.OperatorAuthorization && a.Item.AppID == b.Item.AppID && a.Item.AppHash == b.Item.AppHash && a.Item.ReleaseEntry == b.Item.ReleaseEntry && a.Item.FoundationApp == b.Item.FoundationApp && a.Item.Listing == b.Item.Listing
}

var _ listingTransactionSigner = (*inProcessListingSigner)(nil)
var _ listingTransactionSigner = (*unixListingSignerClient)(nil)
var _ = pda.Pubkey{}
