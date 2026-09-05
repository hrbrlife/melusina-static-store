// Package publisherenvelope implements the narrow custody boundary used by a
// Bazaar Control finalizer.  It is deliberately not an HTTP service, a
// transaction signer, or a release client: it signs exactly one short-lived
// publish-request envelope for an already bound Pearl dossier.
package publisherenvelope

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	RequestSchema  = "bazaar-control-publisher-envelope-request-v1"
	ResponseSchema = "bazaar-control-publisher-envelope-response-v1"

	maxRequestBytes = 128 << 10
	socketMode      = 0o600
	privateFileMode = 0o600
	directoryMode   = 0o700
	envelopeTTL     = 15 * time.Minute
)

// Request contains facts that the finalizer has already verified against its
// persisted job, observed proposal, and immutable candidate. It contains no
// route, endpoint, source path, command, transaction, or expiry selected by a
// caller. The service derives the only route from DossierID and fixes the TTL.
type Request struct {
	Schema          string `json:"schema"`
	DossierID       string `json:"dossierId"`
	StoreID         string `json:"storeId"`
	AppID           string `json:"appId"`
	Version         string `json:"version"`
	ArtifactSHA256  string `json:"artifactSha256"`
	AppHash         string `json:"appHash"`
	ReleaseHash     string `json:"releaseHash"`
	ReleaseB64      string `json:"releaseB64"`
	ReleaseEntryPDA string `json:"releaseEntryPda"`
	VerifiedSlot    uint64 `json:"verifiedSlot"`
}

// Response returns an encoded signed envelope and its payload hash. The
// finalizer still constructs and returns the complete sidecar body; it never
// receives a network path from this signer.
type Response struct {
	Schema              string    `json:"schema"`
	PublisherIntentHash string    `json:"publisherIntentHash,omitempty"`
	EnvelopeB64         string    `json:"envelopeB64,omitempty"`
	ExpiresAt           time.Time `json:"expiresAt,omitempty"`
	Error               string    `json:"error,omitempty"`
}

// Config is intentionally small. StoreID and both identity files are fixed by
// the service unit, rather than being supplied in a finalization job.
type Config struct {
	SocketPath            string
	PublisherIdentityPath string
	StoreIdentityPath     string
	StoreID               string
	AllowedUID            uint32
}

// Service owns the publisher identity in a local process. It is not exported
// to the Pearl, Store Link, agent terminal, browser, or a worker container.
type Service struct {
	publisher *identity.Private
	store     identity.Public
	storeID   string
	allowedID uint32
	now       func() time.Time
}

// New validates the fixed custody binding. Tests and a process bootstrap use
// this directly; deployment loads identities through Load.
func New(publisher *identity.Private, store identity.Public, storeID string, allowedUID uint32) (*Service, error) {
	if publisher == nil || strings.TrimSpace(storeID) == "" || store.Validate() != nil {
		return nil, errors.New("publisher identity, Store identity, and Store id are required")
	}
	return &Service{publisher: publisher, store: store, storeID: storeID, allowedID: allowedUID, now: time.Now}, nil
}

// Load reads the publisher seed only from an owner-only regular file. A public
// Store identity may be readable, but it is still required to be a regular,
// non-symlinked file so a service cannot be redirected after review.
func Load(config Config) (*Service, error) {
	if !filepath.IsAbs(config.SocketPath) || strings.TrimSpace(config.StoreID) == "" {
		return nil, errors.New("envelope signer requires an absolute socket and Store id")
	}
	publisher, err := loadPublisherIdentity(config.PublisherIdentityPath)
	if err != nil {
		return nil, err
	}
	store, err := loadStoreIdentity(config.StoreIdentityPath)
	if err != nil {
		return nil, err
	}
	return New(publisher, store, config.StoreID, config.AllowedUID)
}

// Sign produces the only message this service can sign. It deliberately does
// not know how to submit that message, read chain state, or select a catalog.
func (s *Service) Sign(request Request) (Response, error) {
	if s == nil || s.publisher == nil || s.now == nil {
		return Response{}, errors.New("publisher envelope signer is unavailable")
	}
	release, err := request.validate(s.storeID)
	if err != nil {
		return Response{}, err
	}
	now := s.now().UTC()
	target := "/control/v1/releases/" + request.DossierID + "/publish"
	artifact, err := digest32(request.ArtifactSHA256)
	if err != nil {
		return Response{}, err
	}
	releaseSum := sha256.Sum256(release)
	signed, err := envelope.Sign(envelope.KindPublishRequest, s.publisher, s.store, envelope.SignOptions{
		Method:      httpMethodPost,
		Target:      target,
		Body:        release,
		BodyHash:    hex.EncodeToString(releaseSum[:]),
		RequestHash: hex.EncodeToString(artifact[:]),
		TTL:         envelopeTTL,
		Now:         now,
		Chain: envelope.ChainEvidence{
			ChainID: s.publisher.Public().Ref.ChainID, ProgramID: s.publisher.Public().Ref.ProgramID,
			VerifiedSlot: request.VerifiedSlot, ReleaseEntryPDA: request.ReleaseEntryPDA,
		},
	})
	if err != nil {
		return Response{}, fmt.Errorf("sign fixed publisher envelope: %w", err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		return Response{}, err
	}
	return Response{
		Schema: ResponseSchema, PublisherIntentHash: signed.PayloadHash,
		EnvelopeB64: base64.RawURLEncoding.EncodeToString(raw),
		// Return the exact millisecond value encoded in the signed payload.
		// Using now.Add(envelopeTTL) here could retain sub-millisecond precision
		// that the envelope does not carry, making a caller unable to bind the
		// response expiry to the signed message exactly.
		ExpiresAt: time.UnixMilli(signed.Payload.ExpiresAtMs).UTC(),
	}, nil
}

const httpMethodPost = "POST"

type releaseClaims struct {
	Schema          string `json:"$schema"`
	AppHash         string `json:"appHash"`
	ReleaseHash     string `json:"releaseHash"`
	Version         string `json:"version"`
	ReleaseEntryPDA string `json:"releaseEntryPda"`
}

func (r Request) validate(expectedStore string) ([]byte, error) {
	if r.Schema != RequestSchema || !lowerHex(r.DossierID, 24) || strings.TrimSpace(r.StoreID) != expectedStore || !sandstormAppID(r.AppID) || !safeText(r.Version, 256) || !lowerHex(r.ArtifactSHA256, 64) || !lowerHex(r.AppHash, 64) || !lowerHex(r.ReleaseHash, 64) || r.VerifiedSlot == 0 {
		return nil, errors.New("publisher-envelope request is not exact")
	}
	if _, err := primitives.PubkeyFromBase58(strings.TrimSpace(r.ReleaseEntryPDA)); err != nil {
		return nil, errors.New("publisher-envelope request has an invalid release entry")
	}
	release, err := base64.StdEncoding.DecodeString(strings.TrimSpace(r.ReleaseB64))
	if err != nil || len(release) == 0 || len(release) > maxRequestBytes || !json.Valid(release) {
		return nil, errors.New("publisher-envelope request has an invalid release document")
	}
	var claims releaseClaims
	// RELEASE.json evolves under its own schema. This signer binds the fields
	// relevant to its narrow authority but does not pretend to own that schema;
	// json.Unmarshal still rejects trailing garbage.
	if err := json.Unmarshal(release, &claims); err != nil {
		return nil, errors.New("publisher-envelope request release is malformed")
	}
	if claims.Schema != "melusina-release-v1" || claims.AppHash != r.AppHash || claims.ReleaseHash != r.ReleaseHash || claims.Version != r.Version || claims.ReleaseEntryPDA != r.ReleaseEntryPDA {
		return nil, errors.New("publisher-envelope request release does not bind the approved facts")
	}
	return release, nil
}

// Serve opens a same-user Unix socket. The service intentionally accepts no
// TCP connection and has no HTTP handler, preventing a browser or Pearl from
// using the publisher identity as a general signing endpoint.
func Serve(ctx context.Context, socketPath string, service *Service) error {
	if service == nil || !filepath.IsAbs(socketPath) {
		return errors.New("publisher envelope signer requires an absolute socket and service")
	}
	if err := ownerOnlyDirectory(filepath.Dir(socketPath)); err != nil {
		return fmt.Errorf("publisher envelope signer socket directory: %w", err)
	}
	if info, err := os.Lstat(socketPath); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSocket == 0 || int(stat.Uid) != os.Geteuid() {
			return errors.New("refusing to replace an unsafe publisher-envelope socket")
		}
		if err := os.Remove(socketPath); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close(); _ = os.Remove(socketPath) }()
	if err := os.Chmod(socketPath, socketMode); err != nil {
		return err
	}
	for {
		if err := listener.SetDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			return err
		}
		conn, err := listener.AcceptUnix()
		if err != nil {
			if networkTimeout(err) {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					continue
				}
			}
			return err
		}
		go serveConnection(conn, service)
	}
}

func serveConnection(conn *net.UnixConn, service *Service) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	respond := func(response Response) { _ = json.NewEncoder(conn).Encode(response) }
	if err := requirePeerUID(conn, service.allowedID); err != nil {
		respond(Response{Schema: ResponseSchema, Error: err.Error()})
		return
	}
	var request Request
	decoder := json.NewDecoder(io.LimitReader(conn, maxRequestBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		respond(Response{Schema: ResponseSchema, Error: "invalid publisher-envelope request"})
		return
	}
	response, err := service.Sign(request)
	if err != nil {
		respond(Response{Schema: ResponseSchema, Error: err.Error()})
		return
	}
	respond(response)
}

func requirePeerUID(conn *net.UnixConn, want uint32) error {
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
	if controlErr != nil || peer == nil || peer.Uid != want {
		return errors.New("publisher-envelope signer peer is not the configured finalizer user")
	}
	return nil
}

type privateIdentityFile struct {
	Ref      identity.Ref `json:"ref"`
	SignSeed string       `json:"sign_seed_hex"`
	BoxSeed  string       `json:"box_seed_hex"`
}

func loadPublisherIdentity(path string) (*identity.Private, error) {
	raw, err := readOwnerOnlyRegularFile(path)
	if err != nil {
		return nil, fmt.Errorf("publisher identity: %w", err)
	}
	var file privateIdentityFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, errors.New("publisher identity JSON is malformed")
	}
	sign, err := seed32(file.SignSeed)
	if err != nil {
		return nil, fmt.Errorf("publisher signing seed: %w", err)
	}
	box, err := seed32(file.BoxSeed)
	if err != nil {
		return nil, fmt.Errorf("publisher encryption seed: %w", err)
	}
	return identity.NewPrivate(file.Ref, sign, box)
}

func loadStoreIdentity(path string) (identity.Public, error) {
	if err := regularNonSymlink(path); err != nil {
		return identity.Public{}, fmt.Errorf("Store identity: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > maxRequestBytes {
		return identity.Public{}, errors.New("Store identity cannot be read")
	}
	return identity.ParsePublicJSON(raw)
}

func readOwnerOnlyRegularFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("must be an absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != privateFileMode || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("must be an owner-only mode-0600 regular file owned by this user")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > maxRequestBytes {
		return nil, errors.New("cannot be read safely")
	}
	return raw, nil
}

func regularNonSymlink(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("must be an absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("must be a regular non-symlink file")
	}
	return nil
}

func ownerOnlyDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != directoryMode || int(stat.Uid) != os.Geteuid() {
		return errors.New("must be an owner-only mode-0700 directory owned by this user")
	}
	return nil
}

func seed32(value string) ([32]byte, error) {
	var result [32]byte
	raw, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(raw) != len(result) {
		return result, errors.New("must be exactly 32 hexadecimal bytes")
	}
	copy(result[:], raw)
	return result, nil
}

func digest32(value string) ([32]byte, error) {
	var result [32]byte
	raw, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(raw) != len(result) {
		return result, errors.New("must be exactly 32 lowercase hexadecimal bytes")
	}
	copy(result[:], raw)
	return result, nil
}

func lowerHex(value string, want int) bool {
	if len(value) != want || strings.ToLower(value) != value {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func sandstormAppID(value string) bool {
	if len(value) != 52 || strings.ToLower(value) != value {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func safeText(value string, max int) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > max {
		return false
	}
	for _, c := range value {
		if c < ' ' || c == 0x7f {
			return false
		}
	}
	return true
}

func networkTimeout(err error) bool {
	value, ok := err.(net.Error)
	return ok && value.Timeout()
}
