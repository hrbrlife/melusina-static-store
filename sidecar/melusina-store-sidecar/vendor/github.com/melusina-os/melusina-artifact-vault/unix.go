package artifactvault

// The Unix broker is the only cross-identity vault surface. It is deliberately
// narrower than HTTP and has no path, URL, source, command, or transaction
// field. A worker can store bytes it already produced or load exactly one
// digest-and-size-addressed object; it cannot browse, replace, or delete.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	unixSchema      = "melusina-artifact-vault-unix-v1"
	unixStore       = "store"
	unixLoad        = "load"
	maxUnixHeader   = 16 << 10
	unixSocketMode  = 0o660
	socketDirMode   = 0o710
	defaultUnixWait = 30 * time.Second
)

// UnixServerConfig is deployer-owned. SocketGroupID grants connectivity only;
// the server separately checks SO_PEERCRED against AllowedPeerUIDs on every
// request. The vault root never becomes group-readable.
type UnixServerConfig struct {
	Root            string
	SocketPath      string
	SocketGroupID   uint32
	AllowedPeerUIDs []uint32
	MaxObjectBytes  int64
}

// UnixClientConfig names one already-provisioned broker socket. The expected
// vault UID prevents a worker from accepting a same-path socket substituted by
// another local user.
type UnixClientConfig struct {
	SocketPath        string
	ExpectedServerUID uint32
	MaxObjectBytes    int64
}

// UnixServer owns the private disk vault and accepts only the small framed
// protocol below. It does not start a public listener.
type UnixServer struct {
	vault       *Vault
	listener    *net.UnixListener
	allowedUIDs map[uint32]struct{}
	maxBytes    int64
	closeOnce   sync.Once
}

// UnixClient is used by a worker's fixed vault adapter. It contains no
// filesystem root, generic endpoint, or server credential.
type UnixClient struct {
	socketPath string
	serverUID  uint32
	maxBytes   int64
}

type unixRequest struct {
	Schema     string     `json:"schema"`
	Operation  string     `json:"operation"`
	Descriptor Descriptor `json:"descriptor"`
}

type unixResponse struct {
	Schema     string     `json:"schema"`
	OK         bool       `json:"ok"`
	Descriptor Descriptor `json:"descriptor,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// ListenUnix opens the vault root and one Unix socket. A stale or substituted
// socket is a startup failure rather than a reason to unlink an arbitrary path.
func ListenUnix(config UnixServerConfig) (*UnixServer, error) {
	normalized, allowed, err := normalizeUnixServerConfig(config)
	if err != nil {
		return nil, err
	}
	vault, err := Open(normalized.Root, normalized.MaxObjectBytes)
	if err != nil {
		return nil, err
	}
	if err := verifySocketDirectory(filepath.Dir(normalized.SocketPath), normalized.SocketGroupID); err != nil {
		return nil, fmt.Errorf("artifact vault socket directory: %w", err)
	}
	if _, err := os.Lstat(normalized.SocketPath); err == nil {
		return nil, errors.New("artifact vault socket already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect artifact vault socket: %w", err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: normalized.SocketPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen on artifact vault socket: %w", err)
	}
	if err := os.Chown(normalized.SocketPath, os.Geteuid(), int(normalized.SocketGroupID)); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("set artifact vault socket group: %w", err)
	}
	if err := os.Chmod(normalized.SocketPath, unixSocketMode); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("set artifact vault socket mode: %w", err)
	}
	if err := verifySocket(normalized.SocketPath, uint32(os.Geteuid()), normalized.SocketGroupID); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return &UnixServer{vault: vault, listener: listener, allowedUIDs: allowed, maxBytes: normalized.MaxObjectBytes}, nil
}

// Serve runs until context cancellation or Close. Each connection carries one
// operation and is closed afterwards, so there is no request pipelining or
// ambient authority carried between calls.
func (s *UnixServer) Serve(ctx context.Context) error {
	if s == nil || s.listener == nil || s.vault == nil {
		return errors.New("artifact vault Unix server is unavailable")
	}
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	for {
		connection, err := s.listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.serveConnection(ctx, connection)
	}
}

// Close releases the listener. The runtime directory—not arbitrary caller
// cleanup—is responsible for removing a socket after an unclean host restart.
func (s *UnixServer) Close() error {
	if s == nil || s.listener == nil {
		return nil
	}
	var err error
	s.closeOnce.Do(func() { err = s.listener.Close() })
	return err
}

func (s *UnixServer) serveConnection(ctx context.Context, connection *net.UnixConn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(defaultUnixWait))
	uid, err := peerUID(connection)
	if err != nil || !s.authorized(uid) {
		_ = writeUnixResponse(connection, unixResponse{Schema: unixSchema, Error: "artifact vault peer is not authorised"})
		return
	}
	reader := bufio.NewReaderSize(connection, maxUnixHeader+1)
	request, err := readUnixRequest(reader)
	if err != nil {
		_ = writeUnixResponse(connection, unixResponse{Schema: unixSchema, Error: "artifact vault request is invalid"})
		return
	}
	switch request.Operation {
	case unixStore:
		body, err := readExact(reader, request.Descriptor.Bytes, s.maxBytes)
		if err != nil || DescriptorFor(body) != request.Descriptor {
			_ = writeUnixResponse(connection, unixResponse{Schema: unixSchema, Error: "artifact vault object does not match its descriptor"})
			return
		}
		descriptor, err := s.vault.Store(ctx, body)
		if err != nil || descriptor != request.Descriptor {
			_ = writeUnixResponse(connection, unixResponse{Schema: unixSchema, Error: "artifact vault could not store object"})
			return
		}
		_ = writeUnixResponse(connection, unixResponse{Schema: unixSchema, OK: true, Descriptor: descriptor})
	case unixLoad:
		body, err := s.vault.Load(ctx, request.Descriptor)
		if err != nil {
			_ = writeUnixResponse(connection, unixResponse{Schema: unixSchema, Error: "artifact vault object is unavailable"})
			return
		}
		if err := writeUnixResponse(connection, unixResponse{Schema: unixSchema, OK: true, Descriptor: request.Descriptor}); err != nil {
			return
		}
		_ = writeAll(connection, body)
	default:
		_ = writeUnixResponse(connection, unixResponse{Schema: unixSchema, Error: "artifact vault operation is invalid"})
	}
}

func (s *UnixServer) authorized(uid uint32) bool {
	_, allowed := s.allowedUIDs[uid]
	return allowed
}

// NewUnixClient validates only static local socket identity. It neither dials
// a network endpoint nor accepts a caller-provided path per operation.
func NewUnixClient(config UnixClientConfig) (*UnixClient, error) {
	path := filepath.Clean(strings.TrimSpace(config.SocketPath))
	if !filepath.IsAbs(path) || path == "/" || config.MaxObjectBytes <= 0 {
		return nil, errors.New("artifact vault client requires an absolute socket path and positive size limit")
	}
	if err := verifySocket(path, config.ExpectedServerUID, socketGID(path)); err != nil {
		return nil, fmt.Errorf("artifact vault client socket: %w", err)
	}
	return &UnixClient{socketPath: path, serverUID: config.ExpectedServerUID, maxBytes: config.MaxObjectBytes}, nil
}

// Store persists one immutable object through the fixed local broker.
func (c *UnixClient) Store(ctx context.Context, body []byte) (Descriptor, error) {
	if c == nil || len(body) == 0 || int64(len(body)) > c.maxBytes {
		return Descriptor{}, errors.New("artifact vault object is empty or exceeds its configured limit")
	}
	descriptor := DescriptorFor(body)
	response, _, connection, err := c.open(ctx, unixRequest{Schema: unixSchema, Operation: unixStore, Descriptor: descriptor}, body)
	if err != nil {
		return Descriptor{}, err
	}
	defer connection.Close()
	if !response.OK || response.Descriptor != descriptor {
		return Descriptor{}, errors.New("artifact vault store was refused")
	}
	return descriptor, nil
}

// Load retrieves only the exact immutable object named by descriptor.
func (c *UnixClient) Load(ctx context.Context, descriptor Descriptor) ([]byte, error) {
	if c == nil || descriptor.Validate(c.maxBytes) != nil {
		return nil, errors.New("artifact vault descriptor is invalid")
	}
	response, reader, connection, err := c.open(ctx, unixRequest{Schema: unixSchema, Operation: unixLoad, Descriptor: descriptor}, nil)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if !response.OK || response.Descriptor != descriptor {
		return nil, errors.New("artifact vault load was refused")
	}
	body, err := readExact(reader, descriptor.Bytes, c.maxBytes)
	if err != nil || DescriptorFor(body) != descriptor {
		return nil, errors.New("artifact vault returned an invalid object")
	}
	return body, nil
}

func (c *UnixClient) open(ctx context.Context, request unixRequest, body []byte) (unixResponse, *bufio.Reader, *net.UnixConn, error) {
	if err := request.Descriptor.Validate(c.maxBytes); err != nil {
		return unixResponse{}, nil, nil, err
	}
	if err := verifySocket(c.socketPath, c.serverUID, socketGID(c.socketPath)); err != nil {
		return unixResponse{}, nil, nil, errors.New("artifact vault socket identity changed")
	}
	dialer := net.Dialer{}
	connectionRaw, err := dialer.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return unixResponse{}, nil, nil, err
	}
	connection, ok := connectionRaw.(*net.UnixConn)
	if !ok {
		_ = connectionRaw.Close()
		return unixResponse{}, nil, nil, errors.New("artifact vault did not open a Unix connection")
	}
	if err := connection.SetDeadline(time.Now().Add(defaultUnixWait)); err != nil {
		_ = connection.Close()
		return unixResponse{}, nil, nil, err
	}
	if err := writeUnixRequest(connection, request, body); err != nil {
		_ = connection.Close()
		return unixResponse{}, nil, nil, err
	}
	if err := connection.CloseWrite(); err != nil {
		_ = connection.Close()
		return unixResponse{}, nil, nil, err
	}
	reader := bufio.NewReaderSize(connection, maxUnixHeader+1)
	response, err := readUnixResponse(reader)
	if err != nil {
		_ = connection.Close()
		return unixResponse{}, nil, nil, err
	}
	return response, reader, connection, nil
}

func normalizeUnixServerConfig(config UnixServerConfig) (UnixServerConfig, map[uint32]struct{}, error) {
	config.Root = filepath.Clean(strings.TrimSpace(config.Root))
	config.SocketPath = filepath.Clean(strings.TrimSpace(config.SocketPath))
	if !filepath.IsAbs(config.Root) || config.Root == "/" || !filepath.IsAbs(config.SocketPath) || config.SocketPath == "/" || config.MaxObjectBytes <= 0 {
		return UnixServerConfig{}, nil, errors.New("artifact vault server paths must be absolute and size must be positive")
	}
	if filepath.Dir(config.SocketPath) == config.Root || strings.HasPrefix(config.SocketPath, config.Root+string(filepath.Separator)) {
		return UnixServerConfig{}, nil, errors.New("artifact vault socket must not live under its private object root")
	}
	allowed := make(map[uint32]struct{}, len(config.AllowedPeerUIDs))
	for _, uid := range config.AllowedPeerUIDs {
		allowed[uid] = struct{}{}
	}
	if len(allowed) == 0 {
		return UnixServerConfig{}, nil, errors.New("artifact vault server requires allowed worker peer UIDs")
	}
	return config, allowed, nil
}

func readUnixRequest(reader *bufio.Reader) (unixRequest, error) {
	raw, err := readHeader(reader)
	if err != nil {
		return unixRequest{}, err
	}
	var request unixRequest
	if err := decodeExact(raw, &request); err != nil || request.Schema != unixSchema || (request.Operation != unixStore && request.Operation != unixLoad) || request.Descriptor.Validate(1<<62) != nil {
		return unixRequest{}, errors.New("invalid artifact vault request")
	}
	return request, nil
}

func readUnixResponse(reader *bufio.Reader) (unixResponse, error) {
	raw, err := readHeader(reader)
	if err != nil {
		return unixResponse{}, err
	}
	var response unixResponse
	if err := decodeExact(raw, &response); err != nil || response.Schema != unixSchema || (!response.OK && response.Error == "") || (response.OK && response.Error != "") {
		return unixResponse{}, errors.New("invalid artifact vault response")
	}
	return response, nil
}

func writeUnixRequest(writer io.Writer, request unixRequest, body []byte) error {
	if err := writeHeader(writer, request); err != nil {
		return err
	}
	if request.Operation == unixStore {
		return writeAll(writer, body)
	}
	return nil
}

func writeUnixResponse(writer io.Writer, response unixResponse) error {
	return writeHeader(writer, response)
}

func writeHeader(writer io.Writer, value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > maxUnixHeader {
		return errors.New("artifact vault wire header is invalid")
	}
	return writeAll(writer, append(raw, '\n'))
}

func writeAll(writer io.Writer, body []byte) error {
	for len(body) != 0 {
		written, err := writer.Write(body)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		body = body[written:]
	}
	return nil
}

func readHeader(reader *bufio.Reader) ([]byte, error) {
	raw, err := reader.ReadSlice('\n')
	if err != nil || len(raw) < 2 || len(raw) > maxUnixHeader+1 {
		return nil, errors.New("artifact vault wire header is invalid")
	}
	return append([]byte(nil), raw[:len(raw)-1]...), nil
}

func decodeExact(raw []byte, value any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing artifact vault JSON")
	}
	return nil
}

func readExact(reader io.Reader, bytes int64, maximum int64) ([]byte, error) {
	if bytes <= 0 || bytes > maximum || bytes > int64(int(^uint(0)>>1)) {
		return nil, errors.New("artifact vault wire body exceeds its bound")
	}
	body := make([]byte, int(bytes))
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	return body, nil
}

func verifySocketDirectory(path string, group uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != socketDirMode || int(stat.Uid) != os.Geteuid() || uint32(stat.Gid) != group {
		return errors.New("must be a mode-0710 vault-owned socket directory with the configured worker group")
	}
	return nil
}

func verifySocket(path string, owner, group uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != unixSocketMode || uint32(stat.Uid) != owner || uint32(stat.Gid) != group {
		return errors.New("must be the configured mode-0660 vault-owned Unix socket")
	}
	return nil
}

func socketGID(path string) uint32 {
	info, err := os.Lstat(path)
	if err != nil {
		return ^uint32(0)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ^uint32(0)
	}
	return uint32(stat.Gid)
}

func peerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *syscall.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credential, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if controlErr != nil || credential == nil {
		return 0, errors.New("artifact vault peer credentials are unavailable")
	}
	return credential.Uid, nil
}

// AllowedPeerUIDs returns a canonical presentation-safe list useful for
// operator diagnostics. It never exposes any socket or filesystem secret.
func (s *UnixServer) AllowedPeerUIDs() []uint32 {
	if s == nil {
		return nil
	}
	result := make([]uint32, 0, len(s.allowedUIDs))
	for uid := range s.allowedUIDs {
		result = append(result, uid)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

// SocketFingerprint returns a stable non-secret identifier for audit records.
func (c *UnixClient) SocketFingerprint() string {
	if c == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(c.socketPath))
	return fmt.Sprintf("sha256:%x", sum[:8])
}
