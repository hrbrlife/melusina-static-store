package releasefinalizer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/catalogselection"
	"github.com/hrbrlife/melusina-store-sidecar/internal/artifactvault"
	"github.com/hrbrlife/melusina-store-sidecar/internal/publisherenvelope"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// ServiceConfig is installed by the service owner. None of these paths,
// identities, endpoints or authority pins are accepted in a release request.
// The service composes only the existing fixed finalization engines.
type ServiceConfig struct {
	Schema                  string `json:"schema"`
	WorkerID                string `json:"workerId"`
	RepositoryRoot          string `json:"repositoryRoot"`
	ResultKeyPath           string `json:"resultKeyPath"`
	ResultPublicKey         string `json:"resultPublicKey"`
	PublisherEnvelopeSocket string `json:"publisherEnvelopeSocket"`
	Vault                   struct {
		SocketPath        string  `json:"socketPath"`
		ExpectedServerUID *uint32 `json:"expectedServerUid"`
	} `json:"vault"`
	Core struct {
		RPCURL  string   `json:"rpcUrl"`
		Members []string `json:"members"`
	} `json:"core"`
	TLS struct {
		ListenAddr                string `json:"listenAddr"`
		CertPath                  string `json:"certPath"`
		KeyPath                   string `json:"keyPath"`
		ClientCAPath              string `json:"clientCaPath"`
		StoreLinkClientCertSHA256 string `json:"storeLinkClientCertSha256"`
	} `json:"tls"`
}

// Service owns the actual fixed mTLS listener and its durable runner. There
// is deliberately no backend/handler injection in this runtime constructor.
type Service struct {
	server *http.Server
	runner *Runner
}

func LoadService(path string) (*Service, error) {
	raw, err := readServicePrivateFile(path, 64<<10)
	if err != nil {
		return nil, errors.New("finalizer service config must be one bounded owner-only file")
	}
	var config ServiceConfig
	if catalogselection.DecodeExact(raw, &config) != nil || config.Schema != "bazaar-release-finalizer-service-v1" || !safeText(config.WorkerID, 256) || config.Vault.ExpectedServerUID == nil || len(config.Core.Members) != 4 {
		return nil, errors.New("finalizer service config does not bind the required fixed identities")
	}
	key, err := loadServiceResultKey(config.ResultKeyPath, config.ResultPublicKey)
	if err != nil {
		return nil, err
	}
	var members [4]string
	copy(members[:], config.Core.Members)
	observer, err := NewCoreProposalObserver(CoreProposalObserverConfig{RPCURL: config.Core.RPCURL, Members: members})
	if err != nil {
		return nil, err
	}
	for _, member := range members {
		if member == config.ResultPublicKey {
			return nil, errors.New("finalizer result identity must be separate from original Core members")
		}
	}
	vault, err := artifactvault.NewUnixClient(artifactvault.UnixClientConfig{SocketPath: config.Vault.SocketPath, ExpectedServerUID: *config.Vault.ExpectedServerUID, MaxObjectBytes: maxBytes})
	if err != nil {
		return nil, err
	}
	if err := publisherenvelope.CheckSocket(config.PublisherEnvelopeSocket); err != nil {
		return nil, err
	}
	signer, err := publisherenvelope.NewClient(config.PublisherEnvelopeSocket)
	if err != nil {
		return nil, err
	}
	engine, err := New(config.WorkerID, key, vault, observer, signer)
	if err != nil {
		return nil, err
	}
	records, err := OpenRepository(config.RepositoryRoot, config.WorkerID, key.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	runner, err := NewRunner(engine, records, vault)
	if err != nil {
		return nil, err
	}
	handler, err := NewHTTPHandler(runner, config.TLS.StoreLinkClientCertSHA256)
	if err != nil {
		return nil, err
	}
	server, err := NewMTLSServer(MTLSConfig{
		ListenAddr: config.TLS.ListenAddr, CertPath: config.TLS.CertPath, KeyPath: config.TLS.KeyPath,
		ClientCAPath: config.TLS.ClientCAPath, StoreLinkClientCertSHA256: config.TLS.StoreLinkClientCertSHA256,
	}, handler)
	if err != nil {
		return nil, err
	}
	return &Service{server: server, runner: runner}, nil
}

func loadServiceResultKey(path, publicText string) (ed25519.PrivateKey, error) {
	raw, err := readServicePrivateFile(path, 16<<10)
	if err != nil {
		return nil, errors.New("finalizer result key must be owner-only")
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("-----BEGIN PRIVATE KEY-----")) || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("finalizer result key must be one PKCS8 key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("finalizer result key is malformed")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	public, err := primitives.PubkeyFromBase58(publicText)
	if !ok || len(key) != ed25519.PrivateKeySize || err != nil || !bytes.Equal(key.Public().(ed25519.PublicKey), public[:]) {
		return nil, errors.New("finalizer result key differs from its installed public identity")
	}
	return key, nil
}

func readServicePrivateFile(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("private service path must be canonical and absolute")
	}
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return nil, errors.New("private service parent cannot be redirected")
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("private service parent must be owner-only")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("private service parent has another owner")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("private service file has invalid type, mode or size")
	}
	stat, ok = info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || stat.Nlink != 1 {
		return nil, errors.New("private service file has another owner or hard link")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > maximum {
		return nil, errors.New("private service file exceeded its bound")
	}
	return raw, nil
}

// Serve owns both listener and request lifetime. A stopped service cancels
// outstanding read-only governance checks and closes its fixed listener.
func (s *Service) Serve(ctx context.Context) error {
	if s == nil || s.server == nil || ctx == nil {
		return errors.New("finalizer service is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return err
	}
	return s.serve(ctx, listener)
}

func (s *Service) serve(ctx context.Context, listener net.Listener) error {
	defer listener.Close()
	s.server.BaseContext = func(net.Listener) context.Context { return ctx }
	done := make(chan error, 1)
	go func() { done <- s.server.ServeTLS(listener, "", "") }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if s.server.Shutdown(stop) != nil {
			_ = s.server.Close()
		}
		<-done
		return ctx.Err()
	}
}
