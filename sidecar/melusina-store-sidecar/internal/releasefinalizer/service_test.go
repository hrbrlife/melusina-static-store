package releasefinalizer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/artifactvault"
	"github.com/hrbrlife/melusina-store-sidecar/internal/publisherenvelope"
	sharedvault "github.com/melusina-os/melusina-artifact-vault"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

type serviceFixture struct {
	config     ServiceConfig
	path       string
	chain      *preparedEngineFixture
	key        ed25519.PrivateKey
	publisher  *identity.Private
	roots      *x509.CertPool
	clientLeaf tls.Certificate
	otherLeaf  tls.Certificate
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	f := &serviceFixture{chain: newPreparedEngineFixture(t)}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	ca, caKey, roots := newFinalizerTestCA(t)
	f.roots = roots
	f.clientLeaf = newFinalizerTestLeaf(t, 22, "store-link.test", x509.ExtKeyUsageClientAuth, ca, caKey)
	f.otherLeaf = newFinalizerTestLeaf(t, 23, "foreign-link.test", x509.ExtKeyUsageClientAuth, ca, caKey)
	serving := newFinalizerTestLeaf(t, 24, "finalizer.test", x509.ExtKeyUsageServerAuth, ca, caKey)
	f.config.Schema, f.config.WorkerID = "bazaar-release-finalizer-service-v1", "finalizer-service-test"
	f.config.RepositoryRoot = filepath.Join(root, "records")
	f.config.ResultKeyPath = filepath.Join(root, "result.pem")
	f.key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x72}, 32))
	f.config.ResultPublicKey = primitives.EncodeBase58(f.key.Public().(ed25519.PublicKey))
	der, err := x509.MarshalPKCS8PrivateKey(f.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.config.ResultKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	f.config.Core.RPCURL = f.chain.chain.o.endpoint
	f.config.Core.Members = append([]string(nil), f.chain.chain.sdk.Pins.Members[:]...)
	f.config.TLS.ListenAddr = "127.0.0.1:0"
	f.config.TLS.CertPath, f.config.TLS.KeyPath = writeFinalizerCertificate(t, root, "serving", serving)
	f.config.TLS.ClientCAPath = filepath.Join(root, "ca.pem")
	if err := os.WriteFile(f.config.TLS.ClientCAPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	f.config.TLS.StoreLinkClientCertSHA256 = hash(f.clientLeaf.Certificate[0])
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	vaultSocketRoot := filepath.Join(root, "vault-socket")
	if err := os.Mkdir(vaultSocketRoot, 0710); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(vaultSocketRoot, 0710); err != nil {
		t.Fatal(err)
	}
	f.config.Vault.SocketPath = filepath.Join(vaultSocketRoot, "vault.sock")
	uid := uint32(os.Geteuid())
	f.config.Vault.ExpectedServerUID = &uid
	vault, err := sharedvault.ListenUnix(sharedvault.UnixServerConfig{Root: filepath.Join(root, "vault"), SocketPath: f.config.Vault.SocketPath, SocketGroupID: uint32(os.Getegid()), AllowedPeerUIDs: []uint32{uid}, MaxObjectBytes: maxBytes})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = vault.Serve(ctx) }()
	t.Cleanup(func() { _ = vault.Close() })
	client, err := artifactvault.NewUnixClient(artifactvault.UnixClientConfig{SocketPath: f.config.Vault.SocketPath, ExpectedServerUID: uid, MaxObjectBytes: maxBytes})
	if err != nil {
		t.Fatal(err)
	}
	for digest, raw := range f.chain.vault.values {
		if got, err := client.Store(ctx, raw); err != nil || got.SHA256 != digest {
			t.Fatalf("real vault store failed: %v", err)
		}
	}
	signerDir := filepath.Join(root, "publisher")
	if err := os.Mkdir(signerDir, 0700); err != nil {
		t.Fatal(err)
	}
	f.config.PublisherEnvelopeSocket = filepath.Join(signerDir, "signer.sock")
	f.publisher = serviceTestIdentity(t, 0x21, false)
	signer, err := publisherenvelope.New(f.publisher, serviceTestIdentity(t, 0x31, true).Public(), f.chain.request.StoreID, uid)
	if err != nil {
		t.Fatal(err)
	}
	signerDone := make(chan error, 1)
	signerSocket := f.config.PublisherEnvelopeSocket
	go func() { signerDone <- publisherenvelope.Serve(ctx, signerSocket, signer) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-signerDone:
		case <-time.After(time.Second):
			t.Error("publisher custody did not stop")
		}
	})
	deadline := time.Now().Add(time.Second)
	for publisherenvelope.CheckSocket(f.config.PublisherEnvelopeSocket) != nil {
		if time.Now().After(deadline) {
			t.Fatal("publisher socket unavailable")
		}
		time.Sleep(time.Millisecond)
	}
	f.path = filepath.Join(root, "service.json")
	f.write(t)
	return f
}

func (f *serviceFixture) write(t *testing.T) {
	t.Helper()
	raw, err := json.Marshal(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func serviceTestIdentity(t *testing.T, seed byte, sidecar bool) *identity.Private {
	t.Helper()
	ref := identity.Ref{Kind: identity.KindPearl, ChainID: "solana:devnet", ProgramID: "program", LicenseMint: "license", Domain: "bazaar.test", PDA: "pda", PearlIDHash: "pearl", KeyVersion: 1}
	if sidecar {
		ref.Kind, ref.PearlIDHash, ref.SidecarID = identity.KindSidecar, "", "store-test"
	}
	var sign, box [32]byte
	for i := range sign {
		sign[i], box[i] = seed, seed+1
	}
	private, err := identity.NewPrivate(ref, sign, box)
	if err != nil {
		t.Fatal(err)
	}
	return private
}

func (f *serviceFixture) load(t *testing.T) *Service {
	t.Helper()
	s, err := LoadService(f.path)
	if err != nil {
		t.Fatal(err)
	}
	o, ok := s.runner.engine.observer.(*CoreProposalObserver)
	if !ok || o.pins.registry != observerKey(coreRegistryProgram) || o.pins.multisig != observerKey(coreReleaseMultisig) {
		t.Fatal("service did not install original fixed Core observer")
	}
	if _, ok := s.runner.engine.signer.(*publisherenvelope.Client); !ok {
		t.Fatal("service did not install actual custody client")
	}
	if _, ok := s.runner.engine.vault.(*artifactvault.UnixClient); !ok {
		t.Fatal("service did not install actual artifact vault client")
	}
	// As in the original SDK fixture tests, only the test substitutes synthetic
	// chain accounts/CA. The runtime config has no program/vault/parser override.
	o.pins = f.chain.chain.o.pins
	o.now = f.chain.chain.o.now
	o.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = f.chain.chain.o.client.Transport.(*http.Transport).TLSClientConfig.RootCAs
	return s
}

func serveServiceFixture(t *testing.T, s *Service, roots *x509.CertPool, leaf tls.Certificate) (*http.Client, string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.serve(ctx, listener) }()
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "finalizer.test", Certificates: []tls.Certificate{leaf}}}}
	stop := func() {
		cancel()
		client.CloseIdleConnections()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("service shutdown: %v", err)
			}
		case <-time.After(6 * time.Second):
			t.Error("service did not stop")
		}
	}
	return client, "https://" + listener.Addr().String(), stop
}

func TestServiceActualMTLSVaultCoreCustodyAndRestart(t *testing.T) {
	f := newServiceFixture(t)
	s := f.load(t)
	client, origin, stop := serveServiceFixture(t, s, f.roots, f.clientLeaf)
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	f.chain.chain.accounts[2] = f.chain.chain.account(f.chain.chain.sdk.PendingProposal)
	f.chain.chain.accounts[3].Data = nil
	raw, _ := json.Marshal(f.chain.request)
	response, err := client.Post(origin+jobCollectionPath, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var job Job
	decodeErr := json.NewDecoder(response.Body).Decode(&job)
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted || decodeErr != nil {
		t.Fatalf("pending service returned %d: %v", response.StatusCode, decodeErr)
	}
	stored, found, err := s.runner.records.Load(context.Background(), job.ID)
	if err != nil || !found || stored.State != WaitingForGovernance || stored.Result != nil {
		t.Fatal("pending job did not remain unsigned and durable")
	}
	stop()
	stop = nil
	f.chain.chain.accounts[2] = f.chain.chain.account(f.chain.chain.sdk.Proposal)
	f.chain.chain.accounts[3] = f.chain.chain.account(f.chain.chain.sdk.Release)
	s = f.load(t)
	client, origin, stop = serveServiceFixture(t, s, f.roots, f.clientLeaf)
	response, err = client.Get(origin + jobCollectionPath + "/" + job.ID)
	if err != nil {
		t.Fatal(err)
	}
	var completed completion
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || json.Unmarshal(body, &completed) != nil {
		_, _, reason := s.runner.Run(context.Background(), f.chain.request)
		t.Fatalf("actual finalization failed %d: %s (%v)", response.StatusCode, body, reason)
	}
	sig, err := base64.RawURLEncoding.DecodeString(completed.Result.Signature)
	if err != nil || !ed25519.Verify(f.key.Public().(ed25519.PublicKey), []byte(resultPrefix+completed.Result.Digest()), sig) || completed.Result.Job != job {
		t.Fatal("real result signature/job is invalid")
	}
	finalBody, err := base64.RawURLEncoding.DecodeString(completed.FinalCandidateB64)
	if err != nil || hash(finalBody) != completed.Result.FinalCandidateSHA256 {
		t.Fatal("final body does not match real result")
	}
	var publish struct {
		Envelope envelope.Signed `json:"envelope"`
	}
	if json.Unmarshal(finalBody, &publish) != nil || envelope.VerifySignature(publish.Envelope, f.publisher.Public().SignPubkeyB58) != nil {
		t.Fatal("real publisher custody signature is invalid")
	}
	before := f.chain.chain.calls
	response, err = client.Get(origin + jobCollectionPath + "/" + job.ID)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Equal(body, again) || f.chain.chain.calls != before {
		t.Fatal("unexpired retry did not return exact durable result")
	}
	foreign := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.roots, ServerName: "finalizer.test", Certificates: []tls.Certificate{f.otherLeaf}}}}
	defer foreign.CloseIdleConnections()
	if response, err := foreign.Get(origin + jobCollectionPath + "/" + job.ID); err == nil {
		response.Body.Close()
		t.Fatal("same-CA foreign Store Link was accepted")
	}
}

func TestServiceRefusesUnpinnedAndAmbiguousConfiguration(t *testing.T) {
	f := newServiceFixture(t)
	for name, change := range map[string]func(*ServiceConfig){
		"missing vault UID":     func(c *ServiceConfig) { c.Vault.ExpectedServerUID = nil },
		"wrong result identity": func(c *ServiceConfig) { c.ResultPublicKey = primitives.EncodeBase58(bytes.Repeat([]byte{1}, 32)) },
		"missing Core member":   func(c *ServiceConfig) { c.Core.Members = c.Core.Members[:3] },
		"duplicate Core member": func(c *ServiceConfig) { c.Core.Members[1] = c.Core.Members[0] },
		"cleartext RPC":         func(c *ServiceConfig) { c.Core.RPCURL = "http://localhost" },
		"credential RPC":        func(c *ServiceConfig) { c.Core.RPCURL = "https://user:secret@rpc.invalid" },
		"unavailable custody": func(c *ServiceConfig) {
			c.PublisherEnvelopeSocket = filepath.Join(filepath.Dir(f.path), "missing.sock")
		},
		"unavailable vault": func(c *ServiceConfig) { c.Vault.SocketPath = filepath.Join(filepath.Dir(f.path), "missing.sock") },
	} {
		t.Run(name, func(t *testing.T) {
			old := f.config
			f.config.Core.Members = append([]string(nil), old.Core.Members...)
			change(&f.config)
			f.write(t)
			if _, err := LoadService(f.path); err == nil {
				t.Fatal("invalid fixed binding accepted")
			}
			f.config = old
		})
	}
	f.write(t)
	original, _ := os.ReadFile(f.path)
	for _, raw := range [][]byte{
		append([]byte(`{"schema":"wrong",`), original[1:]...),
		bytes.Replace(original, []byte(`"workerId"`), []byte(`"WorkerID"`), 1),
		append([]byte(`{"command":"sh",`), original[1:]...),
		bytes.Replace(original, []byte(`"members":`), []byte(`"rpcUrl":"https://other.invalid","members":`), 1),
		bytes.Repeat([]byte(" "), (64<<10)+1),
	} {
		if err := os.WriteFile(f.path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadService(f.path); err == nil {
			t.Fatal("ambiguous or oversized config accepted")
		}
	}
}

func TestServicePrivateInputBoundsAndOriginalKeyPin(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	raw := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(root, "key.pem")
	_ = os.WriteFile(path, raw, 0600)
	pub := primitives.EncodeBase58(key.Public().(ed25519.PublicKey))
	if actual, err := loadServiceResultKey(path, pub); err != nil || !bytes.Equal(actual, key) {
		t.Fatal("exact pinned key refused")
	}
	for _, value := range [][]byte{append(bytes.Clone(raw), raw...), append([]byte("discarded prefix"), raw...), []byte("invalid"), bytes.Repeat([]byte("x"), (16<<10)+1)} {
		_ = os.WriteFile(path, value, 0600)
		if _, err := loadServiceResultKey(path, pub); err == nil {
			t.Fatal("unbounded or multiple key accepted")
		}
	}
	_ = os.WriteFile(path, raw, 0600)
	_ = os.Chmod(path, 0644)
	if _, err := loadServiceResultKey(path, pub); err == nil {
		t.Fatal("readable private key accepted")
	}
	_ = os.Chmod(path, 0600)
	link := filepath.Join(root, "link.pem")
	_ = os.Symlink(path, link)
	if _, err := loadServiceResultKey(link, pub); err == nil {
		t.Fatal("redirected private key accepted")
	}
	_ = os.Remove(link)
	_ = os.Link(path, link)
	if _, err := loadServiceResultKey(path, pub); err == nil {
		t.Fatal("hardlinked private key accepted")
	}
	_ = os.Remove(link)
	_ = os.Chmod(root, 0755)
	if _, err := loadServiceResultKey(path, pub); err == nil {
		t.Fatal("public private-key parent accepted")
	}
}

type serviceRoundTrip func(*http.Request) (*http.Response, error)

func (f serviceRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestServiceCancellationReachesActiveCoreRequest(t *testing.T) {
	f := newServiceFixture(t)
	s := f.load(t)
	entered, canceled := make(chan struct{}), make(chan struct{})
	s.runner.engine.observer.(*CoreProposalObserver).client.Transport = serviceRoundTrip(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
		return nil, r.Context().Err()
	})
	client, origin, stop := serveServiceFixture(t, s, f.roots, f.clientLeaf)
	raw, _ := json.Marshal(f.chain.request)
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		response, err := client.Post(origin+jobCollectionPath, "application/json", bytes.NewReader(raw))
		if err == nil {
			response.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		stop()
		t.Fatal("actual Core request did not start")
	}
	stop()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("service lifetime did not cancel active Core request")
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("service request did not stop")
	}
}

type serviceEnvelopeSigner func(context.Context, publisherenvelope.Request) (publisherenvelope.Response, error)

func (f serviceEnvelopeSigner) Sign(ctx context.Context, r publisherenvelope.Request) (publisherenvelope.Response, error) {
	return f(ctx, r)
}

func TestFinalizerRechecksTimeAndCancellationAfterCustody(t *testing.T) {
	for _, name := range []string{"canceled", "clock backwards", "excess TTL"} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC()
			engine, request, job, _, signer, _ := finalizerFixture(t, now)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			engine.signer = serviceEnvelopeSigner(func(ctx context.Context, r publisherenvelope.Request) (publisherenvelope.Response, error) {
				response, err := signer.Sign(ctx, r)
				switch name {
				case "canceled":
					cancel()
				case "clock backwards":
					engine.now = func() time.Time { return now.Add(-time.Second) }
				case "excess TTL":
					response.ExpiresAt = now.Add(16 * time.Minute)
				}
				return response, err
			})
			if _, _, err := engine.Finalize(ctx, job, request); err == nil {
				t.Fatal("custody return bypassed final time/context check")
			}
		})
	}
}
