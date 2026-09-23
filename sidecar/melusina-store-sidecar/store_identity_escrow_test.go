package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/storerecovery"
)

type identityEscrowFixture struct {
	cfg        Config
	configPath string
	verified   *verifiedBootIdentity
	state      *storeEnrollmentState
	holders    map[string]*ecdh.PrivateKey
	recipients storerecovery.IdentityEscrowRecipientsV1
}

// newIdentityEscrowFixture is the enrolled root Store of the entry-point
// fixture, its boot identity derived in process through the enrollment gate,
// with one holder per shard.
func newIdentityEscrowFixture(t *testing.T) identityEscrowFixture {
	t.Helper()
	entry := newEnrolledEntryPointFixture(t)
	configPath := entry.configs["enrolled"]
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	verified, state, err := deriveEnrolledBootIdentity(context.Background(), cfg, configPath, newConfiguredStoreRPCReader(cfg))
	if err != nil || verified == nil || state == nil {
		t.Fatalf("fixture: the enrolled Store does not pass the gate: %v", err)
	}
	f := identityEscrowFixture{cfg: cfg, configPath: configPath, verified: verified, state: state, holders: map[string]*ecdh.PrivateKey{}}
	f.recipients = storerecovery.IdentityEscrowRecipientsV1{Schema: storerecovery.IdentityEscrowRecipientsSchema}
	for _, role := range storerecovery.ShardRoles {
		holder, err := storerecovery.GenerateRecoveryKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		f.holders[role] = holder
		recipient := storerecovery.EncodeRecipient(holder.PublicKey())
		switch role {
		case storerecovery.ShardRoleAuthor:
			f.recipients.Author = []string{recipient}
		case storerecovery.ShardRoleHostObservation:
			f.recipients.HostObservation = []string{recipient}
		case storerecovery.ShardRoleRelease:
			f.recipients.Release = []string{recipient}
		}
	}
	return f
}

func (f identityEscrowFixture) handoffs(t *testing.T, escrow storerecovery.IdentityEscrow, session *ecdh.PrivateKey) [][]byte {
	t.Helper()
	var handoffs [][]byte
	for _, role := range storerecovery.ShardRoles {
		raw, _, err := storerecovery.ResealShard(rand.Reader, escrow.Manifest, f.verified.operator.Public().SignPubkeyB58, escrow.Escrows[role], f.holders[role], storerecovery.EncodeRecipient(session.PublicKey()))
		if err != nil {
			t.Fatalf("reseal %s: %v", role, err)
		}
		handoffs = append(handoffs, raw)
	}
	return handoffs
}

func newSessionKeyFile(t *testing.T) (*ecdh.PrivateKey, string) {
	t.Helper()
	session, err := storerecovery.GenerateRecoveryKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "session.key")
	if err := storerecovery.WritePrivateKeyFile(path, session); err != nil {
		t.Fatal(err)
	}
	return session, path
}

// The Store seals its own shards; on a replacement host whose configuration
// derives the same identity Ref, the three holders' handoffs rebuild the
// exact shard files, the session key is destroyed, and the replacement Store
// then passes the enrollment gate with the restored shards.
func TestStoreIdentityEscrowRestoresAStoreThatPassesTheGate(t *testing.T) {
	f := newIdentityEscrowFixture(t)
	escrow, err := sealStoreIdentityEscrow(f.cfg, f.verified, f.state, f.recipients)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	operatorKey := f.verified.operator.Public().SignPubkeyB58
	outDir := filepath.Join(t.TempDir(), "escrow")
	if err := writeStoreIdentityEscrow(outDir, escrow); err != nil {
		t.Fatal(err)
	}
	if err := writeStoreIdentityEscrow(outDir, escrow); storerecovery.RefusalName(err) != refusalStoreStateOutputExists {
		t.Fatalf("a second escrow into the same directory = %v", err)
	}
	written, err := os.ReadFile(filepath.Join(outDir, storeIdentityEscrowManifestFile))
	if err != nil || !bytes.Equal(written, escrow.Manifest) {
		t.Fatalf("written manifest differs: %v", err)
	}

	replacement := f.cfg
	replacement.BootIdentity.ShardsDir = filepath.Join(t.TempDir(), "restored-shards")
	_, sessionPath := newSessionKeyFile(t)
	session, err := storerecovery.ReadPrivateKeyFile(sessionPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := restoreStoreIdentity(replacement, escrow.Manifest, operatorKey, sessionPath, f.handoffs(t, escrow, session)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, role := range storerecovery.ShardRoles {
		original, err := os.ReadFile(filepath.Join(f.cfg.BootIdentity.ShardsDir, storerecovery.ShardFileName(role)))
		if err != nil {
			t.Fatal(err)
		}
		restored, err := os.ReadFile(filepath.Join(replacement.BootIdentity.ShardsDir, storerecovery.ShardFileName(role)))
		if err != nil {
			t.Fatal(err)
		}
		originalShard, _ := parseShard32(original)
		restoredShard, _ := parseShard32(restored)
		if originalShard != restoredShard {
			t.Fatalf("restored %s shard differs from the original", role)
		}
	}
	if _, err := os.Lstat(sessionPath); !os.IsNotExist(err) {
		t.Fatalf("the session key survived the restore: %v", err)
	}
	verified, _, err := deriveEnrolledBootIdentity(context.Background(), replacement, f.configPath, newConfiguredStoreRPCReader(replacement))
	if err != nil || verified == nil || verified.operator.Public().SignPubkeyB58 != operatorKey {
		t.Fatalf("the Store with restored shards does not pass the enrollment gate as the same operator: %v", err)
	}
}

// A replacement configuration that would derive the operator under another
// identity Ref is refused before any handoff is opened or any shard written.
// A binding rotation that keeps the operator coordinates is accepted.
func TestStoreIdentityRestoreRequiresTheSameIdentityRef(t *testing.T) {
	f := newIdentityEscrowFixture(t)
	escrow, err := sealStoreIdentityEscrow(f.cfg, f.verified, f.state, f.recipients)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	operatorKey := f.verified.operator.Public().SignPubkeyB58
	for _, tc := range []struct {
		name    string
		edit    func(*Config)
		refusal string
	}{
		{name: "binding-rotated-operator-kept", edit: func(cfg *Config) {
			cfg.BootIdentity.KeyVersion = 2
			cfg.BootIdentity.OperatorKeyVersion = 1
		}},
		{name: "another-chain", edit: func(cfg *Config) { cfg.BootIdentity.ChainID = "solana:another-network" }, refusal: refusalStoreIdentityRestoreConfigMismatch},
		{name: "binding-rotated-operator-lost", edit: func(cfg *Config) { cfg.BootIdentity.KeyVersion = 2 }, refusal: refusalStoreIdentityRestoreConfigMismatch},
		{name: "another-domain", edit: func(cfg *Config) { cfg.Domain = "another.store.invalid" }, refusal: refusalStoreIdentityRestoreConfigMismatch},
		{name: "another-mint", edit: func(cfg *Config) { cfg.LicenseNFTMint = randPubkeyB58(t) }, refusal: refusalStoreIdentityRestoreConfigMismatch},
		{name: "another-store", edit: func(cfg *Config) { cfg.StoreID = "another-store" }, refusal: refusalStoreIdentityRestoreConfigMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			replacement := f.cfg
			replacement.BootIdentity.ShardsDir = filepath.Join(t.TempDir(), "restored-shards")
			tc.edit(&replacement)
			session, sessionPath := newSessionKeyFile(t)
			err := restoreStoreIdentity(replacement, escrow.Manifest, operatorKey, sessionPath, f.handoffs(t, escrow, session))
			if tc.refusal == "" {
				if err != nil {
					t.Fatalf("positive control refused: %v", err)
				}
				return
			}
			if storerecovery.RefusalName(err) != tc.refusal {
				t.Fatalf("restore = %v, want %s", err, tc.refusal)
			}
			if _, statErr := os.Lstat(replacement.BootIdentity.ShardsDir); !os.IsNotExist(statErr) {
				t.Fatal("a refused restore wrote the shards directory")
			}
			if _, statErr := os.Lstat(sessionPath); statErr != nil {
				t.Fatal("a refused restore destroyed the session key")
			}
		})
	}
}

func TestStoreIdentityEscrowSealRefusesAnotherOperatorsEnrollment(t *testing.T) {
	f := newIdentityEscrowFixture(t)
	other := *f.state
	other.Enrollment.StoreOperatorKey = randPubkeyB58(t)
	if _, err := sealStoreIdentityEscrow(f.cfg, f.verified, &other, f.recipients); storerecovery.RefusalName(err) != refusalStoreStateEnrollmentOperator {
		t.Fatalf("seal under another operator's enrollment = %v", err)
	}
	if _, err := sealStoreIdentityEscrow(f.cfg, f.verified, nil, f.recipients); storerecovery.RefusalName(err) != refusalStoreStateRequiresEnrollment {
		t.Fatalf("seal without an enrollment = %v", err)
	}
	// Shards on disk that no longer derive the verified operator are refused.
	replaced := f.cfg
	replaced.BootIdentity.ShardsDir = t.TempDir()
	for _, role := range storerecovery.ShardRoles {
		if err := os.WriteFile(filepath.Join(replaced.BootIdentity.ShardsDir, storerecovery.ShardFileName(role)), []byte(randomShardHex(t)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := sealStoreIdentityEscrow(replaced, f.verified, f.state, f.recipients); storerecovery.RefusalName(err) != storerecovery.RefusalIdentityOperatorMismatch {
		t.Fatalf("seal of shards that derive another operator = %v", err)
	}
	// The public report of a seal is only public values.
	escrow, err := sealStoreIdentityEscrow(f.cfg, f.verified, f.state, f.recipients)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(escrow.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, role := range storerecovery.ShardRoles {
		shard, err := os.ReadFile(filepath.Join(f.cfg.BootIdentity.ShardsDir, storerecovery.ShardFileName(role)))
		if err != nil {
			t.Fatal(err)
		}
		needle := bytes.TrimSpace(shard)
		for name, raw := range escrow.Escrows {
			if bytes.Contains(raw, needle) {
				t.Fatalf("escrow %s carries the %s shard", name, role)
			}
		}
		if bytes.Contains(escrow.Manifest, needle) {
			t.Fatalf("the manifest carries the %s shard", role)
		}
	}
}

func randomShardHex(t *testing.T) string {
	t.Helper()
	var shard [32]byte
	if _, err := rand.Read(shard[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(shard[:])
}
