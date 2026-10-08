package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerpublish"
)

func TestInstallerPublishExactBindingAndRestartReplay(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.ReleaseMasterNftMint = randPubkeyB58(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	chain := newMockChainReader()
	bindTestInstallerReleaseEstate(t, chain, &cfg)
	pinRootStoreOperator(t, cfg, chain, op)
	artifact := []byte("exact installer binding")
	pinInstallerEntry(t, cfg, chain, artifact, "1.0.0", verify.AttestationStatusActive)
	svc := newTestService(t, cfg, chain, op)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	sign := func(class, name, method, target, storeID string) envelope.Signed {
		t.Helper()
		hash := sha256.Sum256(artifact)
		if method == http.MethodPost && target == installerpublish.Target {
			signed, err := installerpublish.Sign(pub, op.Public(), class, name, hex.EncodeToString(hash[:]),
				storeID, svc.cfg.Domain, svc.cfg.LicenseNFTMint, svc.cfg.ProgramID, 12345, 5*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			return signed
		}
		binding, err := installerpublish.Digest(class, name, hex.EncodeToString(hash[:]),
			storeID, svc.cfg.Domain, svc.cfg.LicenseNFTMint, svc.cfg.ProgramID)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := envelope.Sign(envelope.KindPublishRequest, pub, op.Public(), envelope.SignOptions{
			RequestHash: hex.EncodeToString(hash[:]), BodyHash: binding,
			Method: method, Target: target, TTL: 5 * time.Minute,
			Chain: envelope.ChainEvidence{ChainID: pub.Public().Ref.ChainID,
				ProgramID: svc.cfg.ProgramID, VerifiedSlot: 12345},
		})
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	for _, tc := range []struct {
		name, signedClass, signedName, requestClass, requestName, method, target, storeID string
	}{
		{"installer-publish-wrong-class", "shell", "sandstorm-42.tar.xz", "data", "sandstorm-42.tar.xz", http.MethodPost, installerpublish.Target, svc.cfg.StoreID},
		{"installer-publish-wrong-name", "shell", "sandstorm-42.tar.xz", "shell", "other.tar.xz", http.MethodPost, installerpublish.Target, svc.cfg.StoreID},
		{"installer-publish-wrong-target", "shell", "sandstorm-42.tar.xz", "shell", "sandstorm-42.tar.xz", http.MethodPost, "/publish/other", svc.cfg.StoreID},
		{"installer-publish-wrong-estate", "shell", "sandstorm-42.tar.xz", "shell", "sandstorm-42.tar.xz", http.MethodPost, installerpublish.Target, "other-store"},
		{"installer-publish-wrong-method", "shell", "sandstorm-42.tar.xz", "shell", "sandstorm-42.tar.xz", http.MethodPut, installerpublish.Target, svc.cfg.StoreID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signed := sign(tc.signedClass, tc.signedName, tc.method, tc.target, tc.storeID)
			response := doPublishInstaller(t, svc, jsonInstallerPublishBody(t, signed, tc.requestClass, tc.requestName, artifact))
			if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "check=installer_binding") {
				t.Fatalf("%s: status=%d body=%s", tc.name, response.Code, response.Body.String())
			}
		})
	}
	signed := sign("shell", "sandstorm-42.tar.xz", http.MethodPost, installerpublish.Target, svc.cfg.StoreID)
	response := doPublishInstaller(t, svc, jsonInstallerPublishBody(t, signed, "shell", "sandstorm-42.tar.xz", artifact))
	if response.Code != http.StatusOK {
		t.Fatalf("installer-publish-bound-positive: status=%d body=%s", response.Code, response.Body.String())
	}
	reopened, err := openPublishNonceLedger(filepath.Join(svc.cfg.PrivateStageDir, publishNonceLedgerDirName),
		testPublishNonceLedgerID, defaultPublishNonceLedgerOptions())
	if err != nil {
		t.Fatal(err)
	}
	restarted := *svc
	restarted.appNonces = reopened
	replay := doPublishInstaller(t, &restarted, jsonInstallerPublishBody(t, signed, "shell", "sandstorm-42.tar.xz", artifact))
	if replay.Code != http.StatusUnauthorized || !strings.Contains(replay.Body.String(), "nonce_ledger") {
		t.Fatalf("installer-publish-restart-replay: status=%d body=%s", replay.Code, replay.Body.String())
	}
}
