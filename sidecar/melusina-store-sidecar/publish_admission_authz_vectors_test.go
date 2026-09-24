package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry/releaseentrytest"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// The other side of finding 19 is the tenant's authorization daemon. Its
// committed vector (testdata/authz-store-receipt, a byte-for-byte copy of
// melusina-authzsign-component pkg/grainauth/testdata/
// shell_store_receipt_vectors.json) holds the exact Context the Shell sends
// for a Store receipt: [decoded appId | appHash | releaseHash | serving
// domain hash]. The daemon's own test drives each one through its store stage:
// it Allows when the ReleaseEntry attests the context's app and release hash,
// and refuses a one-bit change to the release hash as
// store:release-hash-mismatch (evalRelease also refuses an entry app_id that
// is not sha256 of the appId as release-appid-mismatch). These tests hold the
// Store's publish admission and receipt signer to the same bytes.

const (
	authzReceiptDir            = "testdata/authz-store-receipt"
	authzReceiptVectorPath     = authzReceiptDir + "/shell_store_receipt_vectors.json"
	authzReceiptProvenancePath = authzReceiptDir + "/shell_store_receipt_vectors.provenance.json"
	authzReceiptGitObjectsDir  = authzReceiptDir + "/git-objects"
	authzReceiptSourcePath     = "pkg/grainauth/testdata/shell_store_receipt_vectors.json"
	authzReceiptRepository     = "https://github.com/hrbrlife/melusina-authzsign-component"
	// authzReceiptContextLen is the daemon's storeReceiptContextLen.
	authzReceiptContextLen = 128
)

type authzReceiptVectors struct {
	Source struct {
		Repository         string `json:"repository"`
		Commit             string `json:"commit"`
		Path               string `json:"path"`
		Lines              string `json:"lines"`
		EncoderBlockSha256 string `json:"encoderBlockSha256"`
	} `json:"source"`
	Generator                  string `json:"generator"`
	IncompleteProvenanceIsNull bool   `json:"incompleteProvenanceIsNull"`
	DevContextLength           int    `json:"devContextLength"`
	Cases                      []struct {
		Name                   string `json:"name"`
		AppID                  string `json:"appId"`
		ServingHost            string `json:"servingHost"`
		ReleaseAppHash         string `json:"releaseAppHash"`
		ReleaseHash            string `json:"releaseHash"`
		ServingStoreDomainHash string `json:"servingStoreDomainHash"`
		Context                string `json:"context"`
	} `json:"cases"`
}

func loadAuthzReceiptVectors(t *testing.T) authzReceiptVectors {
	t.Helper()
	raw, err := os.ReadFile(authzReceiptVectorPath)
	if err != nil {
		t.Fatalf("read authz receipt vector: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var v authzReceiptVectors
	if err := decoder.Decode(&v); err != nil {
		t.Fatalf("authz-receipt-vector-unreadable: %v", err)
	}
	if len(v.Cases) < 2 {
		t.Fatalf("authz-receipt-vector-incomplete: %d cases; the app_id mutation needs a second app", len(v.Cases))
	}
	return v
}

func loadAuthzReceiptProvenance(t *testing.T) contractsSidecarProvenance {
	t.Helper()
	raw, err := os.ReadFile(authzReceiptProvenancePath)
	if err != nil {
		t.Fatalf("read authz receipt vector provenance: %v", err)
	}
	var withComment struct {
		Comment []string `json:"comment"`
		contractsSidecarProvenance
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&withComment); err != nil {
		t.Fatalf("decode authz receipt vector provenance: %v", err)
	}
	p := withComment.contractsSidecarProvenance
	if p.Schema != "melusina.store.vendored-vector-provenance.v1" || p.File != filepath.Base(authzReceiptVectorPath) ||
		p.SourceRepository != authzReceiptRepository || p.SourcePath != authzReceiptSourcePath {
		t.Fatalf("authz-receipt-vector-provenance-wrong: provenance does not describe the daemon's receipt vector: %+v", p)
	}
	if !isLowerHex(p.SourceCommit, 40) || !isLowerHex(p.GitBlobSHA1, 40) || !isLowerHex(p.SHA256, 64) {
		t.Fatalf("authz-receipt-vector-provenance-wrong: commit, blob or digest is not a full lowercase hex id: %+v", p)
	}
	return p
}

func TestAuthzReceiptVectorCopyMatchesItsRecordedProvenance(t *testing.T) {
	p := loadAuthzReceiptProvenance(t)
	raw, err := os.ReadFile(authzReceiptVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if len(raw) != p.Bytes || hex.EncodeToString(digest[:]) != p.SHA256 || gitBlobSHA1(raw) != p.GitBlobSHA1 {
		t.Fatalf("authz-receipt-vector-copy-altered: %d bytes sha256 %x blob %s; provenance records %d bytes sha256 %s blob %s",
			len(raw), digest, gitBlobSHA1(raw), p.Bytes, p.SHA256, p.GitBlobSHA1)
	}
}

// TestAuthzReceiptVectorCopyIsTheBlobTheNamedCommitHolds walks from the
// vendored commit object through one vendored tree per path component to the
// blob id, checking every object against its own id, so a hand-edited copy
// with recomputed digests still fails: the commit's trees name the original.
func TestAuthzReceiptVectorCopyIsTheBlobTheNamedCommitHolds(t *testing.T) {
	p := loadAuthzReceiptProvenance(t)
	raw, err := os.ReadFile(authzReceiptVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	read := func(kind, id string) []byte {
		body, err := os.ReadFile(filepath.Join(authzReceiptGitObjectsDir, id+"."+kind))
		if err != nil {
			t.Fatalf("authz-receipt-git-object-missing: %s %s: %v", kind, id, err)
		}
		if got := gitObjectID(kind, body); got != id {
			t.Fatalf("authz-receipt-git-object-altered: %s.%s hashes to %s", id, kind, got)
		}
		return body
	}
	used := map[string]bool{p.SourceCommit + ".commit": true}
	treeID, err := gitCommitTree(read("commit", p.SourceCommit))
	if err != nil {
		t.Fatalf("authz-receipt-git-object-altered: commit %s: %v", p.SourceCommit, err)
	}
	components := strings.Split(p.SourcePath, "/")
	blobID := ""
	for index, component := range components {
		used[treeID+".tree"] = true
		entries, err := parseGitTree(read("tree", treeID))
		if err != nil {
			t.Fatalf("authz-receipt-git-object-altered: tree %s: %v", treeID, err)
		}
		var entry *gitTreeEntry
		for i := range entries {
			if entries[i].Name == component {
				entry = &entries[i]
			}
		}
		if entry == nil {
			t.Fatalf("authz-receipt-vector-provenance-wrong: commit %s has no %s", p.SourceCommit, strings.Join(components[:index+1], "/"))
		}
		if index < len(components)-1 {
			if entry.Mode != "40000" {
				t.Fatalf("authz-receipt-vector-provenance-wrong: %s is mode %s, not a directory", strings.Join(components[:index+1], "/"), entry.Mode)
			}
			treeID = entry.ID
			continue
		}
		if entry.Mode != "100644" && entry.Mode != "100755" {
			t.Fatalf("authz-receipt-vector-provenance-wrong: %s is mode %s, not a regular file", p.SourcePath, entry.Mode)
		}
		blobID = entry.ID
	}
	if blobID != p.GitBlobSHA1 || gitBlobSHA1(raw) != blobID {
		t.Fatalf("authz-receipt-vector-copy-diverged: commit %s holds blob %s at %s; provenance records %s; the copy is %s", p.SourceCommit, blobID, p.SourcePath, p.GitBlobSHA1, gitBlobSHA1(raw))
	}
	files, err := os.ReadDir(authzReceiptGitObjectsDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if !used[file.Name()] || !file.Type().IsRegular() {
			t.Fatalf("authz-receipt-git-object-unused: %s is not on the walk from %s to %s", file.Name(), p.SourceCommit, p.SourcePath)
		}
	}
}

// TestPublishAdmissionAgreesWithTheDaemonOnItsCommittedReceipts: for each of
// the daemon's committed receipt contexts, the Store admits a RELEASE.json
// whose entry attests exactly that app and release hash (the release the
// daemon Allows), and the receipt it then signs is the context's own bytes.
// The mutation the daemon refuses as release-hash-mismatch (bit 0 of
// Context[64], the first release-hash byte) and an entry of another app (the
// daemon's release-appid-mismatch) are refused by the Store at /publish, by
// name, before it signs anything.
func TestPublishAdmissionAgreesWithTheDaemonOnItsCommittedReceipts(t *testing.T) {
	v := loadAuthzReceiptVectors(t)
	cfg, _ := testConfig(t)
	custodian := mustPubkey(cfg.ReleaseSquadsAuthority.Vault)
	master := mustPubkey(randPubkeyB58(t))
	publisher := testReleasePublisherKey()
	trust, err := releaseentry.NewTrust([32]byte(master), [32]byte(custodian), [][32]byte{[32]byte(publisher.Public().(ed25519.PublicKey))}, 1)
	if err != nil {
		t.Fatal(err)
	}
	enrolled := cfg
	enrolled.appReleaseTrust = trust
	operator := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorKey, err := operator.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	for index, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			context, err := hex.DecodeString(c.Context)
			if err != nil || len(context) != authzReceiptContextLen {
				t.Fatalf("authz-receipt-context-length: %d bytes (%v), the daemon reads %d", len(context), err, authzReceiptContextLen)
			}
			appKey, err := decodeSandstormAppIDKey(c.AppID)
			if err != nil {
				t.Fatalf("the Store refuses the daemon's appId %q: %v", c.AppID, err)
			}
			if !bytes.Equal(context[0:32], appKey[:]) {
				t.Fatal("authz-receipt-appid-key: the Store's decoded appId is not Context[0:32]")
			}
			appHash, err := hash32FromHex(c.ReleaseAppHash)
			if err != nil {
				t.Fatal(err)
			}
			releaseHash, err := hash32FromHex(c.ReleaseHash)
			if err != nil {
				t.Fatal(err)
			}
			domainHash, err := hash32FromHex(c.ServingStoreDomainHash)
			if err != nil {
				t.Fatal(err)
			}
			if primitives.StoreDomainHash(c.ServingHost) != domainHash {
				t.Fatalf("authz-receipt-domain-hash: the Store hashes serving host %q to %x, the daemon %x", c.ServingHost, primitives.StoreDomainHash(c.ServingHost), domainHash)
			}
			// The entry the release custodian registers for the release the
			// daemon Allows: app_id is sha256 of the appId text, as the
			// daemon's StableSandstormAppIDHash computes from Context[0:32].
			entry := releaseentrytest.Active([32]byte(master), [32]byte(custodian), appHash, releaseentry.AppIDHash(c.AppID), releaseHash, "1.0.0", publisher)
			meta, err := readReleaseEntryMeta(releaseentrytest.Encode(entry))
			if err != nil {
				t.Fatal(err)
			}
			meta.PDA = "vector-release-entry"
			rel := ReleaseJSON{ReleaseHash: c.ReleaseHash, Version: "1.0.0"}
			if err := admitReleaseEntryForPublish(enrolled, appHash, meta, rel, c.AppID); err != nil {
				t.Fatalf("positive control: the Store refuses the release the daemon Allows: %v", err)
			}
			// What the Store then signs is exactly the receipt part of the
			// context the Shell sends and the daemon Allows.
			receipt := SignReceipt(operator, appHash, releaseHash, domainHash)
			if receipt.ReleaseHash != c.ReleaseHash || receipt.AppHash != c.ReleaseAppHash || receipt.ServingDomainHash != c.ServingStoreDomainHash {
				t.Fatalf("authz-receipt-fields: the Store's receipt %+v is not the daemon's vector", receipt)
			}
			if message := receiptMessage(appHash, releaseHash, domainHash); !bytes.Equal(message, context[32:]) {
				t.Fatalf("authz-receipt-message: the Store signs %x, the daemon reads Context[32:] %x", message, context[32:])
			}
			signature, err := primitives.DecodeBase58(receipt.OperatorSignature)
			if err != nil || !ed25519.Verify(ed25519.PublicKey(operatorKey), context[32:], signature) {
				t.Fatalf("authz-receipt-signature: the Store's receipt signature does not verify over the daemon's Context[32:] (%v)", err)
			}

			// The daemon's mutation: bit 0 of Context[64]. A RELEASE.json
			// naming that release hash is refused before any receipt.
			flipped := append([]byte(nil), context[64:96]...)
			flipped[0] ^= 1
			mutated := rel
			mutated.ReleaseHash = hex.EncodeToString(flipped)
			requireAdmissionRefusal(t, admitReleaseEntryForPublish(enrolled, appHash, meta, mutated, c.AppID), releaseentry.ErrReleaseHashMismatch)
			// An entry of another of the daemon's apps (release-appid-mismatch).
			other := v.Cases[(index+1)%len(v.Cases)].AppID
			if other == c.AppID {
				t.Fatal("the vector's cases share an appId")
			}
			requireAdmissionRefusal(t, admitReleaseEntryForPublish(enrolled, appHash, meta, rel, other), releaseentry.ErrAppIDMismatch)
		})
	}
}
