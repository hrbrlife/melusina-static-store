package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

type selectedReadFixture struct {
	cfg   Config
	op    *identity.Private
	chain *mockChainReader
	appID string
	f     publishFixture
	files map[string][]byte
	now   time.Time
}

func newSelectedReadFixture(t *testing.T) *selectedReadFixture {
	t.Helper()
	cfg, _ := testConfig(t)
	cfg.StoreID = "test-selected-store"
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	cfg.StoreAuthority = op.Public().SignPubkeyB58
	f := controlFixture(t, buildValidFixture(t, cfg, randPubkeyB58(t)))
	// The legacy helper adapted the canonical app hash; rederive its exact
	// listing so this test exercises the real configured Store projection.
	listing, _, err := pda.StoreReleaseListing(f.storeAuthority, f.appHashBytes, programID)
	if err != nil {
		t.Fatal(err)
	}
	f.listingPDA = listing.Base58()
	m := newMockChainReader()
	f.pinAccept(m, operatorSignPub32(t, op))
	f.pinServeListingActive(m)
	appID := metadataAppID(f.metadata)
	packageID := metadataPackageID(f.metadata)
	now := time.Now().UTC().Truncate(time.Second)
	index := []byte("{\n  \"apps\": [{\"appId\":\"" + appID + "\",\"packageId\":\"" + packageID + "\",\"title\":\"Original display metadata\"}, {\"appId\":\"unrelated-app\",\"packageId\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}]\n}\n")
	indexHash := sha256.Sum256(index)
	domain := primitives.StoreDomainHash(cfg.Domain)
	pointer := AppCatalogPointer{Schema: appCatalogPointerSchema, AppID: appID, PackageID: packageID, Version: f.rel.Version, AppHash: f.rel.AppHash, ReleaseHash: f.rel.ReleaseHash, StageID: strings.Repeat("d", 64), CatalogSHA256: hex.EncodeToString(indexHash[:]), ServingDomainHash: hex.EncodeToString(domain[:]), PublishedAt: now.Add(-time.Minute).Unix()}
	message, err := appCatalogPointerMessage(pointer)
	if err != nil {
		t.Fatal(err)
	}
	pointer.OperatorSignature = primitives.EncodeBase58(op.Sign(message))
	pointerBytes, _ := json.MarshalIndent(pointer, "", "  ")
	releaseBytes, _ := json.MarshalIndent(f.rel, "", "  ")
	return &selectedReadFixture{cfg: cfg, op: op, chain: m, appID: appID, f: f, now: now, files: map[string][]byte{
		"apps/index.json":                            index,
		"apps/pointers/" + appID + ".json":           append(pointerBytes, '\n'),
		"packages/" + packageID:                      f.spk,
		"signatures/" + appID + "/metadata.json":     f.metadata,
		"attest/" + appID + "/RELEASE.json":          append(releaseBytes, '\n'),
		"attest/" + appID + "/RUNTIME-CONTRACT.json": f.runtimeContract,
	}}
}

func (f *selectedReadFixture) service(t *testing.T) *publishService {
	t.Helper()
	f.cfg.DistDir = t.TempDir()
	for name, raw := range f.files {
		writeFile(t, filepath.Join(f.cfg.DistDir, name), raw)
	}
	svc := newTestService(t, f.cfg, f.chain, f.op)
	svc.now = func() time.Time { return f.now }
	return svc
}

func TestControlSelectedReleaseRetainsExactPublicBytes(t *testing.T) {
	f := newSelectedReadFixture(t)
	svc := f.service(t)
	w := httptest.NewRecorder()
	newControlReleaseRouter(svc).ServeHTTP(w, httptest.NewRequest(http.MethodGet, controlSelectedReleasePrefix+f.appID, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("selected read: %d %s", w.Code, w.Body.String())
	}
	var selected selectedReleaseSnapshot
	if err := json.Unmarshal(w.Body.Bytes(), &selected); err != nil {
		t.Fatal(err)
	}
	if selected.Schema != selectedReleaseSchema || selected.StoreID != f.cfg.StoreID || selected.AppID != f.appID || selected.ObservedAt != f.now || !validGenerationID(selected.GenerationID) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("selected response binding changed")
	}
	for path, raw := range map[string][]byte{"apps/index.json": selected.Index, "apps/pointers/" + f.appID + ".json": selected.Pointer, "packages/" + metadataPackageID(f.f.metadata): selected.SPK, "signatures/" + f.appID + "/metadata.json": selected.Metadata, "attest/" + f.appID + "/RELEASE.json": selected.Release, "attest/" + f.appID + "/RUNTIME-CONTRACT.json": selected.RuntimeContract} {
		if !bytes.Equal(raw, f.files[path]) {
			t.Fatalf("original public bytes changed: %s", path)
		}
	}
	if bytes.Contains(w.Body.Bytes(), []byte("sourceCommit")) || bytes.Contains(w.Body.Bytes(), []byte("Authenticated")) {
		t.Fatal("readout invented source authority")
	}
}

func TestControlSelectedReleaseRefusesArtifactAndAuthorityDrift(t *testing.T) {
	for name, mutate := range map[string]func(*selectedReadFixture){
		"unsigned pointer": func(f *selectedReadFixture) {
			p := "apps/pointers/" + f.appID + ".json"
			f.files[p] = bytes.Replace(f.files[p], []byte(`"operatorSignature": "`), []byte(`"operatorSignature": "1`), 1)
		},
		"pointer duplicate": func(f *selectedReadFixture) {
			p := "apps/pointers/" + f.appID + ".json"
			f.files[p] = bytes.Replace(f.files[p], []byte("{"), []byte(`{"schema":"melusina-app-catalog-pointer-v1",`), 1)
		},
		"pointer case alias": func(f *selectedReadFixture) {
			p := "apps/pointers/" + f.appID + ".json"
			f.files[p] = bytes.Replace(f.files[p], []byte(`"appId"`), []byte(`"APPID"`), 1)
		},
		"missing pointer": func(f *selectedReadFixture) { delete(f.files, "apps/pointers/"+f.appID+".json") },
		"index bytes":     func(f *selectedReadFixture) { f.files["apps/index.json"] = append(f.files["apps/index.json"], ' ') },
		"package bytes": func(f *selectedReadFixture) {
			p := "packages/" + metadataPackageID(f.f.metadata)
			f.files[p] = append(f.files[p], '!')
		},
		"metadata bytes": func(f *selectedReadFixture) {
			p := "signatures/" + f.appID + "/metadata.json"
			f.files[p] = append(f.files[p], ' ')
		},
		"runtime bytes": func(f *selectedReadFixture) {
			p := "attest/" + f.appID + "/RUNTIME-CONTRACT.json"
			f.files[p] = append(f.files[p], ' ')
		},
		"release unknown schema": func(f *selectedReadFixture) {
			p := "attest/" + f.appID + "/RELEASE.json"
			f.files[p] = bytes.Replace(f.files[p], []byte("melusina-release-v1"), []byte("melusina-release-v2"), 1)
		},
		"release extra authority claim": func(f *selectedReadFixture) {
			p := "attest/" + f.appID + "/RELEASE.json"
			f.files[p] = bytes.Replace(f.files[p], []byte("{"), []byte(`{"sourceBaselineAuthenticated":true,`), 1)
		},
		"chain wrong app": func(f *selectedReadFixture) {
			m := f.chain.releaseEntry[f.f.relPDA]
			m.appID[0] ^= 1
			f.chain.releaseEntry[f.f.relPDA] = m
		},
		"chain wrong version": func(f *selectedReadFixture) {
			m := f.chain.releaseEntry[f.f.relPDA]
			m.version = "2.0.0"
			f.chain.releaseEntry[f.f.relPDA] = m
		},
		"chain wrong registration": func(f *selectedReadFixture) {
			m := f.chain.releaseEntry[f.f.relPDA]
			m.registeredAt++
			f.chain.releaseEntry[f.f.relPDA] = m
		},
		"chain missing release":               func(f *selectedReadFixture) { delete(f.chain.releaseEntry, f.f.relPDA) },
		"chain missing exact listing":         func(f *selectedReadFixture) { delete(f.chain.storeListing, f.f.listingPDA) },
		"missing independent Store authority": func(f *selectedReadFixture) { f.cfg.StoreAuthority = "" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newSelectedReadFixture(t)
			mutate(f)
			w := httptest.NewRecorder()
			newControlReleaseRouter(f.service(t)).ServeHTTP(w, httptest.NewRequest(http.MethodGet, controlSelectedReleasePrefix+f.appID, nil))
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("drift accepted: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestControlSelectedReleaseRefreshesListingAndLimitsFiles(t *testing.T) {
	f := newSelectedReadFixture(t)
	svc := f.service(t)
	router := newControlReleaseRouter(svc)
	get := func() int {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, controlSelectedReleasePrefix+f.appID, nil))
		return w.Code
	}
	if get() != http.StatusOK {
		t.Fatal("initial selected read failed")
	}
	delete(f.chain.storeListing, f.f.listingPDA)
	if get() != http.StatusServiceUnavailable {
		t.Fatal("selected read used a stale listing verdict")
	}
	f.f.pinServeListingActive(f.chain)
	snapshot, err := svc.catalogGenerations.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(snapshot.Root, "packages", metadataPackageID(f.f.metadata))
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, maxSelectedReleaseSPKBytes+1); err != nil {
		t.Fatal(err)
	}
	if get() != http.StatusServiceUnavailable {
		t.Fatal("oversized package accepted")
	}
}

func TestControlSelectedReleaseFixedRoute(t *testing.T) {
	f := newSelectedReadFixture(t)
	router := newControlReleaseRouter(f.service(t))
	for _, path := range []string{controlSelectedReleasePrefix + f.appID + "?url=elsewhere", controlSelectedReleasePrefix + f.appID + "/packages", controlSelectedReleasePrefix + strings.ToUpper(f.appID), controlSelectedReleasePrefix + "short"} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code == http.StatusOK {
			t.Fatal("unscoped route accepted")
		}
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, controlSelectedReleasePrefix+f.appID, nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatal("non-read method accepted")
	}
}

func TestControlSelectedReleaseIsPrivateInBothRouterModes(t *testing.T) {
	for _, isolated := range []bool{false, true} {
		cfg, _ := testConfig(t)
		cfg.PrivateStageDir = t.TempDir()
		public, _ := newGovernedRouterSurfaces(cfg, nil, nil, nil, catalogRuntime{}, isolated)
		w := httptest.NewRecorder()
		public.ServeHTTP(w, httptest.NewRequest(http.MethodGet, controlSelectedReleasePrefix+strings.Repeat("a", 52), nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("public selected read exposed (isolated=%v): %d", isolated, w.Code)
		}
	}
}
