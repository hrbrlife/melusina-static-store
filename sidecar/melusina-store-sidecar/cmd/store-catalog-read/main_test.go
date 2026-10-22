package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

type catalogFixtureGetter struct {
	index, pointer         []byte
	indexGate, pointerGate string
	pointerStatus          int
}

func (g catalogFixtureGetter) Get(path string) (*http.Response, error) {
	response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}
	if strings.HasSuffix(path, "/apps/index.json") {
		response.Body = io.NopCloser(bytes.NewReader(g.index))
		if g.indexGate != "" {
			response.Header.Set("X-Store-Catalog-Gate", g.indexGate)
		}
	} else {
		response.StatusCode = g.pointerStatus
		response.Body = io.NopCloser(bytes.NewReader(g.pointer))
		if g.pointerGate != "" {
			response.Header.Set("X-Store-Catalog-Gate", g.pointerGate)
		}
	}
	return response, nil
}

func pointerFixture(t *testing.T) (catalogFixtureGetter, string, string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	appID, domain := "test-app", "store.example.org"
	spk := sha256.Sum256([]byte("frozen-spk"))
	app := sha256.Sum256([]byte("app-hash"))
	release := sha256.Sum256([]byte("release-hash"))
	stage := sha256.Sum256([]byte("stage-id"))
	row := catalogRow{AppID: appID, PackageID: hex.EncodeToString(spk[:16]), Version: "1.2.3", SHA256: hex.EncodeToString(spk[:])}
	row.Attest.AppHash = hex.EncodeToString(app[:])
	row.Attest.ReleaseHash = hex.EncodeToString(release[:])
	index, err := json.Marshal(struct {
		Apps []catalogRow `json:"apps"`
	}{[]catalogRow{row}})
	if err != nil {
		t.Fatal(err)
	}
	indexHash := sha256.Sum256(index)
	domainHash := primitives.StoreDomainHash(domain)
	pointer := catalogPointer{Schema: "melusina-app-catalog-pointer-v1", AppID: appID,
		PackageID: row.PackageID, Version: row.Version, AppHash: row.Attest.AppHash,
		ReleaseHash: row.Attest.ReleaseHash, StageID: hex.EncodeToString(stage[:]),
		CatalogSHA256: hex.EncodeToString(indexHash[:]), ServingDomainHash: hex.EncodeToString(domainHash[:]),
		PublishedAt: 1234567890}
	message, err := pointerMessage(pointer)
	if err != nil {
		t.Fatal(err)
	}
	pointer.OperatorSignature = primitives.EncodeBase58(ed25519.Sign(private, message))
	encoded, err := json.Marshal(pointer)
	if err != nil {
		t.Fatal(err)
	}
	return catalogFixtureGetter{index: index, pointer: encoded, indexGate: "verified", pointerStatus: http.StatusOK},
		primitives.EncodeBase58(public), appID, domain
}

func TestUnchangedSignedPointerWithoutGateHeaderIsReadAfterVerifiedIndex(t *testing.T) {
	getter, operator, appID, domain := pointerFixture(t)
	got, err := readCatalog(getter, "https://"+domain, "/apps/pointers/"+appID+".json", operator, domain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, getter.pointer) {
		t.Fatal("signed pointer bytes changed")
	}
}

func TestUnmarkedPointerRefusesForeignUnsignedAndMismatchedInputs(t *testing.T) {
	base, operator, appID, domain := pointerFixture(t)
	path := "/apps/pointers/" + appID + ".json"
	for _, item := range []struct {
		name   string
		mutate func(*catalogFixtureGetter, *string, *string)
	}{
		{"unverified-index", func(g *catalogFixtureGetter, _, _ *string) { g.indexGate = "" }},
		{"foreign-operator", func(_ *catalogFixtureGetter, o, _ *string) { *o = primitives.EncodeBase58(make([]byte, 32)) }},
		{"unsigned-pointer", func(g *catalogFixtureGetter, _, _ *string) {
			var p catalogPointer
			_ = json.Unmarshal(g.pointer, &p)
			p.OperatorSignature = ""
			g.pointer, _ = json.Marshal(p)
		}},
		{"mismatched-app-hash", func(g *catalogFixtureGetter, _, _ *string) {
			var p catalogPointer
			_ = json.Unmarshal(g.pointer, &p)
			p.AppHash = strings.Repeat("0", 64)
			g.pointer, _ = json.Marshal(p)
		}},
		{"mismatched-catalog", func(g *catalogFixtureGetter, _, _ *string) {
			var p catalogPointer
			_ = json.Unmarshal(g.pointer, &p)
			p.CatalogSHA256 = strings.Repeat("0", 64)
			g.pointer, _ = json.Marshal(p)
		}},
		{"missing-selected-pointer", func(g *catalogFixtureGetter, _, _ *string) { g.pointerStatus = http.StatusNotFound }},
	} {
		t.Run(item.name, func(t *testing.T) {
			getter, key, host := base, operator, domain
			item.mutate(&getter, &key, &host)
			if _, err := readCatalog(getter, "https://"+host, path, key, host); err == nil {
				t.Fatal("untrusted pointer was accepted")
			}
		})
	}
}
